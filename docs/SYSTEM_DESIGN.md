# Rupas — System Design
## v1.0 · Полный системный дизайн · приложение к PRD.md
Все решения привязаны к лабораторным данным (см. PRD §2, Приложение А).

---

## 0. Реестр решений (ADR-краткость)

| # | Решение | Альтернатива | Почему |
|---|---|---|---|
| ADR-1 | Единый Go-процесс + системный сервис | микросервисы, child-process winws | детерминизм горячего пути, один flow-table, нет IPC на пакетах |
| ADR-2 | WinDivert 2.2 как слой перехвата (Windows) | NDIS/LWF, WFP callout | подписанный драйвер,-userspace-логика, доступный API REDIRECT/FLOW |
| ADR-3 | gVisor netstack для Android | system TUN + iptables | нужен юзерланд-доступ к потокам для desync без root |
| ADR-4 | sing-box как библиотека, не процесс | свой VLESS-клиент | проверенный crypto/транспорт; свой — только на этапе 2 |
| ADR-5 | Desync только для TCP/TLS; UDP-медиа — в туннель | fake-UDP локально | лаборатория: UDP 3478/19302 дропаются, надёжность важнее |
| ADR-6 | Flow-таблица в памяти, шардинг по CPU | общая мьютекс-карта | убрать contention на 100k+ flows |
| ADR-7 | Probe с browser-like CH (uTLS+PQ) | нативный Go TLS | доказано: «тощий» CH даёт ложноположительный результат калибровки |
| ADR-8 | Конфиг + профили провайдера локальные, обновляемые | облако-центричный конфиг | продукт «для своих», оффлайн-first |

---

## 1. Контекст и границы (C4 L1)

     ┌────────────────────────────────────────────────────────────┐
     │ ХОСТ ПОЛЬЗОВАТЕЛЯ (Windows v1 / Android v2)                │
     │                                                            │
     │  приложения (браузер, TG, Discord)                         │
     │         │ сокеты                                           │
     │  ═══════╪════════ RUPAS SERVICE (SYSTEM) ═════════════    │
     │  │ core: inspector → rules → desync/tunnel/direct │        │
     │  │ probes · supervisor · metrics · flow-table    │        │
     │  ═══════╪═════════════════════════════════════════        │
     │     WinDivert.sys / VpnService(TUN)                        │
     │         │                                                  │
     │  NIC ───┴── ISP ─── ТСПУ ───┬── Интернет (прямо)          │
     └─────────────────────────────┼──────────────────────────────┘
                                   │ TLS:443 (VLESS-Reality)
                              VPS пользователя
                                   │ exit
                               Интернет

Внешние зависимости: WinDivert.sys (драйвер), VPS с xray/sing-box сервером,
NTP/DoH (для метрик времени и резолва конфиг-домена).

Trust boundaries: (1) юзерленд↔SYSTEM-сервис; (2) хост↔ТСПУ (враждебный
канал); (3) хост↔VPS (доверенный, но защищаемый TLS-стегано).

---

## 2. Декомпозиция ядра (C4 L2)

    rupas-core (Go)
    ├── capture      — обвязка WinDivert: recv/send/batch, фильтры, layers
    ├── flowtable    — conntrack-подобная таблица потоков, GC
    ├── inspector    — потоковые парсеры: TLS CH (SNI/ALPN/ECH), STUN, DNS, L7-Discord
    ├── rules        — компиляция конфига в таблицы решений (CIDR-trie, SNI-hash)
    ├── desync       — стратегии fake/split/disorder, конструктор фейков (uTLS)
    ├── redirect     — перенаправление flow в локальный inbound (TG, UDP-медиа)
    ├── tunnel       — sing-box lib: VLESS-Reality, XUDP, маршрутизация, health
    ├── prober       — классификация блокировок, TTL-калибровка, browser-like пробы
    ├── supervisor   — жизненный цикл, state machine, деградации, сетевые события
    ├── diag         — сбор диагностического бандла (одна команда)
    └── rpc          — named pipe ACL: CLI/GUI ↔ сервис (gRPC over pipe / JSON)

Зависимости направлены строго вниз; кольцевых нет. Горячий путь (пакеты)
не пересекает rpc/diag/prober — они работают через атомарные снапшоты
состояния (atomic.Pointer[State]).

---

## 3. Горячий путь пакета (Windows)

### 3.1 Слои WinDivert и фильтры

Используем три layer:

| Layer | Фильтр (пример) | Назначение |
|---|---|---|
| FLOW | `outbound and tcp and (tcp.DstPort==443 or ip.DstAddr in tg_cidrs)` | учёт flow: create/delete события, без копирования пакетов |
| NETWORK | `outbound and tcp.DstPort==443` | desync: перехват CH, инжект фейков, split, реинжект |
| REDIRECT | `outbound and tcp and ip.DstAddr in tg_cidrs` | прозрачное перенаправление TG в локальный tproxy-inbound |

Правило генерации фильтра — из скомпилированного rules-стейта, чтобы
ядро драйвера само отсекало ненужные пакеты (нас не интересует чужой TCP:22).

### 3.2 Пайплайн TCP:443 (desync-ветка)

    WinDivertRecv (batch ≤ 64 pkt)
      → classify: SYN? / data? / fin? 
      → flowtable.get(4-tuple)            [shard lock, ~100ns]
      → если SYN: создать flow {state:NEW}
      → если первый data-сегмент:
          inspector.parse_client_hello(bytes)
            ├─ нет TLS/парс не завершён → WAIT (буфер до 4 сегментов, 64KB cap)
            ├─ SNI найден:
            │    rules.match(sni, dstIP, dstPort, process?) → action
            │      DIRECT  → re-inject как есть, flow.state=DIRECT (больше не смотрим)
            │      DESYNC  → strategies[profile] применить к сегментам CH:
            │                  a) inject fake CH ×N, TTL=t_calib, seq/ack валидны
            │                  b) опц. split реального CH по offset
            │                  c) re-inject оригинал(ы)
            │                  flow.state=DESYNCED, t_start
            │      TUNNEL  → пометить flow; следующий SYN пересоздаём через redirect
            ├─ ECH (ext 0xfe0d) в CH → DESYNC запрещён → TUNNEL (lab: Schannel-ECH не пробивается)
            └─ handshake завершён (ACK после ServerHello) → flow.state=ESTABLISHED, desync-снятие счётчиков
      → иначе: re-inject без анализа

Инварианты горячего пути:
- 0 аллокаций в steady-state: буферы из sync.Pool, WINDIVERT_ADDRESS реиспользуются;
- WinDivertSend сразу после обработки батча, никакого межслойного пайплайна;
- одна goroutine на слой (capture NETWORK, REDIRECT), fan-out запрещён.

### 3.3 Ветка TUNNEL-redirect (Telegram, UDP-медиа)

REDIRECT-layer в stock WinDivert 2.2 отсутствует (проверено живым Open: errno 87;
экспорт-таблица DLL не содержит WinDivertRedirect*). Замена — NETWORK-layer NAT:

    outbound: dst rewrite IP:port → 127.0.0.1:tproxy_port
              (OrigDst/OrigPort сохранены в Flow; Address.Loopback учитывается)
    inbound:  src rewrite 127.0.0.1:tproxy_port → OrigDst:OrigPort
              (обратная трансляция по flow-таблице, TTL/checksum пересчёт)
    tproxy-inbound слушает на loopback; original dst получает по 4-tuple клиента.

    TCP: прозрачно для TG-клиента (любой порт, MTProto на 443/80/5222).
    UDP Discord (50000–65535): тот же NAT → tun-core, XUDP-инкапсуляция,
    выход через VPS. Таймауты idle: TCP 5 мин, UDP 30 с.

**Wave 5c (live 2026-10-25): TCP-ветка переведена на userspace-терминатор.**
Живая матрица (zz_tcprealip / zz_gensyn / zz_inbest) доказала: стек Windows
дропает inbound-инъекцию TCP SYN на NETWORK-слое в ЛЮБОЙ комбинации
(IfIdx, Loopback, dst) — включая побайтовый replay подлинного SYN
(контроль: не-loopback replay доставляется, DNS отвечает). Доставляется
только inbound-инъекция в поток, авторизованный стеком на outbound-ноге
(ALE: outbound SYN авторизует 5-tuple). Следствие: NAT→tproxy forward-leg
для TCP нежизнеспособен на stock WinDivert 2.2.

Замена (internal/tunnel/tcpterm.go): перехваченный SYN клиента
потребляется движком; терминатор сам отвечает SYN-ACK (src = оригинальный
dst, inbound-инъекция через выделенный handle с фильтром
`inbound and tcp and ip.SrcAddr in tg_cidrs`), доводит handshake,
релеит поток через carrier-chain (§6) и подделывает данные/FIN/RST
клиенту. §4.2 fast-path: CIDR-правило даёт TUNNEL без ClientHello
(MTProto не TLS — до wave 5c такие dials уходили DIRECT в чёрную дыру).
UDP-ветка остаётся на NAT (inbound UDP доставляется). Шторм-контроль:
admission-gate (SYN дропается, пока marker не прошёл), rate 1/с, burst 2,
экспоненциальный backoff 1с→30с на отказе VPS CONNECT (живой факт: VPS
отказывает CONNECT волнами после бёрста — дни ретрансмит-бэклога клиента
нельзя выгружать разом).

Fallback-альтернатива (если NAT-петля на loopback окажется капризной):
wintun-адаптер + маршрут TG-CIDR → TUN (второй драйвер; решение при интеграции).

### 3.4 Бюджеты горячего пути

| Метрика | Бюджет | Основание |
|---|---|---|
| Задержка пакета через ядро | p50 < 100 µs, p99 < 1 ms | пользователи не должны видеть RTT-джиттер |
| Добавка к TLS-handshake | p50 < 5 ms, p99 < 15 ms | инжект фейков не блокирует оригинал |
| Пропускная способность | линейно до 1 Gbps, деградация < 3% | бенчмарк iperf3 через пары veth в CI |
| Память flow-table | ≤ 64 B/flow × 200k = 13 MB + пулы 32 MB | worst-case торрент-клиента |
| GC-паузы | < 100 µs (GOGC=off + вручную, зоны) | детерминизм; воздух: 512 MB arena |

---

## 4. Структуры данных

### 4.1 FlowTable (упрощённо)

    type FlowKey struct{ SrcIP, DstIP [16]byte; SrcPort, DstPort uint16; Proto uint8 }
    type Flow struct {
        State      atomic.Uint32  // NEW, DIRECT, DESYNCED, ESTABLISHED, TUNNEL
        CHSeen     bool           // ClientHello обработан
        ECH        bool
        Strategy   uint8          // индекс применённой стратегии
        OrigDst    [16]byte; OrigPort uint16   // для redirect
        SynT, DataT, EstT int64   // ns, monotonic
        Fails      uint8          // ретраи handshake (деградация)
    }
    // Шардинг: 2^k шардов (k = log2(GOMAXPROCS)), RWMutex на шарде.
    // GC: кольцевой скан 1 шард/тик, idle > TTL → delete. Без map-удалений в гор. пути:
    // tombstone + паковка шарда раз в N тиков.

### 4.2 Компиляция правил

Конфиг → три индекса:
1. CIDR-таблица: base-trie (patricia) по префиксам, action в листе; lookup O(длина префикса);
2. SNI-таблица: map[string]RuleRef с wildcard-суффиксами (сегментация по меткам, не по строкам);
3. Порядок разрешения: CIDR → SNI → port → default. Приоритет зафиксирован в схеме конфига.

### 4.3 Профиль провайдера (плод probe-калибровки)

    profile:
      id: isp-home-2025-10-25
      tspu:
        sni_blackhole: [www.youtube.com, discord.com, ...]   # классификация
        ip_blackhole_cidrs: [149.154.160.0/20, 91.108.0.0/16, 95.161.76.100/32]
        udp_dead_ports: [3478, 19302, 5353]
      desync:
        strategy: fake
        fake_template: chrome-124-pq.bin      # uTLS-сгенерированный, с ML-KEM
        ttl: 13                               # калибровано binary-search
        ttl_margin: +2
        repeats: 6
      evidence:
        probed_at: 2025-10-25T14:03+05
        browser_validated: true

---

## 5. Стратегии desync (контракт)

ДОКТРИНА ФЕЙКОВ (волна 4A, живая валидация parity с winws, окно TTL 12..14):
1. Реальный ClientHello ДЕРЖИТСЯ (все сегменты, включая многосегментный
   PQ/ML-KEM ~1.5KB) до полной отправки всех фейков; отпускается строго ПОСЛЕ.
2. seq/ack/window/flags/IP-ID фейка клонируются из ПЕРВОГО сегмента CH
   дословно (client ISN+1 / server ISN+1) — seq-1 вне окна DPI и отбрасывается.
3. Крафтеные пакеты отправляются с синтетическим rawsend-адресом (занулен,
   Outbound, IfIdx, все checksum-valid флаги, чексуммы в байтах): captured-адрес
   наследует offload-pending чексуммы → пакеты умирают на первом хопе;
   Impostor-флаг даёт декремент TTL (12→11 на проводе — ниже ТСПУ).
4. Калибровка TTL: ТСПУ эскалирует на сериях одинаковых проб → повторы
   разнесены (pacing 4с, decay 8с), лестница TTL с 12.

    type Strategy interface {
        // Prepare вызывается на первом data-сегменте CH.
        // Возвращает список действий; ядро исполняет их детерминированно.
        Prepare(f *Flow, ch *tls.ClientHelloInfo) []Action
    }
    type Action interface{ isAction() }
    type InjectFake struct{ Pkt []byte; TTL int; Count int }  // seq/ack вычисляет ядро из flow
    type SplitAt struct{ SeqOffset int }                       // разрез CH сегмента
    type Reorder struct{ Permutation []int }

Реестр стратегий: fake / fake+split / multisplit / disorder / disorder2.
Параметры из profile. Ограничения безопасности:
- fake-пакеты: только с src/dst потока, корректные checksums, TTL ≤ 32;
- недопустимо модифицировать чужие потоки (проверка 4-tuple при инжекте);
- каждая DESYNC-операция логируется счётчиком (не payload) в metrics.

## 6. Tunnel-core (sing-box lib)

- inbound: tproxy (127.0.0.1) + mixed (для UDP-redirect);
- outbound: vless+reality (dest из конфига, uTLS chrome), udp: xudp;
- health: активный маркер — GET https://marker.<домен>/204 каждые 30 c через
  туннель; 3 подряд fail → supervisor переводит TG-правила в ESROWNE...
  → в HOLD (retry с backoff 5/10/30 c), SNI-правила остаются на DESYNC;
- цепочки (опция): vless → freedom на VPS; резервная нода.

## 7. Prober — алгоритмы

### 7.1 Классификация цели (запуск, смена сети, деградация)

    для цели t из {yt, discord, tg-dc, control-ru, control-foreign}:
      1) TCP SYN → нет SYN/ACK 3×  ⇒ IP_BLACKHOLE(t)
      2) SYN ок; CH(browser-like) → timeout 3×         ⇒ SNI_BLACKHOLE
      3) CH → RST < RTT сервера (TTL RST ≠ TTL SRV)    ⇒ RST_INJECT
      4) handshake ок, speed < X% базовой              ⇒ THROTTLE
      5) handshake ок                                  ⇒ OPEN
    Параллельно: UDP-матрица {53,123,3478,443} на 3 цели.

### 7.2 TTL-калибровка фейков (для DESYNC)

    t_lo=1, t_hi=32; инвариант: success(t) монотонна ⇒ 
    бинарный поиск минимального t*, критерий: CH-handshake ok 3/3 при fake(t).
    Вернуть t*+margin. Если t* не найден (нет окна) → стратегия split/disorder,
    если и они мертвы → SNI-правило уходит в TUNNEL.
    Бюджет: ≤ 10 итераций × 3 повтора × ~0.3 c ≈ 9–15 c.

### 7.3 Пассивный детектор деградации

Счётчик handshake-файлов на DESYNC-потоках: fails/flows > 0.5 за 60 c →
форс-рекалибровка (7.2) + browser-валидация (реальный uTLS-CH к YT-эндпоинту).

## 8. Supervisor — state machine

    OFF → PROBING → ACTIVE(DESYNC+TUNNEL) 
                    ↘ ACTIVE_TUNNEL_ONLY (desync мёртв)
    любое состояние → DEGRADED (событие: fail-рейт, смена NIC, resume от sleep)
    DEGRADED → PROBING (backoff 5→10→30 c, джиттер)
    Правила гистерезиса: эскалация 3 fail/60 c; деэскалация 300 c стабильно.

События ОС:WM_DEVICECHANGE/POWERRESUME/NLM (Network List Manager) →
перепробинг. Смена default-route → flush flowtable + перенабор WinDivert-фильтров.

## 9. RPC и CLI

- Named pipe `\\.\pipe\rupasctl`, ACL: interactive user + SYSTEM;
- протокол: JSON-line request/response (+ streaming events для логов);
- команды: status, on, off, probe [--force], profile show/export,
  diag bundle, config reload;
- GUI (позже) использует тот же pipe — единственный интерфейс управления.

## 10. Безопасность (threat model, краткая STRIDE)

| Угроза | Вектор | Митигация |
|---|---|---|
| Elevation через pipe | злой юзерленд-процесс | ACL interactive-only, валидация всех полей, лимиты RPS на pipe |
| Подмена конфига/профилей | локальный диск/сеть | профили подписаны (minisign), ключ в конфиге сервиса |
| Вредоносный fake-CH | шаблоны | шаблоны генерит uTLS локально; внешние .bin запрещены политикой |
| Атака на драйвер | старый WinDivert | пин версии + SHA256 драйвера при установке |
| Утечка DNS | системный резолв мимо нас | v1: не перехватываем DNS (лabbr: DoH напрямую); v2: DNS в правилах |
| ТСПУ-фингерпринт клиента | характерные фейки | рандомизация count/шаблона в пределах стратегии, no-activity режим |
| Supply chain | зависимости Go | go.sum, govulncheck в CI, vendoring |

## 11. Наблюдаемость и диагностика

- Метрики (экспорт :9101, opt-in): rupas_flows{state}, rupas_pkts{action},
  rupas_probe{result,target}, rupas_desync_fail_ratio, rupas_tunnel_health;
- Лог: zap, level info в файл ротацией; debug-пакеты — только при flag;
- `rupas diag bundle`: профиль, последние 100 событий, счётчики, выхлоп
  probe — один текстовый файл для пересылки (для «своих» — читаемо).

## 12. Тестирование

| Уровень | Что | Инструмент |
|---|---|---|
| Unit | inspector (SNI/ECH/сегментация CH 1..N сегментов), rules-компилятор, flow-GC | go test + таблицы |
| Fuzz | TLS-парсер, STUN-парсер | go-fuzz corpus из lab-дампов |
| Integration | эмулятор ТСПУ: toxiproxy-подобный прокси, дропающий CH по SNI-списку и по IP; VLESS-сервер в docker | docker-compose CI |
| E2E lab | реальные скрипты лаборатории (python-пробы) против собранного бинаря на стенде | make lab-test (manual tag) |
| Soak | 24 h: память, GC, flow-leak, driver-leak | CI nightly |
| Perf | бюджет п.3.4: iperf3 через пару veth + бинарь | bench CI gate |

## 13. Android (v2) — отличия

- VpnService: TUN fd → netstack (gVisor): полный TCP/UDP стек в юзерленде;
- desync: модификация CH на egress netstack→protected socket (детерминированно,
  без драйверов); probes через protected sockets (мимо VPN-петли);
- redirect TG/UDP — внутренняя маршрутизация netstack → sing-box inbound;
-电池: foreground service + wakeup-политика probe только по событиям сети.

## 14. Открытые вопросы (владелец: ты)

1. Мобильный профиль Т-Мобайл не измерен — влияет на Android-дефолты (отложено юзером).
2. Верхняя граница TTL-окна не найдена (проверено до 20) — не критично.
3. QUIC/UDP:443 — при переходе YT на QUIC-only может потребоваться
   стратегия fake-QUIC или принудительный блок UDP:443 (fallback браузера).
4. Публичный dest для Reality на VPS — выбрать из живых SNI профиля (lab: cloudflare.com проходит).

## 15. Словарь

ТСПУ — технические средства противодействия угрозам (DPI провайдера);
desync — модификация потока, ломающая корреляцию DPI;
fake — инжект поддельного пакета с малым TTL;
profile — калиброванный набор параметров под конкретного провайдера.
