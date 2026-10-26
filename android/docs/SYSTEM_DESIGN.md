# Rupas Android — System Design
## v1.0 · 2026-10-26 · приложение к PRD.md (E:\rupas-android\docs\PRD.md)

База: SYSTEM_DESIGN.md v1.0 из E:\rupas (Windows). Здесь — только отличия и
новые решения; незатронутые подсистемы (inspector, rules, flowtable, supervisor,
tunnel-core, config) переносятся как есть.

---

## 0. Реестр решений (ADR-краткость)

| ADR | Решение | Альтернативы | Почему |
|---|---|---|---|
| 1 | Go-ядро → AAR через gomobile; Java = GUI + VpnService | (а) libbox + вся логика на Java; (б) полная переписка на Java | 20 портируемых пакетов переиспользуются кодом, включая sing-box lib (только в Go); libbox не умеет rupas-rules/desync/prober; переписка Java = месяцы и вечный дрейф от десктопа |
| 2 | Hot path целиком в Go; граница Java↔Go — только управление (start/stop/status/events), 0 вызовов на пакет | прокидывание пакетов через JNI | JNI-переход ~микросекунды × сотни pps × 2 направления — недопустимо; gobind-колбэки медленнее прямого вызова |
| 3 | TUN: sing-box tun inbound (gVisor netstack) внутри Go-ядра, fd передаётся из Java как int | свой netstack-адаптер, hev-socks5-tunnel | тот же паттерн, что libbox/SFA; gVisor чистый Go, уже в дереве sing-box; не тащит второй рантайм (hev — C) |
| 4 | Desync-egress через защищённые kernel-сокеты + socket-примитивы (setsockopt/TCP_MAXSEG/splice), не через raw-пакеты | raw-инжект в TUN | raw egress rootless невозможен (AF_PACKET/raw = root); write в TUN = входящие пакеты; socket-примитивы — доказанный rootless путь (byedpi, SlipNet) |
| 5 | Fake+TTL: JNI/C-помощник `sendFakeThenSwap` (vmsplice+splice+перезапись страниц) | чистый Go на x/sys/unix | механика тонкая (страницы sk_buff), прецедент SlipNet/byedpi на C; Go-вариант — бэкап-путь, сначала C, проверено на Android |
| 6 | Per-network профили: отдельный профиль калибровки на Network (Wi-Fi / each SIM-оператор) | один профиль | домашний и мобильный ТСПУ — разные устройства с разными TTL-окнами; десктопный профиль.json не переносится |
| 7 | v1 IPv4-only TUN | IPv4+IPv6 | IPv6 внутрь TUN добавляет duальный netstack-путь и дыры в правилах; на мобильных операторах IPv4/IPv6-политика неизмерена; IPv6-трафик при заблокированном IPv4-пути = простая дыра отказа — принять осознанно, v2 |
| 8 | Min API 26, target — текущий stable (35/36), Java 8-синтаксис в app-модуле | Kotlin | решение владельца: Java GUI |
| 9 | UID-исключения антифрода в v1: авто-скан пакетов (`ru.*`, `su.*` + зашитый список `com.yandex.*`, `com.avito.*`, банки) → `addDisallowedApplication`; whitelist-режим опцией; сам пакет тоже исключается | только geoip-routing без UID (отклонено) | routing не скрывает TRANSPORT_VPN: anti-fraud SDK (проверено на примере MAX: `hasTransport(TRANSPORT_VPN)` → заглушка) читают activeNetwork; а default=tunnel вдобавок отдаёт банкам IP VPS (Hetzner/DO) — серверная детект-проверка валится даже без локальной |

## 1. Контекст (C4 L1)

```
[Приложения телефона]      [Android OS]                 [VPS xray]
   TG/YT/Discord/…  →  VpnService(TUN) → rupas-android →  VLESS-Reality/XHTTP
                                     (Go-ядро + Java GUI)      ↓
                                     desync | tunnel | direct  [интернет/ТСПУ]
```

Один процесс приложения; один VPN-слот системы (чужой VPN активен → наш
establish рвет его и наоборот — детект и предупреждение до establish).

## 2. Декомпозиция (C4 L2)

```
┌─ app (Java, GUI) ──────────────────────────────────────────────┐
│ MainActivity        — кнопка, статус, лог, настройки            │
│ RupasVpnService     — VpnService: prepare→Builder.establish→fd │
│ StatusNotifications — foreground-нотификация (скорость/статус) │
│ SettingsStore       — EncryptedSharedPreferences (секреты VPS) │
│ ReportExporter      — «почему не работает» → текстовый шаринг  │
└──────────────┬─────────────────────────────────────────────────┘
               │ gomobile bind (AAR): RupasCore
┌──────────────┴─────────────────────────────────────────────────┐
│ rupas core (Go, AAR из E:\rupas)                               │
│  transport/android  — NEW: Android-платформенный слой:          │
│     tun-in (sing-box tun inbound, gVisor, fd от Java)           │
│     egress (protected dialer + socket-примитивы desync)         │
│  inspector / rules / desync / flowtable / prober /               │
│  supervisor / tunnel(sing-box lib) / config  — как на десктопе   │
│  rpc/named-pipe — НЕ переносится (замена: gobind API)            │
└────────────────────────────────────────────────────────────────┘
```

Переносимость подтверждена сканом: Windows-цепочка — `capture/*` (WinDivert),
`app/injector_*`, `app/pipeline_windows.go`, `prober/ttl.go` (сырой форж пакетов),
`rpc/pipe_windows.go`. Портабельное ядро — `inspector`, `rules`, `flowtable`,
`config`, `core/contracts`, `desync/fake.go` (контракт стратегий), `tunnel/*`
(sbinstance/sbconfig/socks/udp/xhttp/health), `prober/classifier+profile`,
`supervisor`.

## 3. Граница Java↔Go (gomobile API)

gobind не поддерживает произвольные типы; API минимальный, байтовые конфиги:

```java
// Java → Go
RupasCore.start(int tunFd, String protectTag, byte[] configYaml); // подъём ядра
RupasCore.stop();
RupasCore.status();               // JSON-строка: машина, туннель, счётчики
RupasCore.reload(byte[] configYaml);
RupasCore.exportReport();         // текст диагностики
// Go → Java (колбэки, редкие)
CoreEvents.onState(String stateJson);   // OFF/PROBING/ACTIVE/DEGRADED + вердикты
CoreEvents.onLog(String line);          // chlog-строки для экрана лога
```

- **protect**: Go-диалер обязан выводить свои сокеты из-под TUN. Механизм:
  `net.Dialer{Control: …}` → в `Control` берём raw fd (`conn.Control`) и зовём
  Java `VpnService.protect(int)` через gobind reverse binding
  (`RupasCore.setProtectHook(func(fd int) bool)`). Прецедент: tabjy/android-vpn-tun2socks,
  libbox PlatformInterface. Fallback-механика (если gobind-колбэк из Control
  капризен): Java-сторона держит `LocalServerSocket`, Go шлёт fd по
  SCM_RIGHTS (паттерн RIPDPI VpnProtectSocketServer). В конфиге sing-box-аутбаундов
  используется `dialer.control`-эквивалент через общий dialer ядра.
- **TUN fd**: `ParcelFileDescriptor.getFd()` → int; процесс один, fd-таблица
  общая — провайдер не нужен. `VpnService.Builder`: адрес 26.26.26.1/24,
  route 0.0.0.0/0, DNS 26.26.26.1 (локальный резолвер ядра, §11), `setMtu(1500)`.
- **Треды**: `start` возвращает сразу; ядро живёт в Go-горутинах; колбэки в Java
  — через `Handler(main)`.

## 4. Горячий путь пакета

```
app-сокет → ядро Android → TUN fd → sing-box tun inbound (gVisor netstack)
   → TCP-поток/UDP-сессия → inspector (SNI/ECH/STUN/DNS из потока) → rules.Match
        ├ DIRECT  → egress: защищённый сокет (protect), для TLS:443 — desync-примитивы
        ├ DESYNC  → egress: защищённый сокет + fake+TTL / split / MSS-clamp (§6)
        ├ TUNNEL  → sing-box outbound (VLESS-Reality/XHTTP/XUDP) — существующий код
        └ BLOCK   → дроп в netstack (QUIC:443) / отказ соединения
   ← ответы: sing-box outbound → netstack → write в TUN fd → приложение
```

Отличия от Windows-горячего пути:
- нет capture/injector/WinDivert и NAT→tproxy: netstack отдаёт **потоки**, а не
  пакеты; терминатор TCP (`tunnel/tcpterm.go`) получает соединения, у которых
  ядро-Android уже закончило handshake с приложением — все соединения
  SYN-ведённые по построению;
- форж «сырых» пакетов (prober/ttl.go на Windows) не используется: калибровочные
  пробы — на защищённых сокетах с теми же socket-примитивами, что и боевой desync
  (§8). Бюджет: gVisor держит сотни Mbps на телефоне (прецедент SFA);
  измерить в S2, регресс — пер-приложенный режим (v2, `addAllowedApplication`).

**Упрощение против десктопа (важно):** проблема §3.2 десктопного дока (вердикт
TUNNEL после SYN → RST + кеш dst + передиал) на Android **не существует**:
SNI читается из потока в netstack **до** открытия исходящего соединения, поэтому
любое соединение дождавшись вердикта просто диалится. `tunnelCache`, RST-логика
и их цена (+1 RTT на новый dst) выпадают из Android-версии.

## 5. Egress-слой (новый: `transport/android/egress.go`)

Единая точка исходящих соединений ядра; контракт:

```go
type Egress interface {
    DialContext(ctx, network, addr, opts DialOpts) (net.Conn, error)
    // DialOpts: Protect=true (всегда, кроме проб с явным bind),
    //           Desync Plan (список Op из desync.Strategy)
}
```

План desync исполняется на сокете **до/вместо** первой записи CH:
`Op{Kind: FakeTTL, TTL: t*}`, `Op{Kind: Split, N: 1..n}`,
`Op{Kind: MssClamp, Mss: 80}`, `Op{Kind: Write, Data}`. Контракт совместим с
`desync.Strategy` десктопа (детерминированный список операций) — меняется только
исполнитель операций: там raw-инжект, здесь socket-примитивы.

## 6. Desync-примитивы на Android (rootless)

| Примитив | Механика | Ограничения |
|---|---|---|
| **split / multisplit** | TCP_NODELAY + N отдельных `write()` — ядро шлёт отдельные сегменты; при необходимости `TCP_MAXSEG` clamp (напр. 80 байт) форсирует мелкую сегментацию на всю сессию | сегментация зависит от ядра; проверить фактически в S1 (tcpdump с ПК через adb недоступен — валидация фактом «пробило/не пробило» пробником) |
| **fake+TTL** | `setsockopt(IP_TTL, t*)` → отправка фейкового CH → `setsockopt(IP_TTL, def)` → реальный CH | фейк умирает после ТСПУ; если TTL слишком большой — сервер получит мусор в потоке → см. swap |
| **fake-then-swap** (для докидывания надёжности) | фейковые байты кладутся в сокет через `vmsplice(SPLICE_F_GIFT)`+`splice` со страниц mmap; после отправки TTL восстанавливается, страницы **перезаписываются реальными байтами** — ретрансмит (если сервер фейк не получил) уносит реальные данные; сервер видит целостный поток | `fake_len == real_len`; требует C/JNI (ADR-5); механизм подтверждён исходниками byedpi (desync.c, restore-логика) и SlipNet (`sendFakeThenSwap`, JNI, Android) |
| **disorder** | не реализуем rootless на socket-примитивах (нужен порядок сегментов) | v1 не делаем; замена — multisplit |
| **QUIC-block** | дроп UDP:443-сессий в netstack | бесплатный |

TTL-фейки: тот же генератор шаблонов, что на десктопе (`build/desync/*.bin`,
uTLS-подобный browser-like CH); GREASE-пустышки фейком не считаются.

## 7. Правила и конфиг

Схема YAML — та же (`internal/config`), включая `tunnels:` (vless tcp +
xhttp_fallback_in_chain), `rules:`, дефолтную политику. Java-сторона хранит
конфиг + секреты раздельно: YAML без секретов в filesDir, секреты (uuid/password)
в EncryptedSharedPreferences и подставляются в конфиг при `start()`.

Профили калибровки: `%ProgramData%`-эквивалент = `filesDir/profiles/<netKey>.json`,
`netKey` = тип сети + SSID/PLMN. TTL-лестница, pacing 4–8 c, TTL-профиль 72 ч,
fast-start — вся логика `prober`/`supervisor` переносится без изменений.

### 7.1 Per-app UID-исключения (антифрод-стелс)

Как работает: `Builder.addDisallowedApplication(pkg)` → system_server строит
UID-ranges (`frameworks/base/.../Vpn.java`) → netd ставит per-UID ip rule: трафик
исключённого UID идёт через физический интерфейс. Официальная семантика
(developer.android.com/develop/connectivity/vpn): *«Disallowed apps use system
networking as if the VPN wasn't running»*.

Что это даёт и чего НЕ даёт:

| Проверка антифрода | Результат для исключённого UID |
|---|---|
| `getNetworkCapabilities(activeNetwork).hasTransport(TRANSPORT_VPN)` (основной метод SDK) | `false` — default network для UID = физическая сеть |
| Серверная проверка IP/ASN | проходит — реальный RU-IP провайдера |
| `getAllNetworks()` + перебор, `NetworkCallback` на все сети | **не гарантировано**: полевые отчёты (per-app VPN на Android, обсуждения методички Минцифры) фиксируют, что приложения вне списка per-app VPN всё равно видят включённый VPN. Честная позиция: гарантируем только activeNetwork-проверки; остаточная видимость — риск, замеряется спайком S4 |
| `NetworkInterface` (`tun0`) | SELinux/UID-изоляция на API 30+ урезает список — не полагаемся, но и не мешает |

Реализация (Java-сторона, до `establish()`):
1. Режим **blacklist** (дефолт): сканируем `getInstalledApplications(0)`, в
   список исключений — префиксы `ru.`, `su.` + зашитый список (`com.yandex.*`,
   `com.avito.*`, `com.vkontakte.android`, известные пакеты банков/госсервисов);
   пользователь редактирует список в GUI. Нужен `QUERY_ALL_PACKAGES`
   (дистрибуция sideload — Play-политика нас не касается).
2. Режим **whitelist** (опция): `addAllowedApplication` только для выбранных
   (браузеры, YouTube, Discord, Telegram). Ловушка: видимость VPN для невключённых
   приложений не исчезает гарантированно (см. выше) + всё незнаемое идёт мимо
   нашей политики. Не дефолт.
3. Сам пакет всегда в исключениях — дубль защиты в дополнение к `protect()`.
4. **Lockdown-ловушка**: при системном always-on «блокировать без VPN» трафик
   исключённых UID **блокируется целиком** (issuetracker 238109298) — банки
   умирают с включённым rupas. Детект lockdown в Java + предупреждение.
5. Исключённые приложения ядро не видит вовсе: 0 CPU, 0 правил — батарея только
   выигрывает; desync к их трафику не применяется (он и не нужен: RU-ресурсы direct).


## 8. Prober на Android

- Пробы — защищённые сокеты (protect) поверх активной Network
  (`ConnectivityManager.getAllNetworks`, bindProcessToNetwork не нужен: protect
  с `Network.bindSocket` на конкретную Network — обязателен при мульти-WAN,
  иначе проба уйдёт не в ту сеть);
- browser-like CH обязателен (uTLS, PQ key share) — лабораторный урок десктопа;
- автокалибровка TTL = та же лестница; мобильный оператор добавляет кандидатов
  t* меньше (у ТСПУ оператора глубина иная) — лестница от 2, не от 12;
- триггеры: старт, смена Network (NetworkCallback), деградация (пассивный
  детектор — существующий), **никаких периодических проб в фоне** (батарея).

## 9. Жизненный цикл и батарея

- `RupasVpnService` — foreground service (`FOREGROUND_SERVICE_TYPE_SPECIAL_USE`),
  `START_STICKY`; нотификация: состояние супервизора + скорость;
- Always-on VPN: метадата `SUPPORTS_ALWAYS_ON` = true; после reboot система сама
  стартует сервис (ядро стартует в OFF → supervisor по профилю fast-start в ACTIVE);
- Doze: foreground-сервис не замораживается; пробы и так привязаны к сетевым
  событиям; wakelock'и не держим;
- `onRevoke` (пользователь/чужой VPN забрал слот): graceful stop ядра, статус в
  GUI; повторный establish — только по кнопке;
- Kill процессом системы: перезапуск через START_STICKY; состояние OFF,
  повторный fast-start ~2 c (профиль жив).

## 10. Структура репозитория и сборка

```
E:\rupas-android\
  docs/PRD.md, docs/SYSTEM_DESIGN.md
  app/                      Java-модуль (GUI, VpnService, настройки)
  core/                     gomobile-обвязка поверх E:\rupas
    mobile.go               gobind API (start/stop/status/events)
    egress_android.go       защищённый диалер + план desync
    tun_android.go          sing-box tun inbound от fd
    jni/                    C-помощники: setTtl, sendFakeThenSwap, mssClamp
  settings.gradle / build.gradle (AGP 8.x, Java 8 source compat)
```

Сборка ядра (из E:\rupas): `gomobile bind -target=android -androidapi 26
-tags "with_utls with_quic" -o app/libs/rupas-core.aar ./core` — теги обязательны
(тот же грабеж, что на десктопе: без with_utls туннель не поднимется).
NDK: jni-помощники собираются внешним gradle-модулем (CMake) и линкуются в app,
`System.loadLibrary` до `RupasCore.start`.
Требование: десктоп-репо остаётся единственным источником ядра — android-слой
живёт в E:\rupas-android и импортирует E:\rupas через go.mod `replace`.

## 11. DNS и IPv6

- TUN объявляет DNS 26.26.26.1; ядро поднимает локальный UDP-резолвер:
  RU-домены → системный DNS реальной сети (direct), прочее → DoH через
  защищённый сокет (блок по DNS-IP не роняет резолв). DNS:53 из приложений
  маршрутизируется правилом DIRECT на резолвер ядра (аналог десктопа);
- IPv6: `Builder.addAddress` только v4; v6-маршруты не добавляем; при
  v6-капабильной сети важно проверить, что приложения не зависают на happy-eyeballs
  (S3-проверка: у youtube/TG не должно быть v6-таймаутов; иначе — `allowFamily(false, AF_INET6)`
  или добавить v6-маршрут в TUN с v6-заглушкой).

## 12. Тестирование и спайки

| Спайк | Что доказываем | Критерий успеха |
|---|---|---|
| S0 (W1, до кода) | Профиль мобильного ТСПУ: SNI-блоки, IP-блоки, UDP-порты, TTL-окно | заполненный JSON-профиль; зоны YT/TG/Discord классифицированы |
| S1 (W2) | socket-примитивы на устройстве: setTtl работает с обычного APK; split реально сегментирует; fake-then-swap не рвёт TLS-поток | тестовый CH с fake t* проходит на заблокированный SNI; сервер получает валидный поток |
| S2 (W2) | gVisor netstack: throughput/память на телефоне под всем трафиком | ≥ скорость канала оператора; RAM ядра < 150 МБ |
| S3 (W3) | сквозной: TG через туннель, YT через desync, Discord голос через XUDP, QUIC-браузер откатывается в TCP | чек-лист PRD US-A1..A3 |
| S4 (W3–W5) | антифрод-стелс: тестовое приложение-зонд (детект-код: activeNetwork, getAllNetworks, NetworkCallback, NetworkInterface) исключается из VPN — что зонд реально видит; заодно поведение банков на реальном устройстве | activeNetwork-детект = false; зафиксировать остаточную видимость allNetworks; банк-приложение без заглушки |

Unit-тесты Go ядра переиспользуются как есть (`go test ./internal/...` на ПК);
известный старый красный `TestPipelineTunnelEscalationNoEndpoint` — не наш.
Инструментальные тесты на устройстве — ручной прогон чек-листов (дистрибуция
внутренняя, CI не требуется).

## 13. Threat model (кратко, отличие от десктопа)

- Секреты VPS в памяти Java-кучи (EncryptedSharedPreferences на диске) — на
  нерутованном устройстве приемлемо; выгрузка дампов не в модели угроз;
- TUN = весь трафик устройства идёт через наш процесс: баг ядра = полная
  потеря связи; митигация — kill-switch поведение по умолчанию (при деградации
  ядра → close fd → система восстанавливает сеть);
- Логи: вердикты CH содержат SNI — отчёт «почему не работает» может раскрывать
  историю обращений; при шаринге — предупреждение/опция вырезать SNI;
- ТСПУ-эскалация: тот же анти-эскалационный pacing, что на десктопе; ускорять
  лестницу нельзя.

## 14. Открытые вопросы (владелец)

1. ~~Per-app режим v2~~ — решено 2026-10-26 (ADR-9): UID-исключения антифрода
   перенесены в v1 (blacklist по умолчанию); полноценные per-app правила ядра — v2.
2. Whitelist-режим: оставить опцией GUI или убрать из v1 (ловушки видимости
   allNetworks + обход политики) — решить после S4.
3. XHTTP-fallback: мобильные операторы иной раз режут длинные TCP-сессии —
   оставить ли fallback-носитель всегда включённым на Android.
4. Нужен ли v1 IPv6-форфардер-заглушка (см. §11) — решить по S3.
5. Имя пакета/applicationId (rupas.android? ru.rupas?) — влияет на ключ
   signature для собственного APK.
