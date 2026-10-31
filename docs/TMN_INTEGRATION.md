# TMN/1 (TUMAN) в Rupas — техтребования и декомпозиция

Статус: этап 1 (интеграция как TCP-транспорта). Ветка: `feat/tmn` (от `master`).
Источник: `E:\PET\tuman` (репо `github.com/kshishtovsky/tuman`, ветка `exp/tmn`).

## 1. Цель и границы

Дать Rupas четвёртый транспорт — свой протокол TMN/1 поверх TLS 1.3 с мультиплексированием,
сайтом-прикрытием и анти-зондированием, — чтобы проверить его с телефона и с десктопа
на живом канале рядом с Reality/XHTTP.

Входит:

- TCP-потоки через TMN/1 в десктоп-ядре (Windows: WinDivert + терминатор) и в Android-ядре (VpnService/TUN).
- Разбор share-ссылок `tmn://` в общем парсере (его используют и GUI, и Android).
- Постоянно работающий `tmns` на VPS `45.67.202.247`, порт 18443, доверенный серт, systemd.
- Профиль (ссылка) для телефона и для десктопа.

Не входит (осознанно, не «потом допишем по ходу»):

- UDP/QUIC внутри TMN: в протоколе нет UDP-потоков (`socks.go`: BAND/UDP ASSOCIATE не поддержаны).
  Discord-voice и QUIC продолжают идти через hysteria2/XUDP-цепочку.
- Шейпер формы трафика на клиенте: поле разбирается и пробрасывается, но значение по умолчанию `off`
  (как в `tmnc`). Включение — отдельное решение после замеров.
- iOS/desktop-GUI-косметика (иконки, отдельные экраны).
- uTLS/JA3-маскировка внутри TMN (сейчас `crypto/tls` Go-клиента; см. §7).

## 2. Контракт библиотеки `tuman/client` (заморожен)

`cmd/tmnc` сегодня — `package main`: пул сессий, health, backoff, TLS-диал и mux внутри одного файла.
Rupas не может это импортировать, поэтому логика переезжает в пакет `client`, а `tmnc` остаётся
тонкой обёрткой (SOCKS5 + TOML). Поведение, цифры и тесты не меняются.

```go
package client

type Endpoint struct {
    Addr string // host:port
    SNI  string // пусто → Config.SNI, иначе Addr-host
}

type Config struct {
    Servers  []Endpoint    // пул раскладывается по ендпоинтам
    PSK      []byte        // 32 байта
    SNI      string        // общий SNI по умолчанию
    Insecure bool          // только для отладки
    Conns    int           // 1..8, 0 → 4
    Profile  string        // off|browse|video|bulk|voice, пусто → off
    Cooldown time.Duration // пауза ендпоинта, 0 → 30s
    Dialer   *net.Dialer   // аплинк; nil → &net.Dialer{}. Android передаёт ProtectedDialer
    Logger   *slog.Logger  // nil → slog.Default()
}

func New(cfg Config) (*Client, error)              // только валидация, сети не касается
func (c *Client) DialContext(ctx context.Context, network, addr string) (net.Conn, error)
func (c *Client) Close() error
func (c *Client) Stats() Stats                     // Dialed, Live — для логов/статуса
```

Инварианты, которые обязаны сохраниться при переносе:

1. `New` не открывает соединений. Пул стартует на первом `DialContext` (иначе мёртвый ендпоинт
   на старте Rupas подвешивает `Tunnel.Start` и тратит cooldown до первого пакета).
2. `network` только `"tcp"`; иначе ошибка `ErrNetwork` (без паники, без тихого успеха).
   `addr` — `host:port`, домен разрешается на выходе (`proto.EncodeTarget`).
3. `DialContext` ждёт появления живой сессии, но не дольше `ctx`: `ctx` отменён → `ctx.Err()`.
4. `Close` идемпотентен, закрывает пул и все сессии; после него `DialContext` → `ErrClosed`.
5. TCP_NODELAY на аплинке, TLS 1.3 + ALPN `h2`, exporter-ключ `TMN1-AUTH-RANDOM` — как есть.
6. Health/backoff/ротация ендпоинтов, round-robin по живым сессиям, ретрай `open` на мёртвой
   сессии — семантика `connector` не меняется (иначе теряются замеры 422 Мбит/с и разбор обрывов).
7. Секреты (PSK, SNI, цели) не попадают в логи: `reason(err)` остаётся укороченным.

Тест-гейт пакета: `client_test.go` поднимает in-process TLS+mux сервер (паттерн
`cmd/tmns/tunnel_test.go`), проверяет roundtrip через echo, отказ на `udp`, переподключение пула
после обрыва сервером, `Close`+`ErrClosed`. Плюс `go test ./... -count=1` по всему репо tuman.

## 3. Формат ссылки

```
tmn://<psk-hex64>@host:port?sni=<прикрытие>&conns=4&profile=off&insecure=0#<имя>
```

- `userinfo` — PSK, 64 hex-символа (32 байта). Как uuid у vless: секрет в ссылке — норма жанра.
- `sni` — обязателен, если `host` — IP; иначе по умолчанию равен `host`.
- `conns` 1..8 (по умолчанию 4), `profile` — `off|browse|video|bulk|voice` (по умолчанию `off`),
  `insecure` 0/1 (по умолчанию 0; нужен только если серт на сервере окажется самоподписанным).
- фрагмент — имя профиля (в логах и UI).

Ошибки парсера — как у остальных схем: без утечки PSK в текст ошибки (`truncate(raw, 48)`
уже маскирует, но hex-PSK не должен попадать в `err` целиком).

## 4. Точки интеграции в Rupas

| Место | Что добавить |
|---|---|
| `internal/config/config.go` | `KindTMN = "tmn"`; поля `PSK string`, `Conns int`; `EndpointKinds()`; `SingBoxKind()` → false для tmn; `SupportsUDP()` → false; `Validate()` — host/port/PSK(64 hex)/conns 1..8 |
| `internal/tunnel/tmn.go` (новый) | `tmnPath` — реализация `tcpCarrier`: `dial`/`dialHost` через `client.Client`, ленивый старт (как `lazyXHTTP`), `Close()` на остановке туннеля, `paced=false` (пул сессий, не одно соединение на dial) |
| `internal/tunnel/tunnel.go` | `carrierTCP`: ветка для `KindTMN`; `Stop` закрывает `tmnPath` |
| `internal/transport/android/sharelink.go` | `KindTMN`, поля `Endpoint.PSK/Conns`, `parseTMNLink`, ветка в `ParseShareLink`, `NeedsNative()` (`xhttp` и `tmn`) |
| `internal/transport/android/engine_chain.go` | нативный carrier для tmn: `client.New(Config{Dialer: ProtectedDialer(protect)})`; цепочка строится **даже если relay не поднялся** (сегодня `if e.relay == nil { return }` — единственный tmn-профиль останется без carrier'ов) |
| `internal/transport/android/relay.go` | tmn-ендпоинт не попадает в sing-box inbounds (`NeedsXHTTP` → `NeedsNative`) |
| `mobile/probe.go` | `TestProfile` для `tmn://` — dial через `client` (как xhttp), чтобы кнопка «проверить профиль» врала меньше туннеля |
| `internal/guictrl/share.go` | `classify` → kind `tmn`, роль `tcp`; `endpointFor` → `config.Endpoint{Kind: "tmn", …}` |
| `internal/guictrl/service.go` | при сохранении ссылок добавлять SNI tmn-ендпоинта в `exclusions.domains` (см. §5) и упоминать tmn в текстах ошибок |
| `android/app/src/main/java/ru/rupas/android/ParseLink.java` | схема `tmn` в регексе и в подписях типа профиля |
| `configs/rupas.example.yaml`, `build/rupas.example.yaml` | пример блока `tunnels.tcp` с `kind: tmn` (без реального PSK) |
| `docs/` | эта спека + строка в CHANGELOG |

## 5. Обязательное условие: сервер не уходит сам в себя

Клиент TMN сам открывает TLS к `45.67.202.247:18443` с SNI прикрытия. На Windows это соединение
поймает WinDivert; если оно классифицируется как TUNNEL — петля и вечное «туннель молчит».
Поэтому при сохранении `tmn`-ссылки SNI ендпоинта обязан попасть в `exclusions.domains`
(и IP в `exclusions.cidrs`, если `host` — литеральный IP). На Android этого не нужно:
сокеты клиента уходят через `VpnService.protect`.

## 6. Сервер

- Хост `45.67.202.247` (`ssh -p 10222 medovarov@…`), рядом работают Caddy (80/443),
  3x-ui, hysteria, docker — **их не трогать** (ни restart, ни правок конфигов).
- Новые файлы только: `/usr/local/bin/tmns`, `/etc/tmn/{tmns.toml,psk,fullchain.pem,privkey.pem}`,
  `/var/www/tmn/` (статика прикрытия из `deploy/cover`), `/etc/systemd/system/tmns.service`,
  `/usr/local/bin/tmn-cert-sync` + `.timer`.
- Порт `18443/tcp` (как в замерах 28.10), `ufw allow 18443/tcp` — только добавление правила.
- Серт: копия живого LE-серта Caddy для `mylifemyrulesonline.ru` (SNI прикрытия = этот домен,
  DNS уже указывает на VPS). Ротация — таймер раз в сутки копирует более свежий серт и
  перезапускает `tmns`, если файл изменился. Самоподписанный — только как аварийный фолбэк,
  с явной пометкой в отчёте и `insecure=1` в ссылке.
- `install.sh` из `deploy/` **не запускать**: он ставит Caddy-сниппет и sysctl,
  а reload Caddy — не наша операция.

## 7. Риски и ограничения (знать до выводов о «круче Reality»)

1. **JA3.** Клиент TMN — стоковый `crypto/tls` Go: ClientHello не как у Chrome. Пока трафик не
   зондируют по отпечатку, это не видно; при включении фингерпринт-фильтров TMN падает первым.
   Лечится uTLS внутри `client` (зависимость `refraction-networking/utls`, как у Rupas) — отдельная задача.
2. **Нет UDP.** Видеозвонки и QUIC — мимо. Для «заменить всё» протокол пока не годится.
3. **Один VPS, один IP.** Отказ IP = отказ транспорта; пул ендпоинтов в протоколе есть,
   но второго сервера нет.
4. **Прикрытие.** Порт 18443 отдаёт статику под тем же доменом, что Caddy на 443: внимательный
   бордер-сканер может сравнить ответы двух портов. Альтернатива — поддомен (`tmn.<домен>`
   + A-запись), это решение владельца, не код.
5. **Скорость.** Медиана 165 Мбит/с против 211 у Reality на том же маршруте (замер 28.10,
   окна 12 с). Повторный замер после интеграции — с окнами ≥25 с и чередованием A/B.

## 8. Критерии приёмки

1. `go build ./... && go vet ./... && go test ./internal/... ./cmd/... -count=1` в Rupas — зелено
   (кроме известного `TestPipelineTunnelEscalationNoEndpoint`).
2. `go test ./... -count=1` в tuman — зелено; `tmnc` против живого `tmns` качает 10 МБ.
3. Десктоп: конфиг с `kind: tmn` стартует, в логе `dial chain: …tmn@…`, `curl` через tproxy-порт
   отдаёт 200, `Stats` показывает живые сессии пула.
4. Android: APK собирается (`make aar`/`make apk` с `ANDROID_HOME=C:/android-sdk`), профиль `tmn://`
   импортируется, VPN стартует, в логе carrier `tmn@…` первым, HTTP-запрос из браузера проходит.
5. Сервер: `systemctl is-active tmns` = active, `ss -tln | grep 18443`, прикрытие отдаёт 200/404,
   после `systemctl restart tmns` клиент восстанавливается ≤60 с.
6. Секретов нет в git: PSK только в `deploy/.server-tmn.env` (в `.gitignore`) и в ссылке, которую
   владелец копирует себе сам.

## 9. Декомпозиция (владение файлами — во избежание конфликтов)

| Волна | Задача | Файлы |
|---|---|---|
| 0 | A. `tuman/client`: библиотека + module path + тег `v0.1.0` | `E:\PET\tuman` целиком |
| 0 | B. сервер: tmns на 18443, серт, systemd, проверка с десктопа | VPS + `E:\PET\tuman\deploy\.server-tmn.env` |
| — | C. схема: `KindTMN` в config, `tmn://` в sharelink, спека | `internal/config/config.go`, `internal/transport/android/sharelink.go`, `docs/` |
| 1 | W1. десктоп-ядро: ✅ `internal/tunnel/tmn.go` (`tmnPath`/`lazyTMN`, PSK hex→bytes, `Cooldown` 0 → 30 s, `dialTO` 20 s), ветка `KindTMN` в `carrierTCP` (`paced: false` — пул из 4 долгих сессий, пейсинг только резал бы скорость), `tmnPaths` закрываются в `Stop`; tmn не попадает в sing-box (`SupportsUDP`=false → `plan.udp=nil`, все порты под `SingBoxKind()`); тесты `TestTMNDialEcho`, `TestTMNDialHostDomain`, `TestTMNClose`, `TestTMNLazyCloseNeverDialed`, `TestTMNOnlyPlanNeedsNoSingbox` | `internal/tunnel/tmn.go`, `internal/tunnel/tunnel.go`, `internal/tunnel/tmn_test.go` |
| 1 | W2. Android-ядро: ✅ `newTMNCarrier` в `buildCarriers` (один `client.New` на ендпоинт, `Dialer` = protecting-dialer, иначе TUN закольцуется), нативные носители строятся **до** `if e.relay == nil`; `Engine.tmn` + `closeTMN` на старте и по `defer` в TUN-run; `relay.go` фильтрует `NeedsNative()` (tmn/xhttp не идут в sing-box и не пре-резолвятся); `mobile/probe.go` — ветка `tmn` с закрытием пула и PSK в `redact`; `ParseLink.java`/`MainActivity.java` принимают `tmn`; AAR собран (80.6 МБ); тесты `TestTMNOnlyProfileBuildsOneCarrier`, `TestTMNCarrierWithoutRelay`, `TestTMNCarrierUsesProtectedDialer`, `TestProbeUsesClientForTMN`, `TestTestProfileTMNHidesPSK` | `internal/transport/android/{engine_chain,engine,relay,tun}.go`, `mobile/`, `android/app/…/ParseLink.java` |
| 1 | W3. GUI и конфиг: ✅ `classify`/`endpointFor` → kind `tmn`, роль `tcp` (tmn-ссылка становится `tunnels.tcp`, hysteria2 рядом остаётся `udp`); `SaveLinks` добавляет SNI ендпоинта в `exclusions.domains` и литеральный IP как `/32` в `exclusions.cidrs` (merge с конфигом, без дублей, домены без учёта регистра); tmn в текстах «нужен vless…»; пример блока в `configs/rupas.example.yaml`; тесты `TestParseTMNChannel`, `TestTMNPlanOrdering`, `TestSaveLinksTMNExclusion` | `internal/guictrl/share.go`, `internal/guictrl/service.go`, `internal/guictrl/tmn_test.go`, `configs/rupas.example.yaml` |

Волна 1 стартует только после тега `v0.1.0` и `go get github.com/kshishtovsky/tuman@v0.1.0`.

Примечание по `build/rupas.example.yaml`: в репозитории этого файла нет — `scripts/make-dist.ps1`
копирует туда `configs/rupas.example.yaml`, поэтому пример tmn-блока живёт только в `configs/`.
