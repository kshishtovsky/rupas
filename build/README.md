# Rupas

[![CI](https://github.com/kshishtovsky/rupas/actions/workflows/ci.yml/badge.svg)](https://github.com/kshishtovsky/rupas/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/kshishtovsky/rupas?sort=semver)](https://github.com/kshishtovsky/rupas/releases/latest)
[![License: MIT](https://img.shields.io/github/license/kshishtovsky/rupas)](LICENSE)
![Go](https://img.shields.io/badge/Go-1.26-00ADD8?logo=go&logoColor=white)
![Platform](https://img.shields.io/badge/platform-Windows%20%7C%20Android-0078D4)

**Обход DPI без прокси в браузере.** Один процесс смотрит на каждый поток и решает
его судьбу: модифицировать пакеты локально (desync, без сервера, полная скорость
канала), увести в туннель на VPS (VLESS-Reality) или пропустить напрямую.
Цели v1 — Telegram, YouTube, Discord на домашнем ISP; перехват идёт на уровне
пакетов, ни одно приложение настраивать не нужно.

## Скачать

| Платформа | Файл из [Releases](https://github.com/kshishtovsky/rupas/releases/latest) | Установка |
|---|---|---|
| Windows 10/11 | `Rupas-win64-<ver>.zip` | распаковать в любую папку, запустить `rupas-gui.exe` (нужен администратор для WinDivert) |
| Android 8+ (arm64) | `Rupas-android-<ver>-arm64.apk` | открыть файл, разрешить установку из этого источника |

Рядом лежит `SHA256SUMS.txt` — проверить целостность:
`certutil -hashfile Rupas-win64-0.6.0.zip SHA256`.

## Автообновление

Приложение само узнаёт о новой версии: раз в 12 часов опрашивает
`/releases/latest` GitHub API (плюс кнопка «Проверить обновления» в настройках и
проверка при старте). Нашлась новее — предлагает обновиться, скачивает и
устанавливает: APK проверяется по подписи, архив для Windows — по SHA256.
Ручных действий при обновлении не требуется.

## Цели v1

Telegram, YouTube, Discord на домашнем ISP. Пользователь не настраивает
прокси ни в одном приложении: перехват идёт на уровне пакетов.

## Статистика

<!-- stats:start -->
| Метрика | Значение |
|---|---|
| Go-код (без тестов) | 26383 строк, 25 пакетов |
| Тесты | 22887 строк, ~250 тестов |
| Android (Java) | 7134 строк |
| Коммитов / релизов | 77 / 1 |
<!-- stats:end -->

## Стек

| Слой | Технология |
|---|---|
| Язык | Go 1.26 |
| Перехват пакетов | WinDivert 2.2 (подписанный драйвер), `pkg/windivert` |
| Туннель | sing-box как библиотека (`-tags with_utls with_quic`), VLESS-Reality / Hysteria2 / XHTTP |
| TLS-фингерпринт | uTLS (браузероподобный ClientHello) |
| Управление | named pipe `\\.\pipe\rupasctl`, JSON-line RPC |
| TUI | bubbletea + lipgloss |

## Быстрый старт

Сборка — **только с тегами**, иначе sing-box не поднимется и все TUNNEL-правила
эскалируются в direct (симптом: «телеграм вообще не работает»):

```powershell
go build -tags "with_utls with_quic" -trimpath -ldflags "-s -w" ./cmd/rupasd ./cmd/rupasctl
# или
make build
```

Требуется консоль администратора (WinDivert ставит драйвер) и `WinDivert.dll` +
`WinDivert64.sys` рядом с бинарником (лежат в `build/`, отслеживаются в git).

Конфиг: скопировать `configs/rupas.example.yaml` → `configs/rupas.yaml` и вписать
свои эндпоинты. `configs/rupas.yaml` в gitignore — он содержит uuid/password.

Запуск:

```powershell
build\rupasd.exe -config configs\rupas.yaml    # демон (стартует в состоянии OFF)
build\rupasctl.exe start                        # поднять демон в фоне, если не запущен
build\rupasctl.exe on                           # включить перехват
build\rupasctl.exe status
build\rupasctl.exe tui                          # интерактивный редактор + статус
```

Первый `on` без сохранённого профиля калибрует канал 2–4 минуты (лестница TTL с
паузами — защита от эскалации ТСПУ). Профиль сохраняется в
`%ProgramData%\rupas\profile.json`; все последующие старты — **~2 секунды**.

## Команды

| Команда | Что делает |
|---|---|
| `make build` | сборка с обязательными тегами |
| `make test` | `go test -race -count=1 ./...` (248 тестов) |
| `make lint` | `go vet ./...` |
| `make bench` | бенчмарки горячего пути |
| `go test -tags "live with_utls" -run TestLive...` | живые замеры против реального ISP/VPS |

`-race` требует cgo/gcc — на хосте без gcc он недоступен, тогда обычный `go test`.

## Структура

```
cmd/
  rupasd/      демон: флаги, RPC-сервер, склейка app; вся логика в internal/
  rupasctl/    CLI + TUI (status/on/off/start/probe/reload/logs/tui)
  labdiff/     живой дифференциальный зонд механики fake-инжекта
  testmutex/   проверка single-instance мьютекса
internal/
  app/         сборка рантайма: конфиг, пайплайн, prober, туннель, супервизор
  capture/     WinDivert: recv/send, фильтры, горячий путь, форж пакетов
  inspector/   потоковые парсеры: TLS ClientHello (SNI/ALPN/ECH), STUN, DNS
  rules/       компиляция конфига в неизменяемые таблицы решений (CIDR-trie, SNI-карты)
  desync/      стратегии fake/split → детерминированный список операций
  tunnel/      sing-box: NAT→tproxy, userspace TCP-терминатор, UDP, health
  prober/      классификация канала, калибровка TTL, персистентный профиль
  supervisor/  state machine OFF/PROBING/ACTIVE/DEGRADED, событийный лог
  flowtable/   шардированная conntrack-подобная таблица потоков
  config/      схема YAML, валидация, дефолтный профиль
  core/        контракты между модулями (типы и интерфейсы, без логики)
  rpc/         named pipe сервер/клиент
pkg/windivert/ обёртка WinDivert (фильтры, адреса, хелперы)
mobile/        gobind-пакет: мост ядра в Android (AAR)
android/       Android-приложение (Java, minSdk 26), собирается gradle из mobile/
.github/       CI: сборка/тесты на PR, релиз и артефакты на push в master
build/         WinDivert.dll/.sys, шаблоны desync (в git), бинарники и логи (игнор)
configs/       пример конфига (в git), реальный конфиг и .bak (игнор)
docs/          PRD.md, SYSTEM_DESIGN.md, PRD релизов и автообновления
```

## Архитектура

Один Go-процесс, никакого IPC на пакетах (ADR-1). Горячий путь:

```
WinDivert → capture.Engine → inspector (ClientHello) → rules.Match
                                    ↓
              DIRECT (pass) | DESYNC (fake+TTL) | TUNNEL (NAT→tproxy→sing-box)
```

Порядок разрешения правил фиксирован: **CIDR → SNI → ports → default**.
У правила есть `proto` (`tcp`/`udp`/пусто) и четыре действия: `direct`, `desync`,
`tunnel`, `block`.

Ключевая особенность TUNNEL: вердикт часто приходит уже после SYN (SNI виден
только в ClientHello). Тогда движок шлёт клиенту RST, кеширует dst на 60 с, и
следующий SYN того же dst ловится fast-path'ом и уходит в терминатор. Без этого
поток висит до таймаута (терминатор терминирует только SYN-ведённые соединения).

ECH: клиент шлёт GREASE-расширение (1 байт) почти на каждый ClientHello —
это не настоящий ECH. Настоящий ECH (payload > 1 байта) ТСПУ дропает, поэтому
такие потоки принудительно уходят в туннель.

## Маршрутизация (текущая политика)

| Трафик | Действие |
|---|---|
| LAN (10/8, 172.16/12, 192.168/16, link-local, multicast) | direct |
| DNS :53 | direct (иначе рекурсия через VPS) |
| `*.ru`, `*.su`, `*.рф` и прочие RU-зоны | direct |
| RU-сервисы на .com (vk.com, ok.ru, userapi.com) | direct — VPS не дозванивается до RU-IP |
| YouTube / googlevideo | desync |
| Discord (все домены), голосовые порты, STUN :3478 | tunnel |
| Telegram CIDR (включая медиа 91.105.192.0/23, 185.76.151.0/24) | tunnel |
| UDP :443 (QUIC) | block — браузер сам уйдёт на TCP |
| **всё остальное** | **tunnel** |

Цена режима «всё остальное → туннель»: первое соединение с новым адресом
получает RST и передиал (+1 RTT один раз на dst). Браузеры это делают молча.

## TUI

`rupasctl tui` — четыре вкладки: **Статус** (живой опрос демона, хоткеи
`o`/`f`/`p`, запуск демона по `o` если он лежит), **Правила** (таблица с
переупорядочиванием — порядок = приоритет), **Desync**, **Туннели** (секреты
маскированы). `s` на любой вкладке конфига: валидация движком → `.bak` →
атомарная запись → reload демона → откат при отказе. Если демон оффлайн, файл
всё равно сохраняется (валидация уже прошла).

## Документация

| Файл | Содержание |
|---|---|
| `docs/PRD.md` | продуктовые требования, лабораторный фундамент, user stories, MVP-скоуп |
| `docs/SYSTEM_DESIGN.md` | ADR, горячий путь, структуры данных, стратегии desync, prober, супервизор, threat model |
| `docs/PRD_RELEASE_PIPELINE.md` | требования к релизам, CI/CD и автообновлению (бизнес-обоснование) |
| `docs/VERSIONING.md` | правило версий: что двигает major/minor/patch, как устроен `VERSION` |
| `docs/RELEASING.md` | как выпускается релиз, что делать при откате и поломке CI |
| `CHANGELOG.md` | история изменений (генерируется CI) |

## Грабли

- **Сборка без `-tags "with_utls with_quic"`** — демон стартует, но туннель не
  поднимается: `uTLS is not included in this build`. TUNNEL-правила эскалируются
  в direct, Telegram-CIDR уходит в чёрную дыру. Ошибка выглядит как баг кода.
- **`rupasctl off` не всегда убивает процесс.** После подмены бинарника проверяй
  `StartTime` процесса: старый образ продолжает жить на переименованном файле, а
  новый экземпляр выходит по single-instance мьютексу.
- **Пробы через TUN.** Если на хосте работает VPN-клиент с TUN (Happ, sing-box),
  пробы без биндинга на физический NIC классифицируют всё как заблокированное.
  В логе должно быть `prober: probes bound to Ethernet (…)`.
- **`configs/rupas.yaml` содержит секреты** — он и `*.bak` в gitignore; в git
  лежит только `rupas.example.yaml`.
- **`build/` не полностью игнорируется**: `WinDivert.dll`, `WinDivert64.sys` и
  `build/desync/*.bin` обязательны в рантайме и отслеживаются.
- **ТСПУ флапает.** desync может не пробивать минуту-другую после серии
  неудачных попыток (residual censorship ~420 с на 4-tuple). Это не баг движка —
  проверяй на свежем dst и через несколько минут.
