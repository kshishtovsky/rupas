# Rupas GUI (Windows) — дизайн-документ
## v1.0 · одно-кнопочный GUI-клиент поверх существующего ядра rupasd
Стилистика — `E:\rupas-android` (тема «dose»: тёплая бумага, зелёно-чёрные чернила, один шалфейный акцент).
Приложение к docs/PRD.md (§7 US-1, §8) и docs/SYSTEM_DESIGN.md (§9: «GUI использует тот же pipe»).

---

## 0. Реестр решений (ADR-краткость)

| # | Решение | Альтернативы | Почему |
|---|---|---|---|
| D1 | GUI = отдельный процесс `rupas-gui.exe`, ядро не трогаем | встроить GUI в rupasd | UAC-изоляция: демон живёт под админом, GUI — нет; крэш/рестарт GUI не рвёт перехват. Pipe-DACL уже даёт interactive user доступ |
| D2 | Wails v3.0.0 (stable, 2026-10-26) + TypeScript + HTML/CSS | Fyne, Gio, WebView1 fixed | PRD §8 прямо называет Wails; v3 stable даёт single-binary ~10–15 МБ, нативный трей, frameless-окна, события Go→JS; HTML/CSS — точный перенос темы «dose» из rupas-android (colors.xml 1:1 → CSS-переменные) |
| D3 | Онбординг = последовательность окон визарда (5 шагов), далее главная с bottom-nav (Главная/Журнал/Настройки) | one-page setup | UX-паттерн уже выработан в Android-версии (activity_settings + wizard-like flow), повторяем знакомый пользователю сценарий |
| D4 | Первый пробинг: GUI шлёт `probe` по pipe после `on`; geoip-таблицы качает сам демон при rules.Compile (internal/geoip уже так работает) | качать в GUI | один владелец сети-ассетов — демон; GUI только показывает прогресс |
| D5 | VLESS-конфиг: парсинг `vless://`-ссылки + ручной ввод полей (порт ParseVless.java → Go) | только YAML-файл | тот же UX, что Android: вставил ссылку → поля заполнились |
| D6 | Управление демоном: `rupasctl start`-механика переносится в GUI (startDaemon/waitForDaemon из daemon_windows.go), elevation через ShellExecute runas только при старте rupasd | сервис Windows | минимум новых сущностей; existing single-instance mutex демона делает дабл-старт безопасным |
| D7 | Статус-модель GUI = маппинг состояний supervisor (OFF/PROBING/ACTIVE/ACTIVE_TUNNEL_ONLY/DEGRADED) на 4 визуальных состояния кнопки | свой FSM в GUI | единый источник правды — core.Snapshot по RPC `status` |

---

## 1. Вопрос и метод

**Вопрос:** спроектировать Windows-GUI для Rupas: первый запуск — визард (скачивание ассетов, ввод VLESS, первый пробинг), затем главное окно с одной кнопкой ВКЛ/ВЫКЛ и навигацией. Оценить реализуемость на Go.

**Метод:** сопоставление требований с существующими швами кода (rpc pipe, geoip, config.Load, supervisor FSM); перенос дизайн-токенов из E:\rupas-android; выбор GUI-фреймворка по критериям (бинарник, треи, HTML/CSS-перенос темы, зрелость).

---

## 2. Данные/факты (из репозиториев, проверено)

| Факт | Источник |
|---|---|
| RPC: named pipe `\\.\pipe\rupasctl`, JSON-line, команды `status/on/off/probe/reload/logs/debug` | internal/rpc/server.go:191-210, SYSTEM_DESIGN §9 |
| Pipe DACL: SYSTEM + interactive user — GUI без админки сможет слать команды | pipe_windows.go:39-61, SYSTEM_DESIGN §9 |
| `status` возвращает core.Snapshot: State, Since, Tunnel(TunnelStatus), Flows, Counters | internal/core/contracts.go:22-36 |
| Состояния supervisor: OFF/PROBING/ACTIVE/ACTIVE_TUNNEL_ONLY/DEGRADED | internal/supervisor/machine.go:19-22 |
| GeoIP-таблицы: демон сам скачивает/кэширует при rules.Compile (мирроры, refresh_days, fail-loud) | internal/geoip/geoip.go:1-12 |
| VLESS-эндпоинт: kind/host/port/uuid/sni/pbk/sid/flow/alpn/fingerprint — валидация есть (Endpoint.Validate) | internal/config/config.go:214+ |
| Android ParseVless.java: vless://uuid@host:port?pbk&sid&sni#label → Result{uuid,server,port,sni,pbk,sid,fallback,warning} | E:\rupas-android .../ParseVless.java |
| Демон стартует detached (startDaemon), ждётся по pipe (waitForDaemon) | cmd/rupasctl/daemon_windows.go:52-125 |
| Тема «dose»: colors.xml (paper/ink/accent …), dimens (152dp power button, 4pt spacing), layouts (tab_home с power disc, tab_logs, tab_settings), bottom_nav_menu (3 вкладки) | E:\rupas-android/app/src/main/res |
| Wails v3.0.0 stable released 2026-10-26 (после 34 betas + v2.17) | api.github.com/wailsapp/wails/releases |
| PRD §8: «GUI — Wails (лёгкий, нативный) или консоль+трей v0»; §13 roadmap: GUI после CLI-валидации | docs/PRD.md |

Допущения (не из кода): размер Wails-бинарника ~10–15 МБ; WebView2 предустановлен в Win10/11 — install не нужен. Проверить на сборке.

---

## 3. Архитектура (C4 L2)

```
┌─────────────────────────── rupas-gui.exe (не elevated) ───────────────────────────┐
│  Wails v3 frontend (TS/HTML/CSS)        backend (Go)                              │
│  ┌───────────────────────┐             ┌────────────────────────────┐            │
│  │ Wizard (5 шагов)      │  events →   │ daemonctl: start/wait/      │            │
│  │ Home (power disc)     │  Wails      │   elevate (runas)           │            │
│  │ Logs (stream)         │  bindings   │ rpcclient: pipe dial,       │            ││
│  │ Settings              │             │   JSON-line req/resp        │            │
│  └───────────────────────┘             │ vless: parse link (D5)      │            │
│         theme.css («dose»)             │ config: write YAML (D5)     │            │
└────────────────────────────────────────┴─────────────────────────────┘
                 │ named pipe \\.\pipe\rupasctl (JSON-line RPC)
        ┌────────▼─────────┐
        │ rupasd.exe (admin)│  capture (WinDivert) · rules · tunnel (sing-box)
        │ supervisor FSM    │  geoip download · prober · flowtable
        └──────────────────┘
```

Ключевые принципы:
1. **GUI ничего не решает сам.** Вердикты — в ядре; GUI — рендер Snapshot + команд on/off/probe/reload. (Допущение о «первом пробинге»: GUI ждёт перехода PROBING→ACTIVE в статусе; отдельного RPC не нужно.)
2. **Daemon-first.** Любое действие начинается с ensureDaemon(): pipe не отвечает → startDaemon (elevated, runas) → waitForDaemon по poll'у.
3. **Один писатель конфига.** Все правки через config.Load-валидацию → запись → RPC reload → откат при отказе (тот же контракт, что TUI, SYSTEM_DESIGN §9).

---

## 3a. Модель данных GUI

```go
// internal/guictrl/types.go — типы GUI-слоя (маппятся из core.Snapshot)
type UIState string // "off" | "connecting" | "on" | "error"

func mapState(s core.Snapshot) (UIState, string) // FSM-маппинг §7
```

Snapshot → UI (одно место истины):
- State OFF → `off`; PROBING → `connecting`; ACTIVE/ACTIVE_TUNNEL_ONLY → `on`; DEGRADED → `error`.
- Tunnel.Mode: tunnel|escalated|off → бейдж туннеля; Held → warn.
- Counters/Flows → карточки статистики.

---

## 4. Стили: перенос темы «dose» из rupas-android

Все токены — из `E:\rupas-android/app/src/main/res/values/colors.xml`, `dimens.xml`, `themes.xml` (ссылки в §2). Правило проекта: «every colour in the app resolves to one of these names; no literal colour outside this block» — переносим в CSS-переменные 1:1.

```css
:root {
  /* paper / ink — из colors.xml */
  --paper: #F7F3EC; --paper-2: #FDFBF6; --paper-3: #EFEAE0; --paper-4: #E6E0D4;
  --ink: #26312C; --ink-2: #4F5B55; --ink-soft: #65706A; --ink-faint: #A2ABA4;
  --rule: #E3DDD2; --rule-strong: #CFC8BB; --field: #7F8B84;
  --accent: #3B745E; --accent-deep: #2F5F4C; --accent-soft: #DFEDE2;
  --accent-tint: #EDF4EE; --accent-ink: #FAFCF9; --focus: #2F5F4C;
  --tint-sand: #F4EDE1; --tint-sky: #E7EEF0;
  --warn: #7A6136; --warn-soft: #F6EEDC; --danger: #8A4A42; --danger-soft: #F7E9E6;
  /* spacing 4pt из dimens.xml */
  --space-xxs: 4px; --space-xs: 8px; --space-s: 12px; --space-m: 16px;
  --space-l: 20px; --space-xl: 24px; --space-xxl: 32px; --space-xxxl: 40px;
  --radius-input: 14px; --radius-panel: 20px; --radius-card: 24px; --radius-pill: 999px;
  --control-height: 52px; --power-button: 152px; --power-tray: 216px;
}
```

Компоненты (портированные drawables → CSS):
- power disc: `btnPower` (152dp) в mint tray (216dp) + outer ring → CSS круг, border-radius 999px, box-shadow мягкая;
- статусы диска: `bg_power_circle_off/on/connecting/error` → классы `.disc.off/.on/.connecting/.error` (accent/ink-soft/warn/danger);
- карточки: `bg_card.xml` → `.card { background: var(--paper-2); border: 1px solid var(--rule); border-radius: var(--radius-card); }`;
- поля ввода: `bg_input.xml` → `.input { height: var(--control-height); border-radius: var(--radius-input); border: 1px solid var(--field); background: var(--paper-2); }`;
- tech-chips (fallback/DPI): pill 999px, accent-soft bg;
- nav: floating tab bar on paper — 3 вкладки (ic_nav_home/logs/settings → inline SVG по pathdata из drawable/*.xml);
- шрифт: sans-serif (system-ui stack), letterSpacing 0; elevation = тень, не тон (elevationOverlayEnabled=false → без тонированных поверхностей).

Тёмная тема: в «dose» её нет (forceDarkAllowed=false) — v1 не делаем.

## 4a. Вид главного окна (спецификация)

```
┌──────────────────────────────────────┐
│ Rupas                    ● Отключено │  header: logo + statusDot(8px)+statusText
├──────────────────────────────────────┤
│                                      │
│            ╭────────────╮            │
│            │  ⏻ 152px   │  power    │
│            │   disc     │  disc в   │
│            ╰────────────╯            │  mint tray 216px, кольцо
│         Статус: Отключено            │  подпись под диском
│                                      │
│  ┌──────────┐ ┌──────────┐           │
│  │ Туннель  │ │ Трафик   │           │  карточки-статистика 2 колонки
│  │ on/esc.  │ │ rx/tx    │           │  (Tunnel.Mode, Counters)
│  └──────────┘ └──────────┘           │
│                                      │
│   [Туннель] [Журнал] [Настройки]     │  floating bottom nav (3)
└──────────────────────────────────────┘
```

## 5. Онбординг-визард (первый запуск)

Условие показа: отсутствует валидный `configs/rupas.yaml` (config.Load ошибка/нет файла) или флаг `onboarded` в отдельном marker-файле `%LocalAppData%\rupas\onboarded`.

| Шаг | Экран | Действия backend | Условие продолжения |
|---|---|---|---|
| 1. Приветствие | логотип, краткое описание, «Начать» | — | кнопка |
| 2. Разрешения | объяснение: демон требует админку (WinDivert-driver), кнопка «Запустить сервис» | ShellExecute(rupas-gui, runas, -startdaemon) → waitForDaemon | pipe отвечает status |
|  elevation-UX: если UAC отклонён — экран «Без админки перехват невозможен» + retry |
| 3. VLESS | поле «Вставьте vless://-ссылку» + «или введите вручную» → uuid/host/port/sni/pbk/sid; кнопка «Проверить» (локальная валидация Endpoint.Validate) | parseVless (порт ParseVless.java), config write | валидный endpoint (или skip → режим desync-only, Tunnel.Configured()==false, warning-чип) |
| 4. GeoIP/GeoSite | «Скачиваю таблицы…» progress | RPC reload → демон качает geoip (мирроры ipdeny/ipverse) | rules.Compile OK (статус показывает профиль) |
| 5. Первый пробинг | «Изучаю ваш DPI…» прогресс-этапы | RPC on → демо-переходы OFF→PROBING→ACTIVE в status-поллинге | State==ACTIVE \|\| ACTIVE_TUNNEL_ONLY (успех) / DEGRADED (см. §7) |
| 6. Готово | «Всё работает» + кнопка «Открыть Rupas» | marker `onboarded=true` | кнопка → главная |

Пользователь ни на одном шаге не редактирует YAML и не запускает консоль.

## 5a. Парсер vless:// (D5)

Портирование ParseVless.java → `internal/guictrl/vless.go` (сигнатура Result идентична Android):

```go
type VlessLink struct {
    UUID, Server string; Port int
    SNI, PublicKey, ShortID string
    Fallback bool; Warning string
}
func ParseVlessLink(s string) (VlessLink, error) // "vless://" prefix, #label, ?pbk=&sid=&sni=&type=tcp/xhttp
```

Тесты: таблица ссылок из ParseVless.java-кейсов (валид, без pbk, xhttp, ws → warning «неподдерживаемый transport», пусто → ошибка).

## 5b. Дополнительно к онбордингу (v1.1+, не блокирует v1)
- Импорт базового пресета правил (github/yt/discord/tg-CIDR из rupas.example.yaml) — v1 кладёт дефолт из example при первом конфиге;
- WFP-конфликт детект (PRD §2) — показать warn на шаге 5, если prober видит глушение :53.

---

## 6. Экраны после онбординга

### 6.1 Главная
- Power disc (см. §4a), статус-текст = mapState(Snapshot).
- Тап по диску:
  - off→on: ensureDaemon → RPC `on` → UI connecting, пока не ACTIVE/ошибка;
  - on→off: RPC `off` (перехват стопается, процесс живёт).
- Карточки: Туннель (Mode+health+held), Трафик (Counters), Активные потоки (Flows).
- Подпись вердиктов не нужна: US-1 — «пользователь не настраивает ничего».

### 6.2 Журнал
- Поток событий: RPC `logs` (последние 200 строк) + подписка на новые (poll 1s при открытой вкладке; стриминг-события — v2).
- Кнопки (из tab_logs.xml): autoscroll-chip, уровень debug/info, share (копия в буфер / сохранение .txt).
- `-chlog` строки (CH sni= ech= verdict=) — под уровнем debug.

### 6.3 Настройки
Секции (из activity_settings/tab_settings.xml):
- **Туннель**: поля host/port/uuid/sni/pbk/sid + «Вставить vless://» (тот же парсер); маскирование uuid/pbk как в TUI.
- **Обход блокировок (DPI)**: desync-стратегии (DesyncStrategies()), fake TTL, переключатель DPI-fake (switchDpiFake).
- **Правила** (v1.1): список cidr/sni/ports + action-чипы desync/tunnel/pass — после того как правила уедут из YAML в UI-модель.
- Сохранение: config validate → .bak → атомарная запись → RPC reload → откат при отказе (SYSTEM_DESIGN §9, контракт как в TUI-редакторе). Оффлайн-демон: сохранить без reload.
- Кнопка «Сбросить до заводских» (конфиг → example-дефолт, requires confirm).

### 6.4 Трей (v1.1)
- Иконка: цвет по UIState; меню: Включить/Выключить/Статус/Выход; balloon при DEGRADED.

## 6.5 Не-цели v1
- Редактор правил в UI (v1.1), автозапуск при логине (v1.1), тёмная тема, мультипрофильность, сторы.
- Соавторинг конфига с TUI: одновременная правка из TUI и GUI не координируется v1 (файл один, reload контракт общий; конфликт = last-writer-wins по файлу).

## 7. Модель состояний кнопки (D7)

```
off --(tap)--> connecting --(ACTIVE*)--> on
                 |                         |
                 +--(DEGRADED)--> error    +--(tap)--> off
                 +--(timeout 60s)--> error
```

| Состояние ядра (core.Snapshot.State) | UIState | Диск | Подпись (ru) |
|---|---|---|---|
| OFF | off | ink-faint кольцо, disc paper | «Отключено» |
| PROBING | connecting | warn-кольцо, пульс | «Подключаюсь…» |
| ACTIVE / ACTIVE_TUNNEL_ONLY | on | accent-диск, accent-ink иконка | «Работает» / «Работает (только туннель)» |
| DEGRADED | error | danger-кольцо | «Сбой: <Note>» |

Подписи — допущение: финализируются на имплементации.

Таймауты: connecting→error 60 с без смены состояния; error → тап = повтор on (сначала probe).

## 8. Доступ и безопасность

- GUI не повышает собственных привилегий: команды — через pipe (DACL: interactive user может писать, SYSTEM тоже) — уже в коде.
- Elevation нужен только для spawn rupasd (один UAC-промпт на запуск демона; v1.1 — запуск демона через Task Scheduler с сохранённым согласием → ноль промптов).
- Секреты: uuid/password/pbk в Settings маскируются (кнопка-глаз, как ic_visibility на Android); в логах не печатаются (контракт ядра), GUI не пишет их в чарты/трей.
- vless://-ссылка содержит uuid — после парсинга из буфера удаляется (Clipboard.clear), как на Android.
- Ошибки elevation/UAC показываются экраном ошибки с retry (см. §5 шаг 2).

## 8a. Обновления и дистрибуция
- Single-файл `RupasSetup.exe` (Wails NSIS): кладёт rupas-gui.exe + rupasd.exe + WinDivert.dll/.sys + rupasctl.exe в Program Files, конфиг в ProgramData (v1.1).
- Обновление: manual download v1 (side-by-side с rupasctl TUI; GUI не зависит от TUI).

## 9. Метрики успеха v1
- Успешный онбординг «до ACTIVE» с нуля ≤ 3 минут, ≤ 2 UAC-промпта (допущение-цель: 1).
- Включение из трея/окна < 2 с от тапа до «Работает» (warm daemon).
- 0 аллокаций в hot path — не затрагивается: GUI не входит в пакетный путь.

## 10. Ответ на «быстро ли на Go?»
Да. Причины: (1) весь backend-слой — тонкая надстройка над готовыми швами (pipe-RPC, config.Load, supervisor-Snapshot, geoip уже в демоне); новый Go-код — парсер vless:// и daemonctl (~600 строк); (2) Wails v3.0.0 stable (2026-10-26) снимает риск «beta-фреймворка»; (3) HTML/CSS-тема переносится из Android 1:1 (CSS-переменные из colors.xml/dimens.xml); (4) ядро (capture/rules/tunnel) не трогаем вообще. Риски: WebView2-зависимость (на Win10/11 предустановлен — допущение, проверить на чистой VM), UAC-поток (v1.1 уходит в Task Scheduler).
Оценка: **MVP (wizard+home+logs) — 3–5 рабочих дней**, полный v1 (настройки+трей+инсталлер) — 8–10 дней. Допущение: один разработчик, знакомый с кодовой базой.
