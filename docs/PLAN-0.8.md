# План 0.8 — четыре потока работ

Декомпозиция под параллельных воркеров. Контракт §1 фиксируется **до** спавна: имена биндингов, JSON-формы и YAML-поля не выводятся воркерами из головы.

Базовые линии (сообщать каждому воркеру, чтобы он не «чинил» чужое):

- зелёное: `go build ./...`, `go test ./internal/guictrl/ ./internal/rules/ ./cmd/rupas-gui/`, `go test ./internal/...` кроме одного пакета;
- красное **известное**: `TestPipelineTunnelEscalationNoEndpoint` (`internal/app`, `tunnel_escalation_test.go:43`: `escalated rules = 6, want 4`) — не трогать;
- сборка GUI: `mingw32-make gui` (бинаря `make` на хосте нет); демон: `mingw32-make build` (теги `with_utls with_quic` в Makefile).

---

## 1. Контракт

### 1.1 Ядро: правило по процессу

```go
// internal/config/config.go, рядом с остальными матчерами Rule
App string `yaml:"app,omitempty" json:"app,omitempty"` // basename, lower-case: "steam.exe"
```

- Матчер `App` **взаимоисключающий** с `CIDR/GeoIP/SNI/Ports` (ровно один непустой) — добавить в `Validate`/`ValidateRules`.
- Значение нормализуется к lower-case, обязателен `.exe`-суффикс не требуется (Linux/Android-семантика не нужна, но валидация не должна падать на имени без точки).
- Стадия **первая** в резолвинге: `app → cidr/geoip → sni(exact → wildcard) → ports → default`. Обоснование: пользователь хочет «весь трафик этого процесса», а не «кроме тех его доменов, что попали в CIDR-правило».
- Неизвестный владелец сокета (`PID == 0`, UDP без записи в таблице) → правило не применяется, резолвинг идёт дальше. Fail-open, не fail-blocked.
- Не-Windows сборки: поле существует и валидируется, но не матчится (нет атрибуции). Android использует свой `Settings.AppRules` (package→action) — **не** переиспользовать.

API таблицы:

```go
// internal/rules/rules.go — MatchProto остаётся (совместимость), добавляется:
func (t *Table) MatchProc(ip [16]byte, sni string, port uint16, proto, app string) config.Action
// zero-alloc: app-правила лежат в map[string]config.Action, ключ — уже lower-case имя.
```

Вызовы в `internal/capture/engine.go`: `:763` (TCP CH-вердикт), `:1023` (UDP), `:1044` (`tgFastTunnel` — оставить без app, там нет PID в контексте).

### 1.2 Биндинги GUI (имена фиксированы)

| Метод | Сигнатура | Смысл |
|---|---|---|
| `CheckLinks` | `(blob string) ([]string, error)` | разбор + `config.Load` на temp без записи; вернуть warnings/ошибку |
| `RefreshGeoIP` | `() ([]string, error)` | форс-перекачка `build/geoip-*.txt` + hot-reload, построчный отчёт |
| `ThemeMode` | `() int` | `-1` системная, `0` светлая, `1` тёмная |
| `SetThemeMode` | `(mode int) error` | сохранить в `%LOCALAPPDATA%\rupas\theme.json` |

### 1.3 GUI: вид правила

`RuleView.Kind` получает значение `"app"` (`internal/guictrl/rules.go:30-36`); `Matcher` = `"steam.exe"`, `Human` = `"весь трафик процесса"`. `RulesView.StageCounts` расширяется `[3]int` → `[4]int` (стадия «Приложения» первой). Это ломает подпись в `app.js` — менять в том же коммите, что и фронт.

### 1.4 Тема

Режимы — как в Android (`SettingsStore.K_THEME`: `-1/0/1`). Токены: один блок `html[data-theme="dark"]` в `theme.css` с **теми же 29 именами**, значения — из `android/app/src/main/res/values-night/colors.xml` (там же комментарии с контрастом; `ink_faint` — только линии, не текст). `color-scheme: light dark` на `:root`/`[data-theme]`, чтобы нативные скроллбары и поля не светились.

**В Wails v3.0.0 нет API темы** — проверил `pkg/application`: есть только `WebviewWindow.SetBackgroundColour` (`webview_window.go:801`). Определение системной темы — `window.matchMedia('(prefers-color-scheme: dark)')` во фронте, Go не участвует. Воркеру не искать `SetTheme`/`SystemTheme` — их нет.

---

## 2. T1 — ядро: маршрутизация по процессу (Windows)

Владеет файлами (никто больше их не трогает):

```
internal/config/config.go            (+поле App, Validate)
internal/config/rules_json.go        (+поле App в ValidateRules-путь; Validate правит матчер-подмножество)
internal/rules/rules.go              (+MatchProc, app-таблица)
internal/rules/compile.go            (+case r.App, порядок стадий)
internal/rules/proc_test.go          (НОВЫЙ: приоритет стадий)
internal/capture/procinfo_windows.go (НОВЫЙ: атрибуция)
internal/capture/procinfo_other.go   (НОВЫЙ: заглушка, всегда "")
internal/capture/engine.go           (:763, :1023)
internal/capture/procinfo_windows_test.go (НОВЫЙ)
```

Атрибуция (проверено на этом хосте одноразовым зондом):

- `GetExtendedTcpTable(TCP_TABLE_OWNER_PID_ALL, AF_INET)` — снапшот 216 строк = **0.50 мс p50/p90/max**, поиск локального порта в снапшоте — мкс. Нужна и `GetExtendedUdpTable` (UDP_TABLE_OWNER_PID).
- Кэш: снапшот на **100 мс** (общий, не на поток), `PID → basename` — `QueryFullProcessImageNameW`, кэш по PID до 5 с (переиспользование PID редко, но не вечно).
- Стоимость при шторме: 128 dial/s × 10 снапшотов/с не бывает — при 100 мс снапшот берётся 10 раз/с = **5 мс/с = 0.5 % одного ядра**, lookup на поток ≈ 100 нс. В путь пакета ничего не добавляется.
- `syscall.SysProcAttr{HideWindow:true}` не нужен (нет exec), но `windows.NewLazySystemDLL("iphlpapi.dll")` + `unsafe` — как в зонде.
- Fail-open во всех ветках: нет записи → `""` → правило не сработало.

Гейты:

```
go build ./... && go vet ./internal/rules/ ./internal/capture/ ./internal/config/
go test ./internal/rules/ ./internal/config/ ./internal/capture/ -count=1
go test -tags "with_utls with_quic" ./internal/... -count=1        # теги обязательны
GOOS=android GOARCH=arm64 go build -tags "with_utls with_quic" ./internal/config ./internal/rules ./internal/capture   # портабельность
```

Обязательно доказать на живом демоне, а не только тестами: правило `app: steam.exe → direct` при `default: tunnel` и `status`/chlog, где поток этого процесса идёт DIRECT, а соседний — TUNNEL. Методика в скилле `rupas` («Проверка правки на живом демоне»).

Риски, которые принять и записать в коммент: UDP-сокет иногда без владельца в таблице (откат на общую политику); поток, поднятый до старта демона, атрибутируется только со следующего снапшота; `System`/`svchost` не отличить по имени — документировать как ограничение.

---

## 3. T2 — GUI: тёмная тема (системная + переключатель)

```
cmd/rupas-gui/frontend/dist/theme.css    (+блок dark, +color-scheme)
cmd/rupas-gui/frontend/dist/index.html   (+кнопка темы в шапке рядом с ⚙, aria-label)
cmd/rupas-gui/frontend/dist/app.js       (+themeApply/themeCycle/тема в loadSettings)
internal/guictrl/theme_windows.go        (НОВЫЙ: theme.json, ThemeMode/SetThemeMode)
cmd/rupas-gui/main.go                    (фон окна под тему: SetBackgroundColour до Show)
```

- Порядок применения: `index.html` содержит инлайн-скрипт, читающий тему из `localStorage` **до** первой отрисовки, иначе будет вспышка светлого (тема хранится в файле, но для первой миллисекунды дублируется в localStorage; файл — источник истины).
- Три состояния по кругу: системная → светлая → тёмная (как `MainActivity.java:220-230`).
- Слушатель `matchMedia('(prefers-color-scheme: dark)').addEventListener('change')` действует только в режиме «системная».
- Контраст: проверить таблицу как в Android (`values-night/colors.xml` содержит готовые коэффициенты); `ink_faint` в тёмной — 3.66:1, только линии/декор.
- Захардкоженных цветов быть не должно: `grep -nE "#[0-9A-Fa-f]{3,6}" app.js index.html` вне блока токенов → ноль.

Гейты: `mingw32-make gui`, затем живая проверка — переключить все три режима, перезапустить GUI (тема восстановилась), переключить системную тему при открытом окне (окно перекрасилось), скриншот каждой вкладки в тёмной.

---

## 4. T3 — GUI: каналы (удаление + проверка конфига)

```
cmd/rupas-gui/frontend/dist/app.js       (renderChannels: кнопка ✕; кнопка «Проверить»)
cmd/rupas-gui/frontend/dist/index.html   (+#btnLinksCheck рядом с «Разобрать»)
internal/guictrl/service.go              (+CheckLinks; SaveLinks не трогать)
internal/guictrl/service_windows_test.go (+тест CheckLinks на валидном/битом blob)
```

- Удаление идёт **через textarea**: `channels.splice(i,1)`, перерисовать список, `$("setLinks").value = ...` — запись на диск по-прежнему только по «Сохранить» (`SaveLinks`). Никакого нового пути сохранения не заводить.
- `CheckLinks` = `channelsToPlan` → `presetConfig(true)` + тунели → `config.Load` на **временном** файле (ровно то, что `writeConfig` делает первым шагом, но без `.bak`, без записи и без RPC). Возвращать: список предупреждений парсера + текст ошибки движка.
- Пустой blob → кнопка «Проверить» не ошибка: сообщение «нет ссылок».

Гейты: `go test ./internal/guictrl/ -count=1` + живая проверка (битая ссылка → внятная ошибка, рабочая → «ок, 2 канала»).

---

## 5. T4 — GUI: маршруты (`+` в шапке, GeoIP, стадия «Приложения»)

```
cmd/rupas-gui/frontend/dist/index.html  (кнопка + в .rt-head; стадия приложений; кнопка GeoIP)
cmd/rupas-gui/frontend/dist/app.js      (RT_STAGES: новая стадия 0; RT_KINDS: {key:"app"}; редактор: пикер процессов)
internal/guictrl/rules.go               (KindApp, StageCounts[4], buildRulesView, SaveRules)
internal/guictrl/geoip.go               (НОВЫЙ: RefreshGeoIP)
internal/geoip/geoip.go                 (+Refresh(p, cc) — форс-перекачка одного cc)
docs/ROUTING_UI.md                      (§4: 4 стадии, порядок резолвинга)
```

- `+` в шапке = `rtOpenEditor(0, null)` (тот же обработчик, что `data-rt="add"`), кнопка внутри стадий остаётся.
- Стадия «Приложения» **первая**, drag между стадиями запрещён (инвариант `ROUTING_UI §4`).
- Ввод: пикер из запущенных процессов (серверная часть — `Controller.ListProcesses() []ProcView{Name, PID, Path}` на `EnumProcesses`+`QueryFullProcessImageNameW`) **и** свободный ввод имени. Ввод без `.exe` дополняется при сохранении только если процесс с таким именем существует; иначе warning, не error.
- GeoIP: `RefreshGeoIP` удаляет `build/geoip-<cc>.txt` для cc, встречающихся в правилах, вызывает `geoip.Refresh`, затем `ReloadConfig`. Долго (до 2 × 30 с на зеркало) → кнопка в состоянии «Обновляю…» с `disabled`, по завершении — построчный отчёт (cc → N префиксов / ошибка). Не делать синхронным вызовом в обработчике клика без спиннера.

Гейты: `go test ./internal/guictrl/ ./internal/geoip/ -count=1`; живая проверка с сетью (обновление ru, отчёт, `reload` без разрыва).

---

## 6. Порядок и параллельность

```
волна 1 (параллельно, файлы не пересекаются):
  T1 ядро        internal/{config,rules,capture}
  T2 тема        dist/theme.css, dist/index.html*, internal/guictrl/theme_windows.go, main.go
  T3 каналы      dist/app.js*, internal/guictrl/service.go
волна 2 (после T1 — нужен контракт вида правила):
  T4 маршруты    dist/index.html*, dist/app.js*, internal/guictrl/rules.go, internal/geoip
```

`index.html` и `app.js` нужны и T2, и T3 — это единственное пересечение волны 1. Развести: T2 берёт `theme.css` + шапку/только свои узлы `index.html`, T3 — секцию «Каналы». Если правки в одном файле неизбежно накладываются, T3 отдаётся после T2 (полчаса разницы), либо T2/T3 делаются одним воркером. Не запускать двух воркеров, собирающих `./gradlew`/GUI одновременно.

---

## 7. Бэклог «что ещё» (после 0.8, с обоснованием цифрами)

| Идея | Слой | Почему стоит | Цена |
|---|---|---|---|
| Мультиплексирование носителя (mux) | ядро | в `tcpterm` один TLS на поток; главный резерв задержки и CPU (см. `PERF_AUDIT_ANDROID.md`) | 3–5 дней, риск для стабильности канала |
| Health-маркер 30 с без keep-alive | ядро | 2880 полных handshake/сутки вхолостую; сделать адаптивным (30 с → 5 мин в покое) | 0.5 дня |
| `gcTick = time.Second` | ядро | 86 400 пробуждений/сутки (`capture/engine.go`) | 0.5 дня |
| Профили VPN в десктопе | GUI | ветки `feat/vpn-profiles`, `feat/profiles-ui` уже пишут это для Android — паритет | 2 дня |
| Экспорт/импорт правил (JSON) | GUI | перенос политики между ПК и телефоном | 0.5 дня |
| Архив логов в файл из GUI | GUI | сейчас только буфер на экране | 0.5 дня |

Стоп-лист: не добавлять новых зависимостей, не вводить второй способ сохранения конфига, не трогать `default: TUNNEL` в пресетах (утечка реального IP — инвариант владельца).

---

## 8. Гигиена перед спавном

- Worktree `E:/rupas-wt/{theme,profiles,profiles-ui}` — **имена врут**: под `feat/theme-toggle` лежит adblock (`c6209f0`), тёмной темы там нет. Проверять содержимое, а не имя ветки; каталоги занимают место на E: (по ~500 МБ с сборками) — снести после решения по профилям.
- `git add -A` запрещён (в дереве живёт незакоммиченный WIP по десктопу). Файлы перечислять поимённо; `dist/` не в `.gitignore` только потому, что файлы уже отслеживаются.
- Секреты из `internal/transport/android/*_test.go` не копировать в новые файлы.
- Любая правка GUI обязана доехать до `master`: апдейтер затирает локальные сборки релизом (проверено 29.10 — фикс в ветке «исчез» после автообновления).
