# R03 — GUI rupas: лаги, утечки опроса и лишние Win32-вызовы

**Severity:** Medium (CPU/батарея при свёрнутом окне, дубли опроса, лаги логов)
**Репозиторий:** `E:/rupas`
**Слой:** десктопный GUI (Wails v3): `cmd/rupas-gui/main.go`,
`cmd/rupas-gui/frontend/dist/app.js`, `internal/guictrl/controller.go`

## Зачем

GUI опрашивает демон раз в секунду (`internal/guictrl/controller.go:45`,
`runPoller:233-257`) и на **каждое** изменение снимка:

1. **пишет подпись трея.** `cmd/rupas-gui/main.go:206-225` →
   `tray.SetLabel(...)` — это Win32 `Shell_NotifyIcon(NIM_MODIFY)` раз в
   секунду, даже когда строка не изменилась (`RxRate`/`TxRate` меняются
   постоянно, поэтому «изменение» есть почти всегда);
2. **шлёт событие в webview.** `app.Event.Emit("rupas:snapshot", s)` — JSON
   через мост Go→JS раз в секунду, **в том числе когда окно свёрнуто в трей**
   и рисовать нечего (пользователь видит только трей).

Плюс два дефекта фронтенда:

3. **Утечка интервала логов.** `app.js:148`: `showPage("logs")` вызывает
   `setInterval(loadLogs, 2000)` без `clearInterval` предыдущего. Повторный
   вход на вкладку «Логи» (клик по уже активной кнопке навигации, клик по
   баннеру `alertMore` из того же раздела) плодит опросы: N кликов → N
   интервалов → N RPC каждые 2 с, каждый — новое подключение к named pipe
   (`internal/guictrl/rpcclient.go:16-21`).
4. **Перерисовка логов целиком.** `loadLogs` (`app.js:157-186`) каждые 2 с
   пересоздаёт до 800 DOM-узлов и **принудительно** прокручивает вниз
   (`box.scrollTop = box.scrollHeight`), из-за чего невозможно читать лог,
   если он обновляется.

## Что менять

### 1. Подпись трея — только при изменении

`cmd/rupas-gui/main.go`: вынести маппинг в чистую функцию и кэшировать
последнюю подпись.

```go
// trayLabel — подпись трея по снимку (чистая: тестируется без окна).
func trayLabel(s guictrl.Snapshot) string { /* switch из updateTrayLabel */ }

var lastTrayLabel string

func updateTrayLabel(s guictrl.Snapshot) {
	if tray == nil {
		return
	}
	if l := trayLabel(s); l != lastTrayLabel {
		lastTrayLabel = l
		tray.SetLabel(l)
	}
}
```

### 2. Не эмитить в скрытое окно

В `main.go` (обратный вызов `ctrl.StartPoller`):

```go
ctrl.StartPoller(func(s guictrl.Snapshot) {
	updateTrayLabel(s)
	if win != nil && !win.IsVisible() {
		hiddenSnap = s // всё равно держим свежий снимок
		return
	}
	app.Event.Emit("rupas:snapshot", s)
})
```
На показ окна — отдать накопленный снимок (`win.RegisterHook(events.Common.WindowShow, ...)`,
`hiddenSnap` под мьютексом или `atomic.Pointer`). `WebviewWindow.IsVisible()`
в Wails v3.0.0 есть (`webview_window.go:757`); **если нужного hook-события в
версии нет — не изобретать: эмитить раз в 5-й опрос, пока окно скрыто**
(флаг `tick`), и написать это в отчёте.

Трей при этом обновляется всегда — его видно и в свёрнутом состоянии.

### 3. Интервал логов — идемпотентный

`app.js:146-152`:

```js
function showPage(name) {
  ...
  clearInterval(logsTimer);            // до ветвления: любой переход гасит прошлый опрос
  logsTimer = null;
  if (name === "logs") { loadLogs(); logsTimer = setInterval(loadLogs, 2000); }
  ...
}
```

### 4. Логи — без перерисовки и без кражи прокрутки

```js
let logsSig = "";
async function loadLogs() {
  ...
  const tail = lines.slice(-800);
  const sig = lines.length + "|" + (tail[tail.length - 1] || "");
  const atBottom = box.scrollHeight - box.scrollTop - box.clientHeight < 24;
  if (sig === logsSig) return;         // ничего нового — не трогаем DOM
  logsSig = sig;
  // ... перестройка как сейчас ...
  if (atBottom) box.scrollTop = box.scrollHeight;
}
```
Сигнатура должна сбрасываться при переключении «Подробно»/«События».

### 5. Чипы телеметрии — без innerHTML на каждое обновление

`app.js:86-94`: `cardGateway`/`cardHealth` пересобираются через `innerHTML`
раз в секунду. Писать `textContent` в существующие узлы и менять только
`className` чипа; `innerHTML` — лишь когда структура реально меняется.

## Границы

Трогать можно: `cmd/rupas-gui/main.go`, `cmd/rupas-gui/bindings_test.go`
(+ новые тестовые файлы в `cmd/rupas-gui`), `cmd/rupas-gui/frontend/dist/app.js`.
Не трогать: `internal/guictrl/*` (кроме случая, когда правка невозможна без
него — тогда описать в отчёте), `internal/core/`, `frontend/dist/vendor/**`,
`frontend/dist/index.html`, `theme.css`.

## Критерии приёмки

1. `TestTrayLabel` (новый, `cmd/rupas-gui`): маппинг состояния → подпись для
   всех 6 веток (`!Online`, `ACTIVE`, `ACTIVE_TUNNEL_ONLY`, `PROBING`,
   `DEGRADED`, прочее).
2. `go build ./cmd/rupas-gui` и `go build -trimpath -ldflags "-H=windowsgui" -o build/rupas-gui.exe ./cmd/rupas-gui` — успешно.
3. `go test ./cmd/rupas-gui/ ./internal/guictrl/ -count=1` зелёные.
4. `node --check cmd/rupas-gui/frontend/dist/app.js` — синтаксис (module).
5. Ручной чек-лист (в отчёте, галочками): окно открывается; вкладка «Логи»
   обновляется; после 3 кликов по «Логи» в devtools виден **один** таймер
   (проверить `console.count` в `loadLogs`); при свёрнутом окне в трее подпись
   живая; при разворачивании цифры сразу актуальны.

## Риск

Низкий. Главное — не потерять обновление цифр после разворачивания окна
(для этого и нужен `hiddenSnap`) и не сломать автоскролл, когда пользователь
читает лог.
