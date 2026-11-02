// Package main is the Rupas desktop GUI (Wails v3, design doc: docs/GUI_DESIGN.md).
//
// Architecture (GUI_DESIGN D1/D2): the GUI is a separate non-elevated process;
// all decisions live in rupasd. The GUI renders core.Snapshot over the existing
// named-pipe RPC and sends on/off/probe/reload. The daemon is spawned detached
// (elevated via runas when needed) using the same mechanics as rupasctl start.
package main

import (
	"embed"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/wailsapp/wails/v3/pkg/application"
	"github.com/wailsapp/wails/v3/pkg/events"

	"github.com/kshishtovsky/rupas/internal/daemonlog"
	"github.com/kshishtovsky/rupas/internal/guictrl"
	"github.com/kshishtovsky/rupas/internal/version"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed icon.png
var trayIcon []byte

func main() {
	startDaemon := flag.Bool("startdaemon", false, "internal: elevated relaunch that spawns rupasd and exits")
	wipeProfile := flag.Bool("wipeprofile", false, "internal: elevated relaunch that deletes the calibration profile and exits")
	daemonPath := flag.String("daemon", "", "rupasd.exe path (with -startdaemon)")
	configPath := flag.String("config", "", "rupas YAML config path")
	logPath := flag.String("log", "", "daemon log path")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("rupas-gui %s\n", version.Version)
		return
	}

	if *wipeProfile {
		if err := guictrl.RunWipeProfileFlag(); err != nil {
			log.Fatalf("rupas-gui -wipeprofile: %v", err)
		}
		return
	}

	if *startDaemon {
		ctrl, err := guictrl.New(guictrl.Options{ConfigPath: *configPath, LogPath: *logPath})
		if err != nil {
			log.Fatal(err)
		}
		if err := ctrl.RunStartDaemonFlag(*daemonPath, *configPath, *logPath); err != nil {
			log.Fatalf("rupas-gui -startdaemon: %v", err)
		}
		return
	}

	// The binary is built with -H=windowsgui (no console): diagnostics go to
	// %LocalAppData%\rupas\gui.log instead of the void stderr.
	redirectLogs()

	ctrl, err := guictrl.New(guictrl.Options{ConfigPath: *configPath, LogPath: *logPath})
	if err != nil {
		log.Fatalf("rupas-gui: %v", err)
	}
	liveCtrl = ctrl
	// The HKCU Run entry is written once: keep it pointing at this binary so a
	// rebuild in a new path does not leave the login start on a deleted exe.
	if err := ctrl.RepairAutostart(); err != nil {
		log.Printf("autostart: %v", err)
	}

	app := application.New(application.Options{
		Name:        "Rupas",
		Description: "Rupas — обход DPI и туннель, одной кнопкой",
		Services: []application.Service{
			application.NewService(ctrl),
		},
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
		SingleInstance: &application.SingleInstanceOptions{
			UniqueID: "rupas-gui",
			OnSecondInstanceLaunch: func(application.SecondInstanceData) {
				if w := application.Get().Window.Current(); w != nil {
					w.Show()
					w.Focus()
				}
			},
		},
	})

	win := app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Rupas",
		Width:            420,
		Height:           740,
		MinWidth:         380,
		MinHeight:        620,
		Frameless:        true,                                    // custom caption buttons (frontend header)
		BackgroundColour: application.NewRGBA(247, 243, 236, 255), // paper #F7F3EC
		URL:              "/",
		// Камера нужна только для импорта конфига из QR (Settings →
		// «Перенос настроек»). Без явного разрешения WebView2 молча отклоняет
		// getUserMedia, и сканер выглядел бы сломанным.
		Permissions: map[application.PermissionType]application.Permission{
			application.PermissionCamera: application.PermissionAllow,
		},
	})

	// Window background only shows until the webview paints its first frame, and
	// that frame already comes from html[data-theme] (index.html sets it before
	// paint). So only the stored explicit dark mode is worth a second colour here;
	// mode -1 (system) keeps the light default, and a system-dark user may see one
	// light frame — resolving the OS mode in Go would cost a registry read plus
	// WM_SETTINGCHANGE tracking that Wails v3 does not expose.
	if ctrl.ThemeMode() == guictrl.ThemeDark {
		win.SetBackgroundColour(application.NewRGBA(18, 21, 20, 255)) // paper #121514 (values-night)
	}

	// Minimize-to-tray (GUI_DESIGN §6.4): the close (X) button hides the
	// window instead of quitting; real exit is the tray menu «Выход».
	// Hooks run synchronously BEFORE the internal WindowClosing listener
	// that destroys the window — Cancel() keeps the window alive.
	win.RegisterHook(events.Common.WindowClosing, func(e *application.WindowEvent) {
		if quitting {
			return // tray «Выход»: let the default close flow run
		}
		e.Cancel()
		win.Hide()
	})

	// System tray (GUI_DESIGN §6.4): toggle + show + quit.
	tray = app.SystemTray.New()
	tray.SetIcon(trayIcon)
	// Double-click on the tray icon reopens the hidden window (single click
	// stays inert so it does not fight the double-click: WM_LBUTTONUP has
	// no handler, only WM_LBUTTONDBLCLK does).
	tray.OnDoubleClick(func() {
		if w := application.Get().Window.Current(); w != nil {
			w.Show()
			w.Focus()
		}
	})
	tray.SetMenu(application.NewMenuFromItems(
		application.NewMenuItem("Включить").OnClick(func(*application.Context) { _ = toggle(true) }),
		application.NewMenuItem("Выключить").OnClick(func(*application.Context) { _ = toggle(false) }),
		application.NewMenuItemSeparator(),
		application.NewMenuItem("Показать окно").OnClick(func(*application.Context) {
			if w := app.Window.Current(); w != nil {
				w.Show()
				w.Focus()
			}
		}),
		application.NewMenuItem("Выход").OnClick(func(*application.Context) {
			quitting = true
			app.Quit()
		}),
	))

	// Snapshot stream: poller → Wails event → frontend (GUI_DESIGN §6.2),
	// mirrored into the tray label. Started once win and tray exist: the tray
	// is live even while the window is hidden, the webview is not — sending a
	// snapshot there only costs a JSON marshal through the bridge, so the last
	// one is parked and replayed by the show hook below.
	ctrl.StartPoller(func(s guictrl.Snapshot) {
		updateTrayLabel(s)
		if !win.IsVisible() {
			hiddenSnap.Store(&s)
			return
		}
		app.Event.Emit("rupas:snapshot", s)
	})
	// Common.WindowShow is not emitted on Windows (only Common.WindowClosing
	// has an explicit emit, webview_window.go:1257); the Windows WM_SHOWWINDOW
	// event is (webview_window_windows.go:1819), so that is the one hooked.
	win.RegisterHook(events.Windows.WindowShow, func(*application.WindowEvent) {
		if s := hiddenSnap.Swap(nil); s != nil {
			app.Event.Emit("rupas:snapshot", *s)
		}
	})

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// redirectLogs sends the default logger to %LocalAppData%\rupas\logs\gui.log
// (windowsgui builds have no stderr). Rotated: a GUI that runs for weeks must
// not grow one file without a bound.
func redirectLogs() {
	dir := os.Getenv("LocalAppData")
	if dir == "" {
		dir = os.TempDir()
	}
	w, err := daemonlog.New(filepath.Join(dir, "rupas", "logs", "gui.log"), 4<<20, 3)
	if err != nil {
		return
	}
	log.SetOutput(w)
}

// tray is the live system tray (label updated from the snapshot poller).
var tray *application.SystemTray

// quitting is set by the tray «Выход»: the WindowClosing hook lets the real
// close flow run instead of hiding to tray.
var quitting bool

// toggle turns interception on/off from the tray menu.
func toggle(on bool) error {
	if on {
		if err := liveCtrl.EnsureDaemon(); err != nil {
			return err
		}
		return liveCtrl.On()
	}
	return liveCtrl.Off()
}

// liveCtrl is the controller for tray callbacks.
var liveCtrl *guictrl.Controller

// hiddenSnap is the newest snapshot while the window sits in the tray: the
// poller skips the event there (nothing to paint) and stores it for the show
// hook to replay.
var hiddenSnap atomic.Pointer[guictrl.Snapshot]

// lastTrayLabel is the label currently on the tray icon: SetLabel is a Win32
// Shell_NotifyIcon(NIM_MODIFY) call and the string rarely changes.
var lastTrayLabel string

// trayLabel maps a snapshot to the tray caption (pure: testable without a tray).
func trayLabel(s guictrl.Snapshot) string {
	switch {
	case !s.Online:
		return "Rupas — демон не запущен"
	case s.State == "ACTIVE":
		return "Rupas — работает"
	case s.State == "ACTIVE_TUNNEL_ONLY":
		return "Rupas — работает (туннель)"
	case s.State == "PROBING":
		return "Rupas — пробинг…"
	case s.State == "DEGRADED":
		return "Rupas — сбой"
	default:
		return "Rupas — выключено"
	}
}

func updateTrayLabel(s guictrl.Snapshot) {
	if tray == nil {
		return
	}
	if l := trayLabel(s); l != lastTrayLabel {
		lastTrayLabel = l
		tray.SetLabel(l)
	}
}
