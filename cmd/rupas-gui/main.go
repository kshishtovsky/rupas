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
	"log"

	"github.com/wailsapp/wails/v3/pkg/application"

	"github.com/rupas/rupas/internal/guictrl"
)

//go:embed all:frontend/dist
var assets embed.FS

//go:embed icon.png
var trayIcon []byte

func main() {
	startDaemon := flag.Bool("startdaemon", false, "internal: elevated relaunch that spawns rupasd and exits")
	daemonPath := flag.String("daemon", "", "rupasd.exe path (with -startdaemon)")
	configPath := flag.String("config", "", "rupas YAML config path")
	logPath := flag.String("log", "", "daemon log path")
	flag.Parse()

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

	ctrl, err := guictrl.New(guictrl.Options{ConfigPath: *configPath, LogPath: *logPath})
	if err != nil {
		log.Fatalf("rupas-gui: %v", err)
	}
	liveCtrl = ctrl

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

	// Snapshot stream: poller → Wails event → frontend (GUI_DESIGN §6.2),
	// mirrored into the tray label.
	ctrl.StartPoller(func(s guictrl.Snapshot) {
		app.Event.Emit("rupas:snapshot", s)
		updateTrayLabel(s)
	})

	app.Window.NewWithOptions(application.WebviewWindowOptions{
		Title:            "Rupas",
		Width:            420,
		Height:           740,
		MinWidth:         380,
		MinHeight:        620,
		BackgroundColour: application.NewRGBA(247, 243, 236, 255), // paper #F7F3EC
		URL:              "/",
	})

	// System tray (GUI_DESIGN §6.4): toggle + show + quit.
	tray = app.SystemTray.New()
	tray.SetIcon(trayIcon)
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
		application.NewMenuItem("Выход").OnClick(func(*application.Context) { app.Quit() }),
	))
	tray.Run()

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}

// tray is the live system tray (label updated from the snapshot poller).
var tray *application.SystemTray

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

func updateTrayLabel(s guictrl.Snapshot) {
	if tray == nil {
		return
	}
	switch {
	case !s.Online:
		tray.SetLabel("Rupas — демон не запущен")
	case s.State == "ACTIVE":
		tray.SetLabel("Rupas — работает")
	case s.State == "ACTIVE_TUNNEL_ONLY":
		tray.SetLabel("Rupas — работает (туннель)")
	case s.State == "PROBING":
		tray.SetLabel("Rupas — пробинг…")
	case s.State == "DEGRADED":
		tray.SetLabel("Rupas — сбой")
	default:
		tray.SetLabel("Rupas — выключено")
	}
}
