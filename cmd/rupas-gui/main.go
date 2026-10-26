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

	app := application.New(application.Options{
		Name:        "Rupas",
		Description: "Rupas — обход DPI и туннель, одной кнопкой",
		Services: []application.Service{
			application.NewService(ctrl),
		},
		Assets: application.AssetOptions{
			Handler: application.BundledAssetFileServer(assets),
		},
	})

	// Snapshot stream: poller → Wails event → frontend (GUI_DESIGN §6.2).
	ctrl.StartPoller(func(s guictrl.Snapshot) {
		app.Event.Emit("rupas:snapshot", s)
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

	if err := app.Run(); err != nil {
		log.Fatal(err)
	}
}
