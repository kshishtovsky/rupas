// Command rupasd is the Rupas daemon. internal/app assembles the capture
// pipeline (capture.Engine), the probe engine (prober.Classifier +
// CalibrateTTL with the WinDivert fake injector) and the supervisor
// state machine; rupasd itself only parses flags, serves the RPC control
// pipe (§9) and manages shutdown.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"

	"github.com/rupas/rupas/internal/app"
	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/rpc"
)

func main() {
	configPath := flag.String("config", "", "path to the rupas YAML config (default: ./config.yaml, falling back to the built-in profile)")
	pipePath := flag.String("pipe", rpc.DefaultPipe, "control named pipe path")
	tunnel := flag.String("tunnel", "on", "tunnel branch: on = NAT-redirect TUNNEL-rule flows (TG CIDRs, UDP relay, ECH) to the loopback tproxy — a stub logger until the tunnel core lands in wave 4; off = demote TUNNEL rules to direct, no NAT")
	verbose := flag.Bool("verbose", false, "chatty logging on stderr")
	flag.Parse()

	var tunnelOn bool
	switch *tunnel {
	case "on":
		tunnelOn = true
	case "off":
		tunnelOn = false
	default:
		fmt.Fprintf(os.Stderr, "rupasd: invalid -tunnel %q (want on|off)\n", *tunnel)
		os.Exit(2)
	}

	logger := log.New(os.Stderr, "rupasd ", log.LstdFlags|log.Lmicroseconds)
	if *verbose {
		logger.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	}

	cfg, err := loadConfig(*configPath, logger)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	// The battle pipeline: supervisor drives capture.Engine through
	// app's Pipeline; probes classify the path and re-profile desync.
	application, err := app.New(cfg, logger, app.Options{
		Tunnel: tunnelOn,
	})
	if err != nil {
		logger.Fatalf("app: %v", err)
	}

	// Ctrl+C / service stop → graceful shutdown (stop pipeline, cancel
	// probes, disarm timers, close the pipe listener).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := application.Start(ctx); err != nil {
		logger.Fatalf("supervisor: %v", err)
	}
	sup := application.Supervisor()

	srv := rpc.New(*pipePath, rpc.Deps{
		Status: application.Snapshot,
		On:     sup.On,
		Off:    sup.Off,
		Probe:  sup.ForceProbe,
		Reload: func() error {
			c, err := loadConfig(*configPath, logger)
			if err != nil {
				return err
			}
			if err := application.SetConfig(c); err != nil {
				return err
			}
			return sup.Reload(c)
		},
		Logs:   application.EventLog().Last,
		Logger: logger,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	tunnelNote := "on: NAT-redirect to the stub tproxy logger (tunnel core comes in wave 4)"
	if !tunnelOn {
		tunnelNote = "off: TUNNEL rules demoted to direct"
	}
	logger.Printf("rupasd up: pipe=%s profile=%s tunnel=%s", *pipePath, cfg.Profile, tunnelNote)
	application.EventLog().Append("daemon started (profile " + cfg.Profile + ", tunnel " + *tunnel + ")")

	select {
	case <-ctx.Done():
		logger.Printf("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			logger.Printf("rpc server failed: %v", err)
		}
	}

	srv.Close()
	if err := application.Close(); err != nil {
		logger.Printf("supervisor close: %v", err)
	}
	logger.Printf("rupasd stopped")
}

// loadConfig resolves the effective config: an explicit -config path must
// load; the default path falls back to the built-in profile with a
// warning when the file is absent.
func loadConfig(path string, logger *log.Logger) (*config.Config, error) {
	if path == "" {
		path = "config.yaml"
		if _, err := os.Stat(path); err != nil {
			logger.Printf("no %s found, using the built-in default profile", path)
			return config.Default(), nil
		}
	}
	return config.Load(path)
}
