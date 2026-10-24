// Command rupasd is the Rupas daemon: it owns the supervisor state
// machine (§8), the capture/tunnel pipeline lifecycle and the RPC control
// pipe (§9). In this milestone Pipeline/Prober are STUBS with explicit
// log markers — the real capture/prober/tunnel implementations plug into
// the same supervisor.Pipeline / supervisor.Prober seams.
package main

import (
	"context"
	"flag"
	"log"
	"os"
	"os/signal"
	"sync/atomic"
	"time"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/rpc"
	"github.com/rupas/rupas/internal/supervisor"
)

func main() {
	configPath := flag.String("config", "", "path to the rupas YAML config (default: ./config.yaml, falling back to the built-in profile)")
	pipePath := flag.String("pipe", rpc.DefaultPipe, "control named pipe path")
	verbose := flag.Bool("verbose", false, "chatty debug logging on stderr")
	flag.Parse()

	logger := log.New(os.Stderr, "rupasd ", log.LstdFlags|log.Lmicroseconds)

	cfg, err := loadConfig(*configPath, logger)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	evlog := supervisor.NewEventLog(100)
	sup := supervisor.New(supervisor.Deps{
		Pipeline: &stubPipeline{log: logger, verbose: *verbose},
		Prober:   &stubProber{log: logger, verbose: *verbose},
		Config:   cfg,
		Logger:   logger,
		EventLog: evlog,
	})

	// Ctrl+C / service stop → graceful shutdown (stop pipeline, cancel
	// probes, disarm timers, close the pipe listener).
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	if err := sup.Start(ctx); err != nil {
		logger.Fatalf("supervisor: %v", err)
	}

	srv := rpc.New(*pipePath, rpc.Deps{
		Status: sup.Snapshot,
		On:     sup.On,
		Off:    sup.Off,
		Probe:  sup.ForceProbe,
		Reload: func() error {
			c, err := loadConfig(*configPath, logger)
			if err != nil {
				return err
			}
			return sup.Reload(c)
		},
		Logs:   evlog.Last,
		Logger: logger,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	logger.Printf("rupasd up: pipe=%s profile=%s (pipeline/prober are stubs until capture integration)", *pipePath, cfg.Profile)
	evlog.Append("daemon started (profile " + cfg.Profile + ")")

	select {
	case <-ctx.Done():
		logger.Printf("shutdown signal received")
	case err := <-errCh:
		if err != nil {
			logger.Printf("rpc server failed: %v", err)
		}
	}

	srv.Close()
	if err := sup.Close(); err != nil {
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

// stubPipeline is a placeholder supervisor.Pipeline until the
// capture/tunnel integration lands. It logs loudly so a stub run is never
// mistaken for a real interception.
type stubPipeline struct {
	log     *log.Logger
	verbose bool
	runs    atomic.Int64
}

func (p *stubPipeline) Start(cfg *config.Config) error {
	n := p.runs.Add(1)
	p.log.Printf("STUB pipeline: Start #%d (profile=%s) — no packets are intercepted; real capture/tunnel engine not integrated yet", n, cfg.Profile)
	return nil
}

func (p *stubPipeline) Stop() error {
	p.log.Printf("STUB pipeline: Stop")
	return nil
}

// stubProber is a placeholder supervisor.Prober returning an optimistic
// classification so the state machine can be exercised end-to-end.
type stubProber struct {
	log     *log.Logger
	verbose bool
	calls   atomic.Int64
}

func (p *stubProber) Run(ctx context.Context) (supervisor.ProfileResult, error) {
	n := p.calls.Add(1)
	select {
	case <-time.After(20 * time.Millisecond):
	case <-ctx.Done():
		return supervisor.ProfileResult{}, ctx.Err()
	}
	p.log.Printf("STUB prober: Run #%d → assumed OPEN, desync alive (real probe engine not integrated yet)", n)
	return supervisor.ProfileResult{
		ProfileID:   "stub-profile",
		DesyncAlive: true,
		TunnelOK:    true,
		Note:        "stub: assumed open / desync alive",
	}, nil
}
