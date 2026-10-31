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
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"

	"github.com/kshishtovsky/rupas/internal/app"
	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/daemonlog"
	"github.com/kshishtovsky/rupas/internal/rpc"
	"github.com/kshishtovsky/rupas/internal/version"
)

// acquireSingleInstanceLock refuses to start a second rupasd on the same
// machine: two daemons share one WinDivert stack and one control pipe
// (named pipes allow unlimited instances), splitting commands/statuses at
// random and fighting over interception - a live field incident.
const singleInstanceMutex = "Global\\rupasd-single"

var kernel32SI = syscall.NewLazyDLL("kernel32.dll")

func acquireSingleInstanceLock(name string) bool {
	p, _ := syscall.UTF16PtrFromString(name)
	r1, _, err := kernel32SI.NewProc("CreateMutexW").Call(0, 1, uintptr(unsafe.Pointer(p)))
	if r1 == 0 {
		return false
	}
	// Proc.Call's err is the thread's last-error value; for an existing mutex
	// it is ERROR_ALREADY_EXISTS (GetLastError() is unreliable after Call).
	if err == syscall.ERROR_ALREADY_EXISTS {
		syscall.CloseHandle(syscall.Handle(r1))
		return false
	}
	return true
}

func main() {
	configPath := flag.String("config", "", "path to the rupas YAML config (default: ./config.yaml, falling back to the built-in profile)")
	pipePath := flag.String("pipe", rpc.DefaultPipe, "control named pipe path")
	tunnel := flag.String("tunnel", "on", "tunnel branch: on = NAT-redirect TUNNEL-rule flows (TG CIDRs, UDP relay, ECH) to the loopback tproxy and relay them through the configured VLESS+Reality endpoint (empty endpoint: TUNNEL rules escalate to sni→desync / cidr,port→direct, logged and counted); off = demote TUNNEL rules to direct, no NAT")
	verbose := flag.Bool("verbose", false, "chatty logging on stderr (adds file:line)")
	debug := flag.Bool("debug", true, "detailed logging: DEBUG level for the tunnel (flow gates, carrier dials, marker probes); -debug=false keeps warnings only")
	logPath := flag.String("log", "", "log file with size rotation (default: %LOCALAPPDATA%\\rupas\\logs\\rupasd.log; empty string disables the file)")
	chlog := flag.Bool("chlog", true, "log every ClientHello decision (sni/ech/dst/verdict) — TSPU-shape diagnostics; TEMPORARY verbose mode, default ON for the debugging phase (pass -chlog=false to silence the hot path)")
	showVersion := flag.Bool("version", false, "print version and exit")
	flag.Parse()

	if *showVersion {
		fmt.Printf("rupasd %s\n", version.Version)
		return
	}

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
	if !acquireSingleInstanceLock(singleInstanceMutex) {
		logger.Printf("another rupasd instance is already running; exiting - stop it first (rupasctl off, then close the old daemon)")
		os.Exit(3)
	}
	if *verbose {
		logger.SetFlags(log.LstdFlags | log.Lmicroseconds | log.Lshortfile)
	}

	// Detailed logging is the default: a live incident cannot be diagnosed
	// after the fact from warnings alone. RUPAS_LOG_DEBUG is the env knob the
	// tunnel reads; set it before app.New builds the slog bridge.
	if *debug {
		os.Setenv("RUPAS_LOG_DEBUG", "1")
	}
	// The file sink outlives the console: the GUI is windowsgui and has no
	// stderr, so without it everything below Warning is lost. When the file
	// is open it REPLACES stderr in the logger — the GUI redirects our stderr
	// into the same file, and MultiWriter would double every line.
	if f := openLogFile(*logPath, logger); f != nil {
		defer f.Close()
		logger.SetOutput(f)
	}

	cfg, err := loadConfig(*configPath, logger)
	if err != nil {
		logger.Fatalf("config: %v", err)
	}

	// The battle pipeline: supervisor drives capture.Engine through
	// app's Pipeline; probes classify the path and re-profile desync.
	application, err := app.New(cfg, logger, app.Options{
		Tunnel: tunnelOn,
		ChLog:  *chlog,
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
		// Elevated-restart path: the GUI re-spawns rupasd via UAC, so this
		// instance must be gone — single-instance lock is held by this
		// process and dies with it.
		Shutdown: func() error {
			_ = sup.Off()
			logger.Printf("shutdown requested (elevated restart)")
			os.Exit(0)
			return nil
		},
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
		// Routing screen commands (rules / rules-set / route-test) work off
		// the same YAML the daemon runs with; rules-set rewrites it
		// atomically and hot-applies through the reload path above.
		ConfigPath: *configPath,
	})

	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe(ctx) }()

	plan := cfg.TunnelPlan()
	tunnelNote := "on: NAT-redirect to the loopback tproxy → configured endpoints"
	if !tunnelOn {
		tunnelNote = "off: TUNNEL rules demoted to direct"
	} else if !plan.Configured() {
		tunnelNote = "on: no endpoint configured — TUNNEL rules escalated (sni→desync, cidr/port→direct)"
	} else {
		var parts []string
		for _, e := range []*config.Endpoint{plan.TCP, plan.UDP, plan.Fallback} {
			if e == nil {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s@%s:%d", e.Kind, e.Host, e.Port))
		}
		tunnelNote = "on: " + strings.Join(parts, " → ")
	}
	logger.Printf("rupasd up: pipe=%s profile=%s tunnel=%s", *pipePath, cfg.Profile, tunnelNote)
	// Which rule set is actually live, and what it does to unmatched traffic.
	// Diagnostics only: the GUI onboarding path once left a 13-rule config with
	// `default: direct` in place while the owner believed his 51-rule policy
	// was running — every unmatched destination then egressed with the real IP.
	logger.Printf("rupasd rules: config=%s rules=%d default=%s",
		absConfigPath(*configPath), len(cfg.Rules), defaultAction(cfg).String())
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

// openLogFile opens the rotating daemon log. An empty explicit path ("-log=")
// disables the file; a default path that cannot be created is reported but
// never fatal — logging must not keep the daemon from starting.
func openLogFile(explicit string, logger *log.Logger) *daemonlog.Writer {
	path := explicit
	if path == "" {
		dir := os.Getenv("LocalAppData")
		if dir == "" {
			dir = os.TempDir()
		}
		path = filepath.Join(dir, "rupas", "logs", "rupasd.log")
		if explicit == "" && flagWasSet("log") {
			return nil // "-log=" disables the file sink
		}
	}
	w, err := daemonlog.New(path, 10<<20, 5)
	if err != nil {
		logger.Printf("log file %s: %v (continuing with stderr only)", path, err)
		return nil
	}
	logger.Printf("rupasd log: %s (10 MiB x 5, rotated)", path)
	return w
}

// flagWasSet reports whether the named flag was given on the command line:
// an explicit empty -log= must mean "no file", while an absent -log means
// "default path".
func flagWasSet(name string) bool {
	set := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			set = true
		}
	})
	return set
}

// loadConfig resolves the effective config: an explicit -config path must
// load; the default path falls back to the built-in profile with a
// warning when the file is absent.
//
// A missing EXPLICIT path also falls back, loudly: the GUI always passes
// %ProgramData%\Rupas\rupas.yaml, which does not exist on a fresh install
// until the onboarding wizard saves — dying here left the GUI with
// «демон не отвечает» and zero diagnostics (v0.10.3 regression report).
// The built-in default profile is the honest state: daemon up, pipe live,
// config pending.
func loadConfig(path string, logger *log.Logger) (*config.Config, error) {
	if path == "" {
		path = "config.yaml"
		if _, err := os.Stat(path); err != nil {
			logger.Printf("no %s found, using the built-in default profile", path)
			return config.Default(), nil
		}
	}
	if _, err := os.Stat(path); err != nil {
		logger.Printf("config %s: %v — using the built-in default profile (save settings in the GUI to write it)", path, err)
		return config.Default(), nil
	}
	return config.Load(path)
}

// absConfigPath resolves the config path for the startup diagnostic (a bare
// relative name is useless in a log when the daemon's working directory is
// not obvious — the live daemon once ran with -config pointing at a deleted
// directory and nobody noticed).
func absConfigPath(path string) string {
	if path == "" {
		return "(built-in default profile)"
	}
	if abs, err := filepath.Abs(path); err == nil {
		return abs
	}
	return path
}

// defaultAction reports what the rule set does to a destination no rule
// matches: the last matcher-less rule wins, DIRECT when there is none.
func defaultAction(cfg *config.Config) config.Action {
	for i := len(cfg.Rules) - 1; i >= 0; i-- {
		r := cfg.Rules[i]
		if r.CIDR == "" && r.SNI == "" && r.Ports == "" && r.GeoIP == "" {
			return r.Action
		}
	}
	return config.ActionDirect
}
