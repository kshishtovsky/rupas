// Package guictrl is the GUI-side control plane (docs/GUI_DESIGN.md §3):
// daemon lifecycle (spawn/wait), pipe RPC client, vless:// link parsing,
// config writing and the snapshot poller that feeds Wails events.
//
// The GUI owns no routing decisions: every verdict comes from rupasd via
// core.Snapshot over the control pipe.
package guictrl

import (
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/rupas/internal/core"
	"github.com/kshishtovsky/rupas/internal/rpc"
)

// Options configures Controller. Zero value is usable for tests.
type Options struct {
	// Pipe is the control pipe path (default rpc.DefaultPipe).
	Pipe string
	// DaemonPath overrides rupasd.exe discovery (tests).
	DaemonPath string
	// ConfigPath is the rupas YAML config the daemon runs with.
	ConfigPath string
	// LogPath is where the daemon stderr/stdout is appended.
	LogPath string
	// PollInterval is the status poll period (default 1s).
	PollInterval time.Duration
	// Logger receives diagnostics (default log.Printf).
	Logger *log.Logger
}

func (o Options) withDefaults() Options {
	if o.Pipe == "" {
		o.Pipe = rpc.DefaultPipe
	}
	if o.PollInterval <= 0 {
		o.PollInterval = time.Second
	}
	if o.Logger == nil {
		o.Logger = log.Default()
	}
	return o
}

// Controller is the Wails-bound service. All exported methods are callable
// from the frontend; struct fields are construction-time only.
type Controller struct {
	opts Options
	log  *log.Logger

	mu       sync.Mutex
	stopPoll chan struct{}

	// last is the last poll result (nil until the first answer).
	last *Snapshot
	// prev is the previous poll sample for rate computation.
	prev ratePrev
	// gatewayHost is the primary channel description (Home «Шлюз» line).
	gatewayHost string
	// elevRestartOnce guards the automatic WinDivert elevated restart: one
	// attempt per GUI session (0 = not tried, 1 = in progress/succeeded).
	elevRestartOnce atomic.Bool
	// listeners are notified on every snapshot change.
	listeners map[int]func(Snapshot)
	nextHook  int
}

// ErrDaemonDown is returned when the control pipe does not answer and the
// daemon could not be started.
var ErrDaemonDown = errors.New("демон rupasd не отвечает")

// New builds a Controller (no side effects; the daemon is started lazily by
// EnsureDaemon or by the wizard's step 2).
func New(opts Options) (*Controller, error) {
	opts = opts.withDefaults()
	return &Controller{
		opts:      opts,
		log:       opts.Logger,
		listeners: map[int]func(Snapshot){},
	}, nil
}

// Snapshot is the JSON shape sent to the frontend: the daemon status plus
// daemon-online flag, derived telemetry (Android W3 home parity: session,
// speeds, health) and the gateway line. It mirrors core.Snapshot but stays a
// separate type so the GUI never couples to core's internals.
type Snapshot struct {
	Online bool   `json:"online"`
	State  string `json:"state"` // OFF|PROBING|ACTIVE|ACTIVE_TUNNEL_ONLY|DEGRADED|""
	Since  string `json:"since"`
	Note   string `json:"note"`
	// Tunnel fields (zero when no tunnel branch).
	TunnelMode    string `json:"tunnelMode"` // tunnel|escalated|off|""
	TunnelHealthy bool   `json:"tunnelHealthy"`
	TunnelHeld    bool   `json:"tunnelHeld"`
	RxBytes       uint64 `json:"rxBytes"`
	TxBytes       uint64 `json:"txBytes"`
	TCPFlows      int64  `json:"tcpFlows"`
	// Derived telemetry (computed across polls, 1 s cadence).
	SessionSec  int64   `json:"sessionSec"`  // seconds in the current ACTIVE state
	RxRate      float64 `json:"rxRate"`      // bytes/s over the last poll gap
	TxRate      float64 `json:"txRate"`      // bytes/s over the last poll gap
	HealthFails uint64  `json:"healthFails"` // tunnel dropped flows counter
	// Gateway is the primary channel description (set from the saved links).
	Gateway string `json:"gateway"`
}

// poll queries the daemon once and returns the GUI snapshot.
func (c *Controller) poll() Snapshot {
	resp, err := CallPipe(c.opts.Pipe, "status", 2*time.Second)
	if err != nil {
		return Snapshot{Online: false}
	}
	var snap core.Snapshot
	if err := decodeSnapshot(resp, &snap); err != nil {
		c.log.Printf("guictrl: status decode: %v", err)
		return Snapshot{Online: false}
	}
	// Fresh machine, first launch: WinDivertOpen needs admin, the daemon
	// survives but cycles DEGRADED forever. One automatic elevated restart
	// per GUI session — the UAC prompt is the permission dialog the user
	// expects anyway.
	if strings.Contains(snap.Counters.LastProbeNote, "WinDivertOpen: Access is denied") {
		c.maybeElevatedRestart()
	}
	s := Snapshot{
		Online: true,
		State:  snap.State,
		Since:  snap.Since.Format(time.RFC3339),
		// The last probe/degradation note is the only reason string the daemon
		// hands out, and the alert bar needs it: «Сбой» alone says nothing.
		Note: snap.Counters.LastProbeNote,
	}
	if snap.Tunnel != nil {
		s.TunnelMode = snap.Tunnel.Mode
		s.TunnelHealthy = snap.Tunnel.Healthy
		s.TunnelHeld = snap.Tunnel.Held
		s.RxBytes = snap.Tunnel.RxBytes
		s.TxBytes = snap.Tunnel.TxBytes
		s.TCPFlows = snap.Tunnel.TCPFlows
		s.HealthFails = snap.Tunnel.Dropped
	}
	// Session: time in the current steady state.
	if s.State == "ACTIVE" || s.State == "ACTIVE_TUNNEL_ONLY" {
		s.SessionSec = int64(time.Since(snap.Since).Seconds())
		if s.SessionSec < 0 {
			s.SessionSec = 0
		}
	}
	// Speeds: byte deltas over the poll gap (field-gated on state change so
	// a jump from OFF does not produce a spike).
	s.Gateway = c.gateway()
	s.RxRate, s.TxRate = c.rates(s.State, s.RxBytes, s.TxBytes)
	return s
}

// rates computes per-second rates from byte deltas between consecutive polls.
func (c *Controller) rates(state string, rx, tx uint64) (float64, float64) {
	now := time.Now()
	c.mu.Lock()
	prev := c.prev
	c.prev = ratePrev{at: now, state: state, rx: rx, tx: tx}
	c.mu.Unlock()
	dt := now.Sub(prev.at).Seconds()
	if dt <= 0.2 || dt > 10 || prev.state != state || prev.rx > rx || prev.tx > tx {
		return 0, 0 // first sample, state change or counter reset
	}
	return float64(rx-prev.rx) / dt, float64(tx-prev.tx) / dt
}

// ratePrev is the previous poll sample for rate computation.
type ratePrev struct {
	at    time.Time
	state string
	rx    uint64
	tx    uint64
}

// Status returns the current snapshot without touching the daemon.
func (c *Controller) Status() Snapshot {
	c.mu.Lock()
	s := c.last
	c.mu.Unlock()
	if s == nil {
		return Snapshot{}
	}
	return *s
}

// OnSnapshot registers a listener fired on every poll result change; returns
// an unregistration function.
func (c *Controller) OnSnapshot(fn func(Snapshot)) (unregister func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextHook++
	id := c.nextHook
	c.listeners[id] = fn
	return func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		delete(c.listeners, id)
	}
}

// emit fires listeners outside the lock.
func (c *Controller) emit(s Snapshot) {
	c.mu.Lock()
	fns := make([]func(Snapshot), 0, len(c.listeners))
	for _, fn := range c.listeners {
		fns = append(fns, fn)
	}
	c.mu.Unlock()
	for _, fn := range fns {
		fn(s)
	}
}

// runPoller polls the daemon and notifies listeners on changes. stop is the
// channel of THIS run, so a stopped poller never adopts a newer one's stop.
func (c *Controller) runPoller(emit func(Snapshot), stop <-chan struct{}) {
	t := time.NewTicker(c.opts.PollInterval)
	defer t.Stop()
	var last Snapshot
	for {
		select {
		case <-stop:
			return
		default:
		}
		s := c.poll()
		if s != last {
			last = s
			c.mu.Lock()
			c.last = &s
			c.mu.Unlock()
			emit(s)
		}
		select {
		case <-t.C:
		case <-stop:
			return
		}
	}
}

// pollerAlive reports whether a poller with stop is still running (its stop
// channel stays non-nil after StopPoller, so liveness is "not closed").
func pollerAlive(stop chan struct{}) bool {
	if stop == nil {
		return false
	}
	select {
	case <-stop:
		return false
	default:
		return true
	}
}

// StartPoller starts the background status poller (idempotent).
func (c *Controller) StartPoller(emit func(Snapshot)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if pollerAlive(c.stopPoll) {
		return
	}
	stop := make(chan struct{})
	c.stopPoll = stop
	go c.runPoller(emit, stop)
}

// StopPoller halts the background poller. The channel is kept: a loop that
// is inside poll() sees it closed on its next check and exits.
func (c *Controller) StopPoller() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if ch := c.stopPoll; ch != nil {
		select {
		case <-ch: // already stopped
		default:
			close(ch)
		}
	}
}

// decodeSnapshot unpacks the RPC Response data into core.Snapshot.
func decodeSnapshot(resp *rpc.Response, snap *core.Snapshot) error {
	if resp == nil || !resp.OK {
		return fmt.Errorf("status failed")
	}
	raw, err := jsonMarshal(resp.Data)
	if err != nil {
		return err
	}
	return jsonUnmarshal(raw, snap)
}

// DefaultConfigPath guesses the onboarding config location:
// <exe dir>/configs/rupas.yaml or <exe dir>/../configs/rupas.yaml (repo
// layout, exe in build/), else %ProgramData%\Rupas\rupas.yaml.
func DefaultConfigPath() string {
	exe, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(exe)
		for _, p := range []string{
			filepath.Join(dir, "configs", "rupas.yaml"),
			filepath.Join(dir, "..", "configs", "rupas.yaml"),
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return filepath.Join(os.Getenv("ProgramData"), "Rupas", "rupas.yaml")
}
