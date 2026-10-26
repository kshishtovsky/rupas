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
	"sync"
	"time"

	"github.com/rupas/rupas/internal/core"
	"github.com/rupas/rupas/internal/rpc"
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
// daemon-online flag and a human note. It mirrors core.Snapshot but stays a
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
	s := Snapshot{
		Online: true,
		State:  snap.State,
		Since:  snap.Since.Format(time.RFC3339),
	}
	if snap.Tunnel != nil {
		s.TunnelMode = snap.Tunnel.Mode
		s.TunnelHealthy = snap.Tunnel.Healthy
		s.TunnelHeld = snap.Tunnel.Held
		s.RxBytes = snap.Tunnel.RxBytes
		s.TxBytes = snap.Tunnel.TxBytes
		s.TCPFlows = snap.Tunnel.TCPFlows
	}
	return s
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

// runPoller polls the daemon and notifies listeners on changes.
func (c *Controller) runPoller(emit func(Snapshot)) {
	t := time.NewTicker(c.opts.PollInterval)
	defer t.Stop()
	var last Snapshot
	for {
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
		case <-c.pollStopped():
			return
		}
	}
}

// pollStopped returns the current stop channel under the lock.
func (c *Controller) pollStopped() <-chan struct{} {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopPoll == nil {
		ch := make(chan struct{})
		return ch
	}
	return c.stopPoll
}

// StartPoller starts the background status poller (idempotent).
func (c *Controller) StartPoller(emit func(Snapshot)) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopPoll != nil {
		return
	}
	stop := make(chan struct{})
	c.stopPoll = stop
	go c.runPoller(emit)
}

// StopPoller halts the background poller.
func (c *Controller) StopPoller() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.stopPoll != nil {
		close(c.stopPoll)
		c.stopPoll = nil
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
// <exe dir>/configs/rupas.yaml (repo layout) or %ProgramData%\rupas\rupas.yaml.
func DefaultConfigPath() string {
	exe, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(exe), "configs", "rupas.yaml")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return filepath.Join(os.Getenv("ProgramData"), "Rupas", "rupas.yaml")
}
