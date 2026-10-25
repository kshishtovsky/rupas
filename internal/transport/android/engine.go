package android

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
)

// Engine owns one TUN-backed transport session. It is created per Start and
// parked under the mobile/ package's lifecycle guard. Start is non-blocking:
// run (platform-specific) executes in a goroutine and shuts down on
// Stop/context cancel.
type Engine struct {
	verdict  Verdict
	protect  ProtectFunc
	logFn    func(string)
	dialer   *net.Dialer
	counters Counters

	mu      sync.Mutex
	running bool
	cancel  context.CancelFunc
	done    chan struct{}
}

// NewEngine assembles an engine. verdict is the wave-2 seam (pass
// DirectVerdict for the current all-direct behaviour); protect is called
// inside dialer Control hooks with the raw socket fd; logFn receives
// transport log lines (nil-safe: drops them).
func NewEngine(verdict Verdict, protect ProtectFunc, logFn func(string)) *Engine {
	if verdict == nil {
		verdict = DirectVerdict
	}
	if logFn == nil {
		logFn = func(string) {}
	}
	return &Engine{
		verdict: verdict,
		protect: protect,
		logFn:   logFn,
		dialer:  ProtectedDialer(protect),
	}
}

// Start launches the transport on a Java-owned TUN fd. Non-blocking; a
// second Start without Stop returns an error.
func (e *Engine) Start(fd int) error {
	e.mu.Lock()
	if e.running {
		e.mu.Unlock()
		return errors.New("android: engine already running (call Stop first)")
	}
	if fd <= 0 {
		e.mu.Unlock()
		return errors.New("android: invalid tun fd")
	}
	e.running = true
	ctx, cancel := context.WithCancel(context.Background())
	e.cancel = cancel
	e.done = make(chan struct{})
	done := e.done

	go func() {
		defer close(done)
		if err := e.run(ctx, fd); err != nil && ctx.Err() == nil {
			e.logf("transport exited: %v", err)
		}
	}()
	return nil
}

// Stop shuts the transport down. Without a prior Start it is a no-op
// returning nil (matches the mobile contract).
func (e *Engine) Stop() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if !e.running {
		return nil
	}
	e.cancel()
	<-e.done
	e.running = false
	e.cancel = nil
	e.done = nil
	return nil
}

// Running reports whether the engine was started and not yet stopped.
func (e *Engine) Running() bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.running
}

// Snapshot returns the transport counters.
func (e *Engine) Snapshot() StatusSnapshot { return e.counters.Snapshot() }

func (e *Engine) logf(format string, args ...any) {
	e.logFn("android: " + fmt.Sprintf(format, args...))
}

func (e *Engine) logln(args ...any) {
	e.logFn("android: " + strings.TrimSuffix(fmt.Sprintln(args...), "\n"))
}

// pump copies one direction of a TCP relay and adds the payload bytes to
// the matching counter (rx: app→internet, tx: internet→app).
func (e *Engine) pump(dst, src net.Conn, add func(int64)) {
	n, _ := copyConn(dst, src)
	add(n)
}

// copyConn copies src→dst with a 16 KiB buffer (comfortably above the TUN
// MTU, so MTU-sized netstack reads complete in one write).
func copyConn(dst, src net.Conn) (int64, error) {
	buf := make([]byte, 16*1024)
	var total int64
	for {
		n, rErr := src.Read(buf)
		if n > 0 {
			written, wErr := dst.Write(buf[:n])
			total += int64(written)
			if wErr != nil {
				return total, wErr
			}
		}
		if rErr != nil {
			return total, rErr
		}
	}
}
