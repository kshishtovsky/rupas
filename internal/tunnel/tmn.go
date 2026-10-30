package tunnel

// TMN/1 — Rupas' own TCP transport (TLS 1.3 + mux + PSK auth), carried by
// the in-package client instead of sing-box (it has no such outbound).
// Unlike a vless carrier, one dial does NOT open a network connection: the
// client keeps a fixed pool of long-lived TLS sessions (Endpoint.Conns) and
// multiplexes every flow over them, so the carrier is not paced.

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/tuman/client"
)

// tmnDialTimeout bounds one flow dial when the caller's ctx has no deadline
// (a cold pool must not hang a redirected flow).
const tmnDialTimeout = 20 * time.Second

var errTMNClosed = errors.New("tmn: carrier closed")

// tmnClientNew builds the session pool. A test seam: the in-process test
// server has a self-signed cert, so the test turns Insecure on.
var tmnClientNew = client.New

// tmnPath carries TCP streams over one tmn endpoint.
type tmnPath struct {
	c      *client.Client
	dialTO time.Duration
}

func newTMNPath(ep config.Endpoint, logger *slog.Logger) (*tmnPath, error) {
	psk, err := config.NormalizePSK(ep.PSK)
	if err != nil {
		return nil, fmt.Errorf("tmn: %v", err)
	}
	key, err := hex.DecodeString(psk)
	if err != nil {
		return nil, fmt.Errorf("tmn: psk: %w", err)
	}
	c, err := tmnClientNew(client.Config{
		Servers: []client.Endpoint{{
			Addr: net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port))),
			SNI:  ep.SNI,
		}},
		PSK:     key,
		SNI:     ep.SNI,
		Conns:   ep.Conns, // 0 → the library default (4)
		Profile: "off",    // the shaper stays off by default
		// Cooldown 0 → the library default (30 s).
		Logger: prefixLogger(logger, "tmn: "),
	})
	if err != nil {
		return nil, fmt.Errorf("tmn: %w", err)
	}
	return &tmnPath{c: c, dialTO: tmnDialTimeout}, nil
}

func (p *tmnPath) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	return p.dialHost(ctx, dst.Addr().Unmap().String(), dst.Port())
}

// dialHost sends the host verbatim: a domain is resolved at the exit.
func (p *tmnPath) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if _, ok := ctx.Deadline(); !ok {
		to := p.dialTO
		if to <= 0 {
			to = tmnDialTimeout
		}
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, to)
		defer cancel()
	}
	c, err := p.c.DialContext(ctx, "tcp", net.JoinHostPort(host, strconv.Itoa(int(port))))
	if err != nil {
		return nil, fmt.Errorf("tmn: %w", err)
	}
	return c, nil
}

func (p *tmnPath) Close() error { return p.c.Close() }

// lazyTMN defers client construction to the first dial so an unresponsive
// endpoint never blocks Start, and so a run that never dialed leaves no pool.
type lazyTMN struct {
	ep     config.Endpoint
	logger *slog.Logger

	once   sync.Once
	p      atomic.Pointer[tmnPath]
	err    error
	closed atomic.Bool
}

func (l *lazyTMN) path() (*tmnPath, error) {
	l.once.Do(func() {
		p, err := newTMNPath(l.ep, l.logger)
		if err != nil {
			l.err = err
			return
		}
		if l.closed.Load() { // Close raced the first dial: leave no pool behind
			p.Close() //nolint:errcheck // teardown
			l.err = errTMNClosed
			return
		}
		l.p.Store(p)
	})
	if p := l.p.Load(); p != nil {
		return p, nil
	}
	return nil, l.err
}

func (l *lazyTMN) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	p, err := l.path()
	if err != nil {
		return nil, err
	}
	return p.dial(ctx, dst)
}

func (l *lazyTMN) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	p, err := l.path()
	if err != nil {
		return nil, err
	}
	return p.dialHost(ctx, host, port)
}

// Close tears the session pool down. Nil-safe and idempotent: it runs for a
// carrier that never dialed too (Stop closes every built tmn carrier).
func (l *lazyTMN) Close() error {
	l.closed.Store(true)
	if p := l.p.Load(); p != nil {
		return p.Close()
	}
	return nil
}

// prefixHandler tags every log line of a subcomponent with its carrier name.
type prefixHandler struct {
	slog.Handler
	prefix string
}

func (h prefixHandler) Handle(ctx context.Context, r slog.Record) error {
	r.Message = h.prefix + r.Message
	return h.Handler.Handle(ctx, r)
}

func (h prefixHandler) WithAttrs(a []slog.Attr) slog.Handler {
	return prefixHandler{h.Handler.WithAttrs(a), h.prefix}
}

func (h prefixHandler) WithGroup(name string) slog.Handler {
	return prefixHandler{h.Handler.WithGroup(name), h.prefix}
}

func prefixLogger(l *slog.Logger, prefix string) *slog.Logger {
	if l == nil {
		l = slog.Default()
	}
	return slog.New(prefixHandler{l.Handler(), prefix})
}
