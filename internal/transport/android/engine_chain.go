package android

// Dial-chain carriers (desktop internal/tunnel dial-order parity).
//
// The engine dials a TUNNEL flow through the first healthy carrier; if the
// carrier fails outright — or dies BEFORE its first payload byte (the
// xray-refusal case: the server answers the VLESS request with an HTTP
// fallback page, sing-box closes the relay with "unknown version: 72", and
// the socks connection sees a clean EOF) — the next carrier is tried
// transparently. The request bytes written before the refusal are REPLAYED
// to the next carrier (the refusal proves the dead carrier never processed
// them). After the first payload byte arrives from the carrier the
// connection is committed: a mid-stream carrier switch would corrupt the
// byte stream.
//
// Carriers that refuse are put on a shared 60s cooldown: new flows start
// at the first healthy carrier instead of re-paying the dead primary every
// connection (desktop parity: tunnel.orderedChain + pathCooldown; live
// finding 2026-10-26: a reconfigured xray can refuse 100% of the primary's
// VLESS requests for hours — "unknown version: 72" — while hysteria2 on
// the same VPS keeps working).

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/tunnel"
)

// carrierCooldown is how long a carrier that failed a dial or died before
// its first payload byte is deprioritized after REPEATED consecutive
// deaths (desktop tunnel.pathCooldown).
const carrierCooldown = 60 * time.Second

// carrierCooldownSoft is the first-response cooldown. Isolated pre-payload
// deaths are frequently NOT the carrier's fault but the destination's: the
// server cannot dial IPv6 / :853 / :5222-5228 (live finding 2026-10-27 —
// hysteria2 as primary kept getting benched by Google's IPv6 flows, the
// journal showing "dial tcp6: network is unreachable" server-side), so the
// first two consecutive deaths only cost a short bench.
const carrierCooldownSoft = 10 * time.Second

// carrierCooldownFails: consecutive pre-payload deaths after which the
// full carrierCooldown applies (the xray-refusal storm still benches the
// dead primary quickly — the third dying flow reaches it).
const carrierCooldownFails = 3

// replayCap bounds the pre-payload write replay buffer. A flow that wrote
// more than this without receiving a single byte back is an upload —
// switching carriers under it buys nothing, so it commits instead.
const replayCap = 16 * 1024

// carrierDialTimeout bounds ONE carrier's dial. Without it a blackholed
// endpoint (DPI drop, dead node) stalls the flow for the SOCKS handshake
// deadline (10s) per carrier, so on a 3-profile chain every new connection
// hung ~30s and the app read as "nothing loads at all" (live 2026-10-29).
// A var so tests can shrink it.
var carrierDialTimeout = 6 * time.Second

// carrierHealth is one carrier's failure cooldown deadline (unix nanos,
// 0 = healthy) plus the consecutive-death counter for cooldown escalation.
// Touches are atomic: dials happen on many goroutines.
type carrierHealth struct {
	down  atomic.Int64
	fails atomic.Int64
	// proven is set once the carrier has delivered payload in this run.
	// A proven carrier outranks an unproven one in the dial order: on a
	// DPI'd access link the secondary profiles are frequently dead outright
	// (live 2026-10-29: Rostelecom, reality works while xhttp/hysteria2 never
	// return a byte), and benching the working primary for 10s used to
	// blackhole every new flow into them — "works 5s, then nothing loads".
	proven atomic.Bool
}

// markCarrierFail puts the carrier on cooldown; logs only the transition
// from healthy (a carrier already down just has its deadline extended).
// The bench length escalates with consecutive deaths: isolated deaths get
// carrierCooldownSoft (usually the destination's fault), a persistent
// failure pattern (xray refusal storm) reaches the full carrierCooldown.
func (e *Engine) markCarrierFail(idx int, cause error) {
	if idx < 0 || idx >= len(e.health) {
		return
	}
	// The escalation tail has nowhere to fail over TO: benching it just puts
	// direct ahead of live tunnel carriers on the next flow.
	if e.carriers[idx].tail {
		return
	}
	dur := carrierCooldownSoft
	if e.health[idx].fails.Add(1) >= carrierCooldownFails {
		dur = carrierCooldown
	}
	till := time.Now().Add(dur).UnixNano()
	if e.health[idx].down.Swap(till) == 0 && len(e.carriers) > 1 {
		e.logf("carrier %s: down (%v) — deprioritized for %s", e.carriers[idx].name, cause, dur)
	}
}

// markCarrierSuccess clears the cooldown after real payload from the carrier.
func (e *Engine) markCarrierSuccess(idx int) {
	if idx < 0 || idx >= len(e.health) {
		return
	}
	e.activeIdx.Store(int64(idx))
	e.health[idx].proven.Store(true)
	e.health[idx].fails.Store(0)
	if e.health[idx].down.Swap(0) != 0 && len(e.carriers) > 1 {
		e.logf("carrier %s: healthy again", e.carriers[idx].name)
	}
}

// CarrierState is one dial-chain carrier as surfaced to the app UI (via
// core.Status JSON): the carrier name and its live health position.
type CarrierState struct {
	Index int    `json:"index"`
	Name  string `json:"name"`
	// State is one of: "active" (where new flows start: the head of the
	// dial order — a recently benched carrier that already proved itself
	// keeps that slot), "cooldown" (failed recently, tried last), "ready".
	State string `json:"state"`
}

// CarrierStates snapshots the dial chain for the UI. Safe for concurrent
// use: all inputs are atomic or built once per run.
func (e *Engine) CarrierStates() []CarrierState {
	n := len(e.carriers)
	if n == 0 {
		return nil
	}
	now := time.Now().UnixNano()
	head := e.carrierOrder()[0]
	out := make([]CarrierState, n)
	for i, c := range e.carriers {
		st := "ready"
		switch {
		case i == head:
			st = "active"
		case n > 1 && e.health[i].down.Load() > now:
			st = "cooldown"
		}
		out[i] = CarrierState{Index: i, Name: c.name, State: st}
	}
	return out
}

// carrierOrder returns carrier indexes in try order: carriers that have
// already delivered payload come before carriers that never have (a bench
// must not divert traffic into a profile that has not proven itself),
// then dial order, healthy before failure cooldown (desktop orderedChain
// parity — deprioritized, never skipped: the primary still gets tried and
// can recover). Single-carrier engines keep the plain order.
func (e *Engine) carrierOrder() []int {
	n := len(e.carriers)
	order := make([]int, 0, n)
	var rank [4][]int
	var tail []int
	now := time.Now().UnixNano()
	for i := range e.carriers {
		// The direct tail is not a candidate to steer away from: it stays
		// last no matter how its own flows ended up.
		if e.carriers[i].tail {
			tail = append(tail, i)
			continue
		}
		r := 0
		if n > 1 && !e.health[i].proven.Load() {
			r += 2
		}
		if n > 1 && e.health[i].down.Load() > now {
			r++
		}
		rank[r] = append(rank[r], i)
	}
	for _, bucket := range rank {
		order = append(order, bucket...)
	}
	return append(order, tail...)
}

// tcpCarrier is one named way to reach the internet for a TUNNEL flow.
type tcpCarrier struct {
	name string
	// tail marks the direct escalation tail. It is never reordered and never
	// benched: benches exist to steer traffic BETWEEN tunnel carriers, and
	// benching the last resort only moves it in front of live carriers.
	tail bool
	dial func(ctx context.Context, dst netip.AddrPort) (net.Conn, error)
}

// buildCarriers assembles the dial chain after the relay start: one
// carrier per endpoint (sing-box inbound for box kinds, the own XHTTP
// client for xhttp). Called once per transport run.
func (e *Engine) buildCarriers(ctx context.Context) {
	e.carriers = nil
	if e.relay == nil {
		return
	}
	eps := e.relay.endpoints
	// socksAddrs is nil when the relay start failed before allocating the
	// inbounds: never index it against the endpoint list shape blindly.
	chainOK := len(e.relay.socksAddrs) == len(eps)
	for i, ep := range eps {
		if ep.NeedsXHTTP() {
			c, err := newXHTTPCarrier(ep, func(line string) { e.logf("xhttp: %s", line) })
			if err != nil {
				e.logf("carrier %d (%s): unavailable: %v", i, endpointName(ep), err)
				continue
			}
			e.carriers = append(e.carriers, tcpCarrier{name: endpointName(ep), dial: c})
			continue
		}
		if !chainOK || e.relay.socksAddrs[i] == "" {
			continue // box failed to start or this slot failed to allocate
		}
		idx := i
		e.carriers = append(e.carriers, tcpCarrier{
			name: endpointName(ep),
			dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
				return e.relay.DialTCPIndex(idx, ctx, dst)
			},
		})
	}
	// Health state is per-run: cooldowns reset when the engine restarts.
	// The direct tail (fallback=true) stays LAST: it is only reached when
	// every tunnel carrier is dead — the honest escalation path with the
	// pre-payload request replayed (desktop dial-order parity).
	if e.fallbackAllowed() {
		e.carriers = append(e.carriers, tcpCarrier{
			name: "direct",
			tail: true,
			dial: func(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
				e.counters.TunnelEscalate()
				e.logf("tcp %s: ESCALATED tunnel->direct (carrier chain exhausted)", dst)
				return e.dialer.DialContext(ctx, "tcp", dst.String())
			},
		})
	}
	e.health = make([]carrierHealth, len(e.carriers))
	if len(e.carriers) > 1 {
		names := make([]string, len(e.carriers))
		for i, c := range e.carriers {
			names[i] = fmt.Sprintf("%d:%s", i, c.name)
		}
		e.logf("dial chain: %s", strings.Join(names, " -> "))
	}
}

// XHTTPDialer exposes the own XHTTP client as a dial function for callers
// outside the engine (the profile probe). Same code path as the carrier, so
// a probe can never disagree with the tunnel about an xhttp endpoint.
func XHTTPDialer(ep Endpoint, logf func(string)) (func(ctx context.Context, dst netip.AddrPort) (net.Conn, error), error) {
	return newXHTTPCarrier(ep, logf)
}

// newXHTTPCarrier maps a parsed endpoint onto the platform-neutral
// internal/tunnel XHTTP client (packet-up, uTLS).
func newXHTTPCarrier(ep Endpoint, logf func(string)) (func(ctx context.Context, dst netip.AddrPort) (net.Conn, error), error) {
	if ep.Kind != KindVLESS {
		return nil, fmt.Errorf("xhttp: only vless is supported")
	}
	fp := ep.Fingerprint
	if fp == "" {
		fp = "chrome"
	}
	cfgEp := config.Endpoint{
		Kind:        config.KindVLESSXHTTP,
		Host:        ep.Host,
		Port:        ep.Port,
		UUID:        ep.UUID,
		SNI:         ep.SNI,
		HTTPHost:    ep.WSHost,
		ALPN:        []string{"h2", "http/1.1"},
		Fingerprint: fp,
		Path:        ep.Path,
		Mode:        "packet-up",
		XPadding:    "100-1000",
	}
	return tunnel.NewXHTTPDialer(cfgEp, slog.New(xhttpLogHandler{fn: logf}))
}

// xhttpLogHandler forwards slog records from the XHTTP client to the
// engine log callback (warnings and above only).
type xhttpLogHandler struct{ fn func(string) }

func (h xhttpLogHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= slog.LevelWarn
}

func (h xhttpLogHandler) Handle(_ context.Context, rec slog.Record) error {
	h.fn(rec.Message)
	return nil
}

func (h xhttpLogHandler) WithAttrs(_ []slog.Attr) slog.Handler { return h }

func (h xhttpLogHandler) WithGroup(_ string) slog.Handler { return h }

// dialChain dials dst trying every carrier in health order; the returned
// conn transparently re-dials through the remaining carriers when the
// current carrier dies before its first payload byte (see redialConn).
func (e *Engine) dialChain(dst netip.AddrPort) (net.Conn, error) {
	if len(e.carriers) == 0 {
		return nil, fmt.Errorf("android: no tunnel carriers available")
	}
	rc := &redialConn{
		carriers:  e.carriers,
		order:     e.carrierOrder(),
		dst:       dst,
		ctx:       context.Background(),
		onFail:    e.markCarrierFail,
		onSuccess: e.markCarrierSuccess,
	}
	rc.onDead = func(idx int, cause error) {
		e.logf("tcp %s: carrier %s died after commit: %v", dst, e.carriers[idx].name, cause)
	}
	if err := rc.dialCurrent(); err != nil {
		return nil, err
	}
	return rc, nil
}

// redialConn is the failover wrapper. See the file comment for the
// commit semantics: pre-payload deaths switch carriers and replay the
// written bytes; the first received payload commits the connection.
type redialConn struct {
	carriers []tcpCarrier
	order    []int // try order (healthy carriers first)
	pos      int   // position in order
	dst      netip.AddrPort
	ctx      context.Context
	conn     net.Conn
	spent    bool // first payload byte RECEIVED — no more switching

	// replay holds the bytes written before the first read; on a carrier
	// switch they are re-written to the next carrier. Lazy: allocated on
	// the first pre-payload write, freed back on commit/close.
	replay []byte
	// full: the replay cap was hit — treat as an upload flow, commit.
	full bool

	// health callbacks (engine-owned, nil-safe for tests).
	onFail    func(idx int, cause error)
	onSuccess func(idx int)
	// onDead fires once when a COMMITTED connection (first payload already
	// received) dies: that case never reaches failover, so without this the
	// log says nothing about a tunnel the DPI cut mid-stream.
	onDead func(idx int, cause error)

	// deadlines captured before the carrier dials (net.Conn contract).
	deadline      time.Time
	readDeadline  time.Time
	writeDeadline time.Time
}

func (r *redialConn) dialCurrent() error {
	for {
		idx := r.order[r.pos]
		dctx, cancel := context.WithTimeout(r.ctx, carrierDialTimeout)
		c, err := r.carriers[idx].dial(dctx, r.dst)
		cancel() // the dialed conn does not inherit it (socks5/xhttp detach)
		if err == nil {
			r.conn = c
			r.applyDeadlines()
			if len(r.replay) > 0 {
				if _, wErr := c.Write(r.replay); wErr != nil {
					if r.onFail != nil {
						r.onFail(idx, wErr)
					}
					r.conn = nil
					if r.pos+1 >= len(r.order) {
						return fmt.Errorf("android: carrier %s lost replay: %w", r.carriers[idx].name, wErr)
					}
					r.pos++
					continue
				}
			}
			return nil
		}
		if r.onFail != nil {
			r.onFail(idx, err)
		}
		if r.pos+1 >= len(r.order) {
			return fmt.Errorf("android: all %d carriers failed (last %s: %w)",
				len(r.order), r.carriers[idx].name, err)
		}
		r.pos++
	}
}

func (r *redialConn) failover(cause error) bool {
	if r.spent || r.full || r.pos+1 >= len(r.order) {
		return false
	}
	if r.onFail != nil {
		r.onFail(r.order[r.pos], cause)
	}
	r.pos++
	if r.conn != nil {
		_ = r.conn.Close()
		r.conn = nil
	}
	if err := r.dialCurrent(); err != nil {
		return false
	}
	return true
}

// commit frees the replay buffer and locks the carrier in.
func (r *redialConn) commit() {
	r.replay = nil
	r.spent = true
	if r.onSuccess != nil {
		r.onSuccess(r.order[r.pos])
	}
}

func (r *redialConn) Read(b []byte) (int, error) {
	for {
		n, err := r.conn.Read(b)
		if n > 0 {
			if !r.spent {
				r.commit()
			}
			return n, err
		}
		if err == nil {
			return 0, nil
		}
		if r.spent && r.onDead != nil {
			dead := r.onDead
			r.onDead = nil
			dead(r.order[r.pos], err)
		}
		if r.failover(err) {
			continue
		}
		return 0, err
	}
}

func (r *redialConn) Write(b []byte) (int, error) {
	// failover() nils r.conn and re-dials (up to DialTimeout); a concurrent
	// writer would deref nil and kill the Android process. Refuse instead.
	if r.conn == nil {
		return 0, net.ErrClosed
	}
	n, err := r.conn.Write(b)
	if n > 0 && !r.spent && !r.full {
		if r.replay == nil {
			r.replay = make([]byte, 0, replayCap)
		}
		if room := replayCap - len(r.replay); room > 0 {
			take := n
			if take > room {
				take = room
			}
			r.replay = append(r.replay, b[:take]...)
		}
		if len(r.replay) >= replayCap {
			// Upload-shaped flow: keep the carrier, stop replaying.
			r.replay = nil
			r.full = true
		}
	}
	return n, err
}

func (r *redialConn) Close() error {
	if r.conn == nil {
		return nil
	}
	return r.conn.Close()
}

func (r *redialConn) applyDeadlines() {
	if r.conn == nil {
		return
	}
	if !r.deadline.IsZero() {
		_ = r.conn.SetDeadline(r.deadline)
	}
	if !r.readDeadline.IsZero() {
		_ = r.conn.SetReadDeadline(r.readDeadline)
	}
	if !r.writeDeadline.IsZero() {
		_ = r.conn.SetWriteDeadline(r.writeDeadline)
	}
}

func (r *redialConn) LocalAddr() net.Addr {
	if r.conn == nil {
		return nil
	}
	return r.conn.LocalAddr()
}

func (r *redialConn) RemoteAddr() net.Addr {
	if r.conn == nil {
		return nil
	}
	return r.conn.RemoteAddr()
}

func (r *redialConn) SetDeadline(t time.Time) error {
	r.deadline = t
	if r.conn != nil {
		return r.conn.SetDeadline(t)
	}
	return nil
}

func (r *redialConn) SetReadDeadline(t time.Time) error {
	r.readDeadline = t
	if r.conn != nil {
		return r.conn.SetReadDeadline(t)
	}
	return nil
}

func (r *redialConn) SetWriteDeadline(t time.Time) error {
	r.writeDeadline = t
	if r.conn != nil {
		return r.conn.SetWriteDeadline(t)
	}
	return nil
}
