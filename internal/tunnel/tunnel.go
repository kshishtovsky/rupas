// Package tunnel implements the TUNNEL branch of the Rupas hot path
// (SYSTEM_DESIGN §3.3, §6): it accepts NAT-redirected TCP and UDP traffic on
// a loopback listener at 127.0.0.1:tproxyPort, recovers the original
// destination for each client 4-tuple from the capture-layer NAT flow table
// (OriginalDstProvider) and carries the flow through a sing-box
// VLESS+Reality tunnel (uTLS fingerprint from the config, XUDP for UDP).
//
// Layout:
//
//	tunnel.go   — public API, lifecycle, TCP accept loop
//	udp.go      — UDP pseudo-session table (src 4-tuple keyed, 30 s idle GC)
//	health.go   — marker probing and Healthy() transitions
//	socks.go    — minimal SOCKS5 client speaking to the internal sing-box
//	              mixed inbound (TCP CONNECT + UDP ASSOCIATE)
//	sbconfig.go — config.TunnelEndpoint → sing-box options (JSON) mapping
//	sbinstance.go — sing-box library lifecycle with a minimal protocol registry
package tunnel

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rupas/rupas/internal/config"
)

// Tunnel is the tunnel-core contract consumed by the supervisor (§2, §6).
type Tunnel interface {
	// Start brings up the sing-box engine, the loopback tproxy listeners and
	// the health probe loop. It returns once startup finished.
	Start(ctx context.Context) error
	// Stop tears everything down. It is idempotent.
	Stop() error
	// Healthy reports whether the marker probe succeeded through the tunnel
	// recently: 3 consecutive failures flip it to false, one success flips it
	// back to true.
	Healthy() bool
	// Stats returns the point-in-time counters (bytes, flows, drops) that
	// `rupasctl status` renders in the tunnel section.
	Stats() Stats
}

// Stats is the live tunnel-branch status (§11 observability).
type Stats struct {
	// Healthy mirrors Healthy() at snapshot time.
	Healthy bool
	// Held is the HOLD state (§6): the marker failed HealthFailThreshold
	// times in a row, so NEW flows are dropped with a counter instead of
	// being relayed through a dead tunnel (or escalated to direct, which
	// the TSPU would black-hole anyway).
	Held bool
	// Started is true once Start succeeded.
	Started bool
	// UDPHealthy reports the UDP-path STUN verdict (true while the primary
	// UDP endpoint answers; unknown/false before the first probe or when
	// the probe is disabled).
	UDPHealthy bool
	// UDPFallback is true while UDP pseudo-sessions ride the xudp fallback
	// over the TCP endpoint (engaged after HealthFailThreshold STUN
	// failures).
	UDPFallback bool
	// RxBytes/TxBytes are the payload bytes relayed client↔tunnel.
	RxBytes, TxBytes uint64
	// TCPFlows is the number of active TCP relays; TCPConns the total
	// accepted flows.
	TCPFlows, TCPConns int64
	// UDPSessions is the number of live UDP pseudo-sessions; UDPDgrams the
	// total datagrams handled.
	UDPSessions int64
	UDPDgrams   uint64
	// Dropped counts flows/datagrams refused: no original dst, dial
	// failure or HOLD.
	Dropped uint64
	// MixedAddr is the loopback address of the main sing-box mixed
	// inbound ("127.0.0.1:port"; "" when the plan has none). Direct
	// SOCKS5/HTTP access to it is ALWAYS accepted regardless of the
	// terminator's storm gate or the HOLD state (different layers —
	// wave-6 acceptance gate for F5).
	MixedAddr string
}

// OriginalDstProvider is the NAT flow-table lookup of the capture layer
// (§3.3): the NETWORK-layer NAT rewrote dst to 127.0.0.1:tproxyPort and
// stored the original dst keyed by the client src 4-tuple. Addresses are
// 16-byte; IPv4 is in IPv4-mapped form (as in flowtable.FlowKey).
type OriginalDstProvider interface {
	Lookup(srcIP [16]byte, srcPort uint16) (dstIP [16]byte, dstPort uint16, ok bool)
}

// Options carries tunnel collaborators.
type Options struct {
	// OriginalDstProvider resolves the pre-NAT destination of a redirected
	// flow. If nil, every flow is dropped (tunnel runs, nothing passes).
	OriginalDstProvider OriginalDstProvider
	// MarkerURL is the health endpoint probed through the TCP chain.
	// Empty → DefaultMarkerURL.
	MarkerURL string
	// Logger defaults to slog.Default().
	Logger *slog.Logger
	// HealthInterval overrides the marker probe period (0 → 30 s). Tests
	// shrink it; production keeps the §6 default.
	HealthInterval time.Duration
	// UDPHealthInterval overrides the UDP STUN probe period (0 → same as
	// HealthInterval).
	UDPHealthInterval time.Duration
	// STUNServer is the UDP-path health probe target ("host:port"). The
	// default (DefaultSTUNServer) is used when empty; "off" disables the
	// UDP probe (the UDP fallback then never engages automatically).
	STUNServer string
	// DialTimeout bounds one relay dial (TCP CONNECT / UDP ASSOCIATE) so a
	// dead endpoint closes the redirected flow promptly instead of hanging
	// it (0 → DefaultDialTimeout).
	DialTimeout time.Duration
	// NoHoldFlows disables the HOLD gate (diagnostics: relay new flows even
	// while the marker is failing).
	NoHoldFlows bool
	// TCPFallbackFirstCIDRs lists destinations whose dials try the FALLBACK
	// carrier before the primary. Wave-6 live finding: Telegram-DC
	// destinations relayed through the primary vless_tcp connection
	// trigger a TSPU quarantine of the whole primary endpoint (~5 min of
	// silently dropped SYNs, marker included), while the same destinations
	// ride hysteria2 TCP fine — so the app fills this with the config's
	// tunnel-verdict CIDRs (the TG ranges).
	TCPFallbackFirstCIDRs []netip.Prefix
}

const (
	// DefaultMarkerURL is the default health marker (§6: GET …/204 every 30 s).
	DefaultMarkerURL = "https://www.gstatic.com/generate_204"
	// DefaultHealthInterval is the marker probe period.
	DefaultHealthInterval = 30 * time.Second
	// HealthFailThreshold consecutive failed probes mark the tunnel down.
	HealthFailThreshold = 3
	// DefaultSTUNServer is the default UDP-path health probe target.
	DefaultSTUNServer = "stun.cloudflare.com:3478"
	// DefaultUDPSessionTimeout is the idle timeout of a UDP pseudo-session
	// (§3.3: UDP idle 30 s).
	DefaultUDPSessionTimeout = 30 * time.Second
	// DefaultDialTimeout bounds one relay dial so a dead endpoint closes
	// the redirected flow promptly (§6: honest degradation, no hangs).
	DefaultDialTimeout = 20 * time.Second
	// markerTimeout bounds one probe round trip.
	markerTimeout = 10 * time.Second
	// stunTimeout bounds one STUN round trip.
	stunTimeout = 5 * time.Second
)

// NewTunnel builds a Tunnel for the wave-5 plan cfg. Configuration errors
// are reported by Start so that a half-configured endpoint can still be
// constructed.
func NewTunnel(cfg config.TunnelConfig, tproxyPort uint16, opts Options) Tunnel {
	if opts.Logger == nil {
		opts.Logger = slog.Default()
	}
	if opts.MarkerURL == "" {
		opts.MarkerURL = DefaultMarkerURL
	}
	if opts.HealthInterval <= 0 {
		opts.HealthInterval = DefaultHealthInterval
	}
	if opts.UDPHealthInterval <= 0 {
		opts.UDPHealthInterval = opts.HealthInterval
	}
	if opts.STUNServer == "" {
		opts.STUNServer = DefaultSTUNServer
	}
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = DefaultDialTimeout
	}
	return &tunnel{
		cfg:               cfg,
		tproxyPort:        tproxyPort,
		opts:              opts,
		logger:            opts.Logger.With("component", "tunnel"),
		healthInterval:    opts.HealthInterval,
		udpHealthInterval: opts.UDPHealthInterval,
		dialTimeout:       opts.DialTimeout,
		udpTimeout:        DefaultUDPSessionTimeout,
	}
}

type tunnel struct {
	cfg        config.TunnelConfig
	tproxyPort uint16
	opts       Options
	logger     *slog.Logger

	// test knobs (package-internal)
	healthInterval    time.Duration
	udpHealthInterval time.Duration
	dialTimeout       time.Duration
	udpTimeout        time.Duration
	// probeFunc overrides the marker probe in unit tests.
	probeFunc func(ctx context.Context) error
	// tr replaces every carrier chain with one fake transport in unit
	// tests (startCore path).
	tr transport

	sb *singbox

	// carrier chains (built by Start; the TCP chain is tried in order per
	// dial — primary then fallback — and the UDP chain switches to the
	// xudp fallback after HealthFailThreshold STUN failures).
	tcpPaths []namedTCP
	udpPaths []namedUDP

	tcpLn    net.Listener
	udpConn  *net.UDPConn
	sessions *udpTable

	ctx       context.Context
	cancelCtx context.CancelFunc
	stopOnce  sync.Once
	stopped   atomic.Bool
	wg        sync.WaitGroup

	healthy    atomic.Bool
	failStreak atomic.Int32

	// UDP-path health (STUN through the active UDP carrier).
	udpHealthy    atomic.Bool
	udpFailStreak atomic.Int32
	activeUDP     atomic.Int32 // index into udpPaths

	// STUN resolution cache.
	stunAddrOnce sync.Once
	stunAddr     netip.AddrPort
	stunAddrErr  error

	// observability counters (Stats)
	started   atomic.Bool
	rxBytes   atomic.Uint64
	txBytes   atomic.Uint64
	tcpFlows  atomic.Int64
	tcpConns  atomic.Int64
	udpDgrams atomic.Uint64
	dropped   atomic.Uint64

	// pathDown tracks per-carrier failure cooldowns (dialOrder fast
	// failover; wave 6).
	pathMu     sync.Mutex
	pathDown   map[string]time.Time
	pathTokens map[string]*tokenBucket
}

var _ Tunnel = (*tunnel)(nil)

// Start validates the plan, boots sing-box (when any sing-box-carried
// endpoint exists), builds the carrier chains, then opens the loopback
// tproxy listeners and the health loops.
//
// NOTE: sing-box gates Reality/uTLS behind the `with_utls` build tag; build
// and test this package with -tags with_utls.
func (t *tunnel) Start(ctx context.Context) error {
	if err := validatePlan(t.cfg); err != nil {
		return err
	}
	if t.stopped.Load() {
		return errors.New("tunnel: Start after Stop is not supported")
	}

	plan := effectivePlan(t.cfg)
	ports, err := sbPortsForPlan(t.cfg)
	if err != nil {
		return err
	}
	if ports.Main != 0 || ports.TCPFB != 0 || ports.UDPFB != 0 {
		sb, err := startSingbox(ctx, t.logger, boxOptions(t.cfg, ports), ports)
		if err != nil {
			return fmt.Errorf("tunnel: start sing-box: %w", err)
		}
		t.sb = sb
	}

	// TCP chain (wave 6): primary, then the automatic fallbacks —
	//   1. a sing-box-carried fallback endpoint when configured, else
	//      the distinct hysteria2 endpoint (hy2 carries TCP streams);
	//   2. the vless_xhttp fallback ONLY when explicitly opted in
	//      (configs .xhttp_fallback_in_chain; default off — live finding
	//      F3: TSPU blackholes the XHTTP port on this ISP and a dead
	//      fallback adds a full dial-timeout penalty to every dial).
	if plan.tcp != nil {
		t.tcpPaths = append(t.tcpPaths, t.carrierTCP(plan.tcp))
	}
	fbSB := plan.fallback != nil && plan.fallback.SingBoxKind()
	switch {
	case fbSB:
		t.tcpPaths = append(t.tcpPaths, t.carrierTCP(plan.fallback))
	case ports.TCPFB != 0:
		// The TCPFB mixed inbound routes to the distinct hy2 outbound
		// (see boxOptions/fbRouteTag).
		if plan.udp != nil && !sameEndpoint(plan.udp, plan.tcp) {
			t.tcpPaths = append(t.tcpPaths, namedTCP{
				name: endpointName(plan.udp) + "+tcp",
				c:    socksPath{addr: t.sb.fbAddr()},
			})
		}
	}
	if plan.fallback != nil && !fbSB && t.cfg.XHTTPFallbackInChain {
		t.tcpPaths = append(t.tcpPaths, t.carrierTCP(plan.fallback))
	}
	// UDP chain: the UDP endpoint (via the main mixed inbound, network
	// rule), then the xudp fallback over the TCP endpoint's outbound.
	if plan.udp != nil && plan.udp.SingBoxKind() {
		t.udpPaths = append(t.udpPaths, namedUDP{
			name: endpointName(plan.udp),
			c:    socksPath{addr: t.sb.mainAddr()},
		})
	}
	if ports.UDPFB != 0 {
		t.udpPaths = append(t.udpPaths, namedUDP{
			name: endpointName(plan.tcp) + "+xudp",
			c:    socksPath{addr: t.sb.udpFBAddr()},
		})
	}

	kinds := make([]string, 0, 3)
	for _, e := range []*config.Endpoint{plan.tcp, plan.udp, plan.fallback} {
		if e != nil {
			kinds = append(kinds, endpointName(e))
		}
	}
	t.logger.Info("tunnel engine started",
		slog.String("endpoints", strings.Join(kinds, " → ")),
		slog.Uint64("mixed_port", uint64(ports.Main)))
	return t.startCore()
}

// carrierTCP builds the TCP carrier for one endpoint: the sing-box SOCKS5
// feeder for sing-box kinds, the in-package XHTTP client for vless_xhttp.
// VLESS carriers are paced (one network connection per dial; the TSPU
// quarantines the endpoint after ~3 rapid connections — wave 6).
func (t *tunnel) carrierTCP(ep *config.Endpoint) namedTCP {
	name := endpointName(ep)
	if ep.SingBoxKind() {
		var addr string
		if ep == effectivePlan(t.cfg).tcp {
			addr = t.sb.mainAddr()
		} else {
			addr = t.sb.fbAddr()
		}
		paced := ep.Kind == config.KindVLESSTCP || ep.Kind == config.KindVLESSReality
		return namedTCP{name: name, c: socksPath{addr: addr}, paced: paced}
	}
	return namedTCP{name: name, c: &lazyXHTTP{ep: *ep, logger: t.logger}}
}

// endpointName renders a human-readable endpoint label.
func endpointName(e *config.Endpoint) string {
	if e == nil {
		return "none"
	}
	return fmt.Sprintf("%s@%s:%d", e.Kind, e.Host, e.Port)
}

// lazyXHTTP defers XHTTP client construction to the first dial so an
// unresponsive fallback endpoint never blocks Start.
type lazyXHTTP struct {
	ep     config.Endpoint
	logger *slog.Logger

	once sync.Once
	p    *xhttpPath
	err  error
}

func (l *lazyXHTTP) path() (*xhttpPath, error) {
	l.once.Do(func() { l.p, l.err = newXHTTPPath(l.ep, l.logger) })
	return l.p, l.err
}

func (l *lazyXHTTP) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	p, err := l.path()
	if err != nil {
		return nil, err
	}
	return p.dial(ctx, dst)
}

func (l *lazyXHTTP) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	p, err := l.path()
	if err != nil {
		return nil, err
	}
	return p.dialHost(ctx, host, port)
}

// tcpChain returns the effective TCP carrier chain (the fake transport
// seam in unit tests).
func (t *tunnel) tcpChain() []namedTCP {
	if t.tr != nil {
		return []namedTCP{{name: "fake", c: t.tr}}
	}
	return t.tcpPaths
}

// udpChain returns the effective UDP carrier chain.
func (t *tunnel) udpChain() []namedUDP {
	if t.tr != nil {
		return []namedUDP{{name: "fake", c: t.tr}}
	}
	return t.udpPaths
}

// activeUDPPath returns the currently active UDP carrier (index clamped).
func (t *tunnel) activeUDPPath() namedUDP {
	chain := t.udpChain()
	if len(chain) == 0 {
		return namedUDP{}
	}
	i := int(t.activeUDP.Load())
	if i < 0 || i >= len(chain) {
		i = len(chain) - 1
	}
	return chain[i]
}

// startCore opens the tproxy listeners and background loops; it is split
// from Start so unit tests can substitute the transport.
//
// The listeners bind the wildcard address: the capture-layer NAT rewrites
// redirected flows toward the machine's own address on the client-facing
// interface (live matrix finding: 127.0.0.1-targeted re-injections never
// deliver), which is not knowable in advance. Foreign flows without a NAT
// entry are dropped by serveTCP/handleUDPPacket, so the wildcard bind does
// not open a relay.
func (t *tunnel) startCore() error {
	t.ctx, t.cancelCtx = context.WithCancel(context.Background())
	addr := &net.TCPAddr{Port: int(t.tproxyPort)}
	tcpLn, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return fmt.Errorf("tunnel: listen tcp %s: %w", addr, err)
	}
	t.tcpLn = tcpLn
	udpConn, err := net.ListenUDP("udp", &net.UDPAddr{Port: int(t.tproxyPort)})
	if err != nil {
		tcpLn.Close()
		return fmt.Errorf("tunnel: listen udp %s: %w", addr, err)
	}
	t.udpConn = udpConn
	t.sessions = newUDPTable(t)
	t.started.Store(true)

	t.wg.Add(2)
	go t.acceptLoop()
	go t.udpLoop()
	go t.healthLoop()
	go t.udpHealthLoop()

	t.logger.Info("tproxy listeners up",
		slog.String("addr", addr.String()), slog.String("marker", t.opts.MarkerURL),
		slog.String("stun", t.opts.STUNServer))
	return nil
}

// Stop closes listeners, sessions, active TCP relays and the sing-box engine.
func (t *tunnel) Stop() error {
	var err error
	t.stopOnce.Do(func() {
		t.stopped.Store(true)
		if t.cancelCtx != nil {
			t.cancelCtx()
		}
		if t.tcpLn != nil {
			err = errors.Join(err, t.tcpLn.Close())
		}
		if t.sessions != nil {
			t.sessions.closeAll()
		}
		if t.udpConn != nil {
			err = errors.Join(err, t.udpConn.Close())
		}
		err = errors.Join(err, t.engineClose())
		done := make(chan struct{})
		go func() { t.wg.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.logger.Warn("Stop: timed out waiting for goroutines")
		}
		t.logger.Info("tunnel stopped")
	})
	return err
}

// Healthy implements Tunnel.
func (t *tunnel) Healthy() bool { return t.healthy.Load() }

// held reports the HOLD state (§6): HealthFailThreshold consecutive marker
// failures — new flows are dropped with a counter instead of relayed
// through a presumed-dead tunnel. The initial "not yet probed" state is
// NOT held: health starts unknown, not down.
func (t *tunnel) held() bool {
	if t.opts.NoHoldFlows {
		return false
	}
	return t.failStreak.Load() >= HealthFailThreshold
}

// Stats implements Tunnel.
func (t *tunnel) Stats() Stats {
	mixed := ""
	if t.sb != nil && t.sb.ports.Main != 0 {
		mixed = t.sb.mainAddr()
	}
	return Stats{
		Healthy:     t.healthy.Load(),
		Held:        t.held(),
		Started:     t.started.Load(),
		UDPHealthy:  t.udpHealthy.Load(),
		UDPFallback: t.activeUDP.Load() > 0,
		RxBytes:     t.rxBytes.Load(),
		TxBytes:     t.txBytes.Load(),
		TCPFlows:    t.tcpFlows.Load(),
		TCPConns:    t.tcpConns.Load(),
		UDPSessions: int64(t.sessions.len()),
		UDPDgrams:   t.udpDgrams.Load(),
		Dropped:     t.dropped.Load(),
		MixedAddr:   mixed,
	}
}

// packetRelay is one UDP pseudo-session's relay channel.
type packetRelay interface {
	send(dst netip.AddrPort, payload []byte) error
	// receive reads one datagram from the relay; payload aliases buf and
	// is valid until the next receive.
	receive(buf []byte) (src netip.AddrPort, payload []byte, err error)
	close()
}

// ensure tunnel satisfies Stop-with-nil-sb in unit tests.
func (t *tunnel) engineClose() error {
	if t.sb == nil {
		return nil
	}
	return t.sb.close()
}

func (t *tunnel) acceptLoop() {
	defer t.wg.Done()
	for {
		conn, err := t.tcpLn.Accept()
		if err != nil {
			if !t.stopped.Load() {
				t.logger.Error("tcp accept failed", slog.Any("err", err))
			}
			return
		}
		if t.stopped.Load() {
			conn.Close()
			return
		}
		t.wg.Add(1)
		go t.serveTCP(conn)
	}
}

// serveTCP relays one NAT-redirected client connection: src 4-tuple →
// original dst via the provider, then through the tunnel.
func (t *tunnel) serveTCP(client net.Conn) {
	defer t.wg.Done()
	t.tcpConns.Add(1)
	src := client.RemoteAddr()
	srcIP, srcPort, ok := splitAddr(src)
	if !ok {
		t.logger.Warn("tcp: unparsable remote addr", slog.String("src", src.String()))
		t.drop()
		client.Close()
		return
	}
	// HOLD (§6): the marker failed 3× — the tunnel is presumed dead. Drop
	// the flow with a counter instead of relaying into a black hole (and
	// instead of escalating to DIRECT: the TSPU blackholes these CIDRs).
	if t.held() {
		t.logger.Warn("tcp: tunnel HELD, dropping flow",
			slog.String("src", src.String()),
			slog.Int("fail_streak", int(t.failStreak.Load())))
		t.drop()
		client.Close()
		return
	}
	dstIP, dstPort, ok := t.lookupOriginalDst(srcIP, srcPort)
	if !ok {
		t.logger.Warn("tcp: no original dst for flow; dropping",
			slog.String("src", src.String()))
		t.drop()
		client.Close()
		return
	}
	dst := joinAddr(dstIP, dstPort)
	upstream := t.dialTCPFlow(src.String(), dst)
	if upstream == nil {
		t.drop()
		client.Close()
		return
	}
	t.splice(client, upstream)
}

// dialTCPFlow runs the §6 fallback chain for one TCP flow (HOLD gate +
// primary endpoint, then the fallback). Returns nil when every path failed.
// Shared by the tproxy relay (handleTCP) and the wave-5c terminator
// (TCPDialer).
func (t *tunnel) dialTCPFlow(src string, dst netip.AddrPort) net.Conn {
	ctx, cancel := context.WithTimeout(ctxOrBackground(t.ctx), t.dialTimeout)
	defer cancel()
	var upstream net.Conn
	multi := len(t.tcpChain()) > 1
	for _, path := range t.dialOrder(dst) {
		if multi && path.paced && !t.takePathToken(path.name) {
			// Rate-limited this instant: overflow rides the next carrier
			// (wave 6: >3 rapid vless connections quarantine the
			// endpoint). Single-path plans never pace — nothing to
			// overflow to.
			continue
		}
		conn, err := path.c.dial(ctx, dst)
		if err != nil {
			t.logger.Warn("tcp: path dial failed",
				slog.String("path", path.name), slog.String("dst", dst.String()),
				slog.Any("err", err))
			t.markPathFailure(path.name)
			continue
		}
		t.markPathSuccess(path.name)
		upstream = conn
		break
	}
	if upstream == nil {
		t.logger.Warn("tcp: every tunnel path failed",
			slog.String("src", src), slog.String("dst", dst.String()))
		return nil
	}
	t.tcpFlows.Add(1)
	t.logger.Debug("tcp flow established",
		slog.String("src", src), slog.String("dst", dst.String()))
	return upstream
}

// dialOrder returns the TCP carrier chain in try order for dst: fallbacks
// first for TCPFallbackFirstCIDR destinations (wave-6: TG destinations
// poison the primary endpoint), with paths in known-failure cooldown moved
// after healthy ones (fast failover instead of a per-path dial timeout).
// Rate pacing (takePathToken) is applied by the dial loops when a paced
// path is about to be dialed.
func (t *tunnel) dialOrder(dst netip.AddrPort) []namedTCP {
	return t.orderedChain(false, dst)
}

// orderedChain is dialOrder generalized for the marker probe (domain dials
// never match CIDR rules).
func (t *tunnel) orderedChain(forDomain bool, dst netip.AddrPort) []namedTCP {
	chain := t.tcpChain()
	if len(chain) < 2 {
		// Single-path plan: pacing must not make the tunnel unusable.
		return chain
	}
	fbFirst := !forDomain && t.fallbackFirst(dst)
	// Preference order: [fallbacks..., primary] when the destination must
	// avoid the primary, else the configured order.
	idx := make([]int, 0, len(chain))
	if fbFirst {
		for i := 1; i < len(chain); i++ {
			idx = append(idx, i)
		}
		idx = append(idx, 0)
	} else {
		for i := range chain {
			idx = append(idx, i)
		}
	}
	now := time.Now()
	ready := make([]namedTCP, 0, len(chain))
	var cooled []namedTCP
	for _, i := range idx {
		p := chain[i]
		if now.Before(t.pathDownAt(p.name)) {
			cooled = append(cooled, p)
		} else {
			ready = append(ready, p)
		}
	}
	return append(ready, cooled...)
}

// path pacing (wave 6): the TSPU silently drops new SYNs to a vless
// endpoint after ~3 rapid connections (quarantine ~2-5 min, marker
// included). The token bucket keeps the dial rate under the observed
// threshold; overflow dials ride the (unpaced) hysteria2 carrier instead —
// hy2 multiplexes every stream over ONE QUIC association and is immune.
const (
	pathTokenRate  = 0.5 // sustained paced dials/second
	pathTokenBurst = 2   // rapid paced dials before pacing kicks in
)

func (t *tunnel) takePathToken(name string) bool {
	t.pathMu.Lock()
	defer t.pathMu.Unlock()
	if t.pathTokens == nil {
		t.pathTokens = map[string]*tokenBucket{}
	}
	b := t.pathTokens[name]
	if b == nil {
		b = &tokenBucket{tokens: pathTokenBurst, last: time.Now()}
		t.pathTokens[name] = b
	}
	now := time.Now()
	b.tokens += now.Sub(b.last).Seconds() * pathTokenRate
	if b.tokens > pathTokenBurst {
		b.tokens = pathTokenBurst
	}
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

type tokenBucket struct {
	tokens float64
	last   time.Time
}

// pathDownAt returns the cooldown deadline of a failed path (zero time when
// healthy).
func (t *tunnel) pathDownAt(name string) time.Time {
	t.pathMu.Lock()
	defer t.pathMu.Unlock()
	return t.pathDown[name]
}

// fallbackFirst reports whether dst matches a TCPFallbackFirstCIDRs prefix.
func (t *tunnel) fallbackFirst(dst netip.AddrPort) bool {
	for _, p := range t.opts.TCPFallbackFirstCIDRs {
		if p.Contains(dst.Addr()) {
			return true
		}
	}
	return false
}

// pathCooldown is how long a failed carrier is deprioritized (its SYNs to
// the VPS are being silently dropped — live finding wave 6: retrying into
// the quarantine only extends it).
const pathCooldown = 60 * time.Second

func (t *tunnel) markPathFailure(name string) {
	t.pathMu.Lock()
	if t.pathDown == nil {
		t.pathDown = map[string]time.Time{}
	}
	t.pathDown[name] = time.Now().Add(pathCooldown)
	t.pathMu.Unlock()
}

func (t *tunnel) markPathSuccess(name string) {
	t.pathMu.Lock()
	delete(t.pathDown, name)
	t.pathMu.Unlock()
}

func (t *tunnel) pathDownUntil(name string) (time.Time, bool) {
	t.pathMu.Lock()
	defer t.pathMu.Unlock()
	until, ok := t.pathDown[name]
	return until, ok
}

// TCPDialer exposes the §6 TCP carrier chain (HOLD gate + fallback) to the
// wave-5c userspace terminator.
func (t *tunnel) TCPDialer() func(ctx context.Context, dst string) (net.Conn, error) {
	return func(ctx context.Context, dst string) (net.Conn, error) {
		if t.held() && !t.opts.NoHoldFlows {
			return nil, errors.New("tunnel HELD: marker failing")
		}
		ap, err := netip.ParseAddrPort(dst)
		if err != nil {
			return nil, err
		}
		var c net.Conn
		multi := len(t.tcpChain()) > 1
		for _, path := range t.dialOrder(ap) {
			if multi && path.paced && !t.takePathToken(path.name) {
				continue // rate-limited: overflow rides the next carrier
			}
			conn, err := path.c.dial(ctx, ap)
			if err != nil {
				t.logger.Warn("term: path dial failed",
					slog.String("path", path.name), slog.String("dst", dst),
					slog.Any("err", err))
				t.markPathFailure(path.name)
				continue
			}
			t.markPathSuccess(path.name)
			c = conn
			break
		}
		if c == nil {
			return nil, errors.New("term: every tunnel path failed")
		}
		t.tcpFlows.Add(1)
		// Relay bytes through the terminator count into the tunnel rx/tx
		// counters (wave 6: the acceptance gates assert rx > 0 on the
		// full-engine TG loop, which rides this dialer).
		return &countingConn{Conn: c, rx: &t.rxBytes, tx: &t.txBytes}, nil
	}
}

// countingConn feeds the tunnel byte counters from a relayed carrier
// connection (terminator path — the tproxy splice counts in splice()).
type countingConn struct {
	net.Conn
	rx, tx *atomic.Uint64
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		c.rx.Add(uint64(n))
	}
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	if n > 0 {
		c.tx.Add(uint64(n))
	}
	return n, err
}

// drop counts one refused flow/datagram.
func (t *tunnel) drop() { t.dropped.Add(1) }

// splice copies both directions until either side closes.
func (t *tunnel) splice(a, b net.Conn) {
	defer t.tcpFlows.Add(-1)
	defer a.Close()
	defer b.Close()
	done := make(chan struct{}, 2)
	go func() {
		n, _ := io.Copy(b, a) //nolint:errcheck // best-effort relay
		t.txBytes.Add(uint64(n))
		b.SetDeadline(time.Now()) //nolint:errcheck // wake the other copier
		done <- struct{}{}
	}()
	n, _ := io.Copy(a, b) //nolint:errcheck // best-effort relay
	t.rxBytes.Add(uint64(n))
	a.SetDeadline(time.Now()) //nolint:errcheck // wake the other copier
	<-done
}

func splitAddr(addr net.Addr) ([16]byte, uint16, bool) {
	var ip [16]byte
	switch a := addr.(type) {
	case *net.TCPAddr:
		ip16 := a.IP.To16()
		if ip16 == nil {
			return ip, 0, false
		}
		copy(ip[:], ip16)
		return ip, uint16(a.Port), true
	case *net.UDPAddr:
		ip16 := a.IP.To16()
		if ip16 == nil {
			return ip, 0, false
		}
		copy(ip[:], ip16)
		return ip, uint16(a.Port), true
	default:
		return ip, 0, false
	}
}

func joinAddr(ip [16]byte, port uint16) netip.AddrPort {
	a := netip.AddrFrom16(ip)
	if a.Is4In6() {
		a = a.Unmap()
	}
	return netip.AddrPortFrom(a, port)
}

func ctxOrBackground(ctx context.Context) context.Context {
	if ctx == nil {
		return context.Background()
	}
	return ctx
}

// lookupOriginalDst consults the NAT provider; a nil provider drops the
// flow (documented Options behavior) instead of panicking.
func (t *tunnel) lookupOriginalDst(srcIP [16]byte, srcPort uint16) ([16]byte, uint16, bool) {
	if t.opts.OriginalDstProvider == nil {
		return [16]byte{}, 0, false
	}
	return t.opts.OriginalDstProvider.Lookup(srcIP, srcPort)
}
