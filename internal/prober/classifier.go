// Package prober classifies the censorship behaviour of the network path
// (SYSTEM_DESIGN.md §7): SNI blackholes, RST injection, IP blackholes and
// dead UDP ports, plus binary-search calibration of the fake-packet TTL
// used by the desync engine. All network effects sit behind small
// interfaces (Transport, FakeInjector) so the algorithms run unchanged
// against the local TSPU emulator (tspu_sim_test.go) without Internet
// access. Probes always speak a browser-like ClientHello via uTLS
// (ADR-7: a "thin" Go CH yields false calibration results).
package prober

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	utls "github.com/refraction-networking/utls"
)

// IPVerdict is the outcome of a TCP reachability probe (§7.1 step 1).
type IPVerdict uint8

const (
	// IPUnknown means the probe was inconclusive (e.g. connection refused
	// or another non-timeout error): no evidence of a blackhole.
	IPUnknown IPVerdict = iota
	// IPOpen means SYN/ACK came back: the IP is not blackholed.
	IPOpen
	// IPSynDrop means no SYN/ACK within the deadline on every attempt:
	// IP blackhole (lab: Telegram DCs drop SYNs on all ports).
	IPSynDrop
)

// String returns the canonical verdict name used in diag output.
func (v IPVerdict) String() string {
	switch v {
	case IPOpen:
		return "OPEN"
	case IPSynDrop:
		return "SYN_DROP"
	default:
		return "UNKNOWN"
	}
}

// SNIVerdict is the outcome of a browser-like TLS probe (§7.1 steps 2-5).
type SNIVerdict uint8

const (
	// SNIUnknown means the TCP session never established (see ProbeIP) or
	// the attempts were inconclusive.
	SNIUnknown SNIVerdict = iota
	// SNIOpen means the TLS handshake completed against ip with sni.
	SNIOpen
	// SNIDrop means every attempt timed out waiting for a response after
	// the ClientHello: the TSPU silently blackholes the flow (lab fact:
	// timeout after CH for blocked SNI, IP itself reachable).
	SNIDrop
	// SNIRSTInject means the flow was abruptly reset (RST or close)
	// immediately after the ClientHello — far sooner than a server-side
	// answer could arrive (§7.1 step 3: RST faster than server RTT).
	SNIRSTInject
)

// String returns the canonical verdict name used in diag output.
func (v SNIVerdict) String() string {
	switch v {
	case SNIOpen:
		return "OPEN"
	case SNIDrop:
		return "SNI_DROP"
	case SNIRSTInject:
		return "RST_INJECT"
	default:
		return "UNKNOWN"
	}
}

// Conn is the connection a Transport hands to the TLS layer.
type Conn = net.Conn

// Transport abstracts TCP establishment so the classifier can be driven
// against mocks and the local TSPU emulator.
type Transport interface {
	Dial(ip string, port uint16) (Conn, error)
}

// DefaultDialTimeout matches the lab probes (tspr_probe.py: 3.5-5 s).
const DefaultDialTimeout = 4 * time.Second

// RealTransport is the production Transport: a plain net.Dialer with a
// 4 s timeout, no proxy, no keep-alives.
type RealTransport struct {
	// Timeout overrides DefaultDialTimeout when positive.
	Timeout time.Duration
}

// Dial establishes a TCP connection to ip:port.
func (t *RealTransport) Dial(ip string, port uint16) (Conn, error) {
	d := net.Dialer{Timeout: DefaultDialTimeout}
	if t.Timeout > 0 {
		d.Timeout = t.Timeout
	}
	return d.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(int(port))))
}

// Default probe parameters (lab: 3 attempts per target, 0.3 s apart).
const (
	DefaultAttempts         = 3
	DefaultAttemptDelay     = 300 * time.Millisecond
	DefaultHandshakeTimeout = 5 * time.Second
	DefaultUDPTimeout       = 3 * time.Second
	DefaultUDPAttempts      = 2
	DefaultTLSPort          = 443
)

// stunBindingRequest is the RFC 5389 binding request used by the lab UDP
// probes (tspr_probe.py): type 0x0001, empty length, magic cookie, txid.
var stunBindingRequest = []byte{
	0x00, 0x01, 0x00, 0x00, // type=Binding, len=0
	0x21, 0x12, 0xa4, 0x42, // magic cookie
	0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
}

// Classifier probes a network path and classifies TSPU behaviour
// (SYSTEM_DESIGN §7.1). The zero value is not usable; construct with
// NewClassifier and override timing fields for tests.
type Classifier struct {
	// Transport establishes TCP connections (RealTransport in production).
	Transport Transport
	// ClientHelloID is the uTLS fingerprint of probe ClientHellos.
	// Zero value means utls.HelloChrome_Auto (browser-like, ADR-7).
	ClientHelloID utls.ClientHelloID
	// TLSPort is the port SNI probes connect to (default 443).
	TLSPort uint16
	// HandshakeTimeout bounds one CH→ServerHello round (default 5 s).
	HandshakeTimeout time.Duration
	// Attempts is the number of probes per target (default 3: lab "3×").
	Attempts int
	// AttemptDelay paces retries (default 300 ms, lab: time.sleep(0.3)).
	AttemptDelay time.Duration
	// UDPTimeout bounds one UDP wait (default 3 s).
	UDPTimeout time.Duration
	// UDPAttempts is the number of UDP probes per target (default 2).
	UDPAttempts int
	// UDPPayload is sent by ProbeUDP; nil means the STUN binding request.
	UDPPayload []byte
	// LocalIP binds UDP probe sockets to a source address (the physical
	// NIC, see bind.go) so UDP classification follows the same path as
	// the TCP probes. Nil → default route.
	LocalIP net.IP
}

// NewClassifier returns a Classifier with lab-derived defaults.
func NewClassifier(t Transport) *Classifier {
	return &Classifier{
		Transport:        t,
		ClientHelloID:    utls.HelloChrome_Auto,
		TLSPort:          DefaultTLSPort,
		HandshakeTimeout: DefaultHandshakeTimeout,
		Attempts:         DefaultAttempts,
		AttemptDelay:     DefaultAttemptDelay,
		UDPTimeout:       DefaultUDPTimeout,
		UDPAttempts:      DefaultUDPAttempts,
		UDPPayload:       append([]byte(nil), stunBindingRequest...),
	}
}

func (c *Classifier) attempts() int {
	if c.Attempts > 0 {
		return c.Attempts
	}
	return DefaultAttempts
}

func (c *Classifier) attemptDelay() time.Duration {
	if c.AttemptDelay > 0 {
		return c.AttemptDelay
	}
	return 0
}

func (c *Classifier) handshakeTimeout() time.Duration {
	if c.HandshakeTimeout > 0 {
		return c.HandshakeTimeout
	}
	return DefaultHandshakeTimeout
}

func (c *Classifier) tlsPort() uint16 {
	if c.TLSPort != 0 {
		return c.TLSPort
	}
	return DefaultTLSPort
}

func (c *Classifier) udpAttempts() int {
	if c.UDPAttempts > 0 {
		return c.UDPAttempts
	}
	return DefaultUDPAttempts
}

func (c *Classifier) udpTimeout() time.Duration {
	if c.UDPTimeout > 0 {
		return c.UDPTimeout
	}
	return DefaultUDPTimeout
}

func (c *Classifier) helloID() utls.ClientHelloID {
	if c.ClientHelloID != (utls.ClientHelloID{}) {
		return c.ClientHelloID
	}
	return utls.HelloChrome_Auto
}

// ProbeIP reports whether TCP connections to ip:port complete (§7.1
// step 1: no SYN/ACK 3× ⇒ IP_BLACKHOLE). Only deadline expiry counts as
// evidence of a blackhole; refusals and other errors yield IPUnknown.
func (c *Classifier) ProbeIP(ip string, port uint16) IPVerdict {
	timeoutOnly := true
	for i := 0; i < c.attempts(); i++ {
		conn, err := c.Transport.Dial(ip, port)
		if err == nil {
			conn.Close()
			return IPOpen
		}
		if !isTimeoutErr(err) {
			timeoutOnly = false
		}
		if i < c.attempts()-1 {
			time.Sleep(c.attemptDelay())
		}
	}
	if timeoutOnly {
		return IPSynDrop
	}
	return IPUnknown
}

// SNIAttempt records one TLS probe round (for diagnostics and tests).
type SNIAttempt struct {
	// DialErr is the TCP establishment error, if any ("" on success).
	DialErr string
	// HandshakeErr is the TLS handshake error, if any ("" on success).
	HandshakeErr string
	// ConnectRTT is the TCP connect duration (RTT baseline for the
	// reset-faster-than-server test, §7.1 step 3).
	ConnectRTT time.Duration
	// Elapsed is the total time from dial start to handshake outcome.
	Elapsed time.Duration
	// Timeout marks deadline-expired failures.
	Timeout bool
	// Reset marks abrupt-reset/close failures.
	Reset bool
}

// SNIReport is the full outcome of ProbeSNI: verdict plus per-attempt
// evidence with timings (сравни время до ошибки).
type SNIReport struct {
	Verdict  SNIVerdict
	Attempts []SNIAttempt
}

// ProbeSNI classifies how the path treats a browser-like TLS handshake
// with the given server name towards ip (§7.1 steps 2-5):
//
//	handshake ok          → SNIOpen
//	timeout after CH, 3×  → SNIDrop   (silent SNI blackhole)
//	abrupt reset after CH → SNIRSTInject (faster than a server answer)
//	TCP never established → SNIUnknown (classify the IP first)
func (c *Classifier) ProbeSNI(ip, sni string) SNIVerdict {
	return c.ProbeSNIContext(context.Background(), ip, sni).Verdict
}

// ProbeSNIContext is ProbeSNI with cancellation between attempts and a
// full evidence report.
func (c *Classifier) ProbeSNIContext(ctx context.Context, ip, sni string) SNIReport {
	rep := SNIReport{Verdict: SNIUnknown}
	timeouts, resets, dialFails := 0, 0, 0
	attempts := c.attempts()
	for i := 0; i < attempts; i++ {
		if err := ctx.Err(); err != nil {
			break
		}
		a := SNIAttempt{}
		t0 := time.Now()
		conn, err := c.Transport.Dial(ip, c.tlsPort())
		a.ConnectRTT = time.Since(t0)
		if err != nil {
			a.DialErr = err.Error()
			a.Timeout = isTimeoutErr(err)
			rep.Attempts = append(rep.Attempts, a)
			dialFails++
		} else if hsErr := c.handshake(ctx, conn, sni); hsErr == nil {
			conn.Close()
			a.Elapsed = time.Since(t0)
			rep.Attempts = append(rep.Attempts, a)
			rep.Verdict = SNIOpen
			return rep
		} else {
			a.Elapsed = time.Since(t0)
			a.HandshakeErr = hsErr.Error()
			// A reset that fires well before the deadline — typically far
			// below one server RTT — is injected, not server-originated.
			a.Timeout = isTimeoutErr(hsErr)
			a.Reset = !a.Timeout && isResetErr(hsErr) && a.Elapsed < c.handshakeTimeout()
			rep.Attempts = append(rep.Attempts, a)
			if a.Timeout {
				timeouts++
			} else if a.Reset {
				resets++
			}
		}
		if i < attempts-1 {
			time.Sleep(c.attemptDelay())
		}
	}
	tlsAttempts := attempts - dialFails
	switch {
	case dialFails == attempts:
		rep.Verdict = SNIUnknown // TCP dead: classify with ProbeIP
	case timeouts == tlsAttempts && tlsAttempts > 0:
		rep.Verdict = SNIDrop
	case resets > 0 && timeouts < tlsAttempts:
		rep.Verdict = SNIRSTInject
	default:
		rep.Verdict = SNIUnknown
	}
	return rep
}

// handshake performs the browser-like TLS handshake over conn with the
// configured uTLS fingerprint (ADR-7) and the per-attempt deadline.
func (c *Classifier) handshake(ctx context.Context, conn Conn, sni string) error {
	cfg := &utls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true, // probes classify the path, not the server
	}
	uconn := utls.UClient(conn, cfg, c.helloID())
	deadline := time.Now().Add(c.handshakeTimeout())
	_ = uconn.SetDeadline(deadline)
	hctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	return uconn.HandshakeContext(hctx)
}

// ProbeUDP sends STUN binding requests (lab payload) to ip:port and
// reports whether any response arrives within the deadline. A connected
// UDP socket that receives an ICMP port-unreachable counts as alive:
// the packet was delivered (lab tspr_probe.py: ICMP ⇒ delivered).
func (c *Classifier) ProbeUDP(ip string, port uint16) bool {
	for i := 0; i < c.udpAttempts(); i++ {
		if c.udpOnce(ip, port) {
			return true
		}
	}
	return false
}

func (c *Classifier) udpOnce(ip string, port uint16) bool {
	var d net.Dialer
	if c.LocalIP != nil {
		d.LocalAddr = &net.UDPAddr{IP: c.LocalIP}
	}
	conn, err := d.Dial("udp", net.JoinHostPort(ip, strconv.Itoa(int(port))))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.udpTimeout()))
	payload := c.UDPPayload
	if len(payload) == 0 {
		payload = stunBindingRequest
	}
	if _, err := conn.Write(payload); err != nil {
		return false
	}
	buf := make([]byte, 256)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			// WSAECONNRESET on a connected UDP socket is the ICMP
			// port-unreachable reaction: the packet did traverse.
			return isResetErr(err)
		}
		if n > 0 {
			return true
		}
	}
}

// runParallel runs jobs with at most limit concurrently — an
// errgroup-style fan-out on plain goroutines (stdlib only). Each job is
// expected to be self-contained; panics propagate normally.
func runParallel(limit int, jobs ...func()) {
	if len(jobs) == 0 {
		return
	}
	if limit < 1 {
		limit = 1
	}
	sem := make(chan struct{}, limit)
	var wg sync.WaitGroup
	for _, job := range jobs {
		wg.Add(1)
		sem <- struct{}{} // blocks until a slot frees up
		go func(job func()) {
			defer wg.Done()
			defer func() { <-sem }()
			job()
		}(job)
	}
	wg.Wait()
}

// isTimeoutErr reports whether err is a deadline expiry (dial timeout,
// I/O deadline, context deadline).
func isTimeoutErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var ne net.Error
	return errors.As(err, &ne) && ne.Timeout()
}

// isResetErr reports whether err is an abrupt reset or close by the peer
// (RST / EPIPE / EOF) rather than a timeout. String matching covers
// platform errno translation quirks: on Windows the poll layer surfaces
// WSAECONNRESET as "wsarecv: An existing connection was forcibly closed
// by the remote host", which is not equal to syscall.ECONNRESET.
func isResetErr(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, syscall.ECONNRESET) || errors.Is(err, syscall.EPIPE) {
		return true
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "reset") ||
		strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "forcibly closed")
}
