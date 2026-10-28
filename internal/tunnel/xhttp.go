package tunnel

// Rupas' own VLESS+XHTTP client (wave 5). sing-box v1.14 has no XHTTP
// transport (it is an Xray-core transport), so vless_xhttp endpoints are
// carried here instead of by the embedded engine.
//
// Protocol (Xray XHTTP, mode packet-up — the most CDN-compatible mode and
// the user-configured one):
//
//	download: GET  https://host:port{path}/{session-uuid}
//	          → streaming body: [vless resp ver(1)][addon len(1)][addons?]data…
//	upload:   POST https://host:port{path}/{session-uuid}/{seq}
//	          → body: raw stream bytes; seq 0 is prefixed by the VLESS
//	            request header (ver, uuid, addon len, cmd, port, atyp, addr).
//
// The session UUID correlates the two directions (the server reaps
// uncorrelated sessions after 30 s). Every request pads with `x_padding=`
// (random length within the configured x_padding_bytes range) inside the
// Referer URL — xray v25.4.30 reads the padding length from the URL query
// or the Referer only, and silently zeroes a bare X-Padding header.
//
// Transport: uTLS (client fingerprint from the config, ALPN h2) and HTTP/2
// via x/net/http2 on the handshaked connection — the GET and the POSTs
// multiplex over one connection, mirroring Xray's xmux behavior.
// :authority/Host is the camouflage domain (xray's inbound host check 404s
// a raw IP authority).

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

const (
	// xhttpMaxPost is the payload cap per packet-up POST. The panel xray
	// inbound has scMaxEachPostBytes = 1000000; exceeding it is a 413.
	// (Live config 2026-10-26.)
	xhttpMaxPost = 1000 * 1000 // server default scMaxEachPostBytes = 1_000_000 bytes
	// xhttpInflight bounds the POSTs awaiting their (discarded) responses,
	// keeping HTTP/2 flow control and memory bounded.
	xhttpInflight = 8
	// xhttpSetupTimeout bounds the TCP+TLS+session setup.
	xhttpSetupTimeout = 20 * time.Second
)

// xhttpPath carries TCP streams over one vless_xhttp endpoint.
type xhttpPath struct {
	ep        config.Endpoint
	hostPort  string
	base      *url.URL // scheme://dialhost:port{path} (dial address only)
	authority string   // HTTP :authority/Host pin (see authorityHost)
	padLo     int
	padHi     int
	logger    *slog.Logger
}

// newXHTTPPath validates the endpoint shape and precomputes the session
// URL prefix.
func newXHTTPPath(ep config.Endpoint, logger *slog.Logger) (*xhttpPath, error) {
	if ep.Kind != config.KindVLESSXHTTP {
		return nil, fmt.Errorf("xhttp: kind %q is not vless_xhttp", ep.Kind)
	}
	if _, err := parseVLESSUUID(ep.UUID); err != nil {
		return nil, fmt.Errorf("xhttp: %v", err)
	}
	p := "/" + strings.Trim(ep.Path, "/")
	base := &url.URL{Scheme: "https", Host: net.JoinHostPort(ep.Host, strconv.Itoa(int(ep.Port))), Path: p}
	lo, hi, err := config.ParsePaddingRange(ep.XPadding)
	if err != nil || lo > hi {
		lo, hi = 100, 1000
	}
	return &xhttpPath{
		ep:        ep,
		hostPort:  base.Host,
		base:      base,
		authority: authorityHost(ep),
		padLo:     lo,
		padHi:     hi,
		logger:    logger,
	}, nil
}

// authorityHost returns the value for the HTTP :authority (and Host) header
// of every request. Xray's own xhttp client wires requestURL.Host to the
// xhttp "host" setting, falling back to the TLS serverName and only then to
// the dial address (splithttp dialer.go v25.4.30), and the inbound validates
// it against its own host setting with 404 on mismatch. A raw IP
// :authority is always rejected by the panel, so resolve the camouflage
// domain here instead. Priority: HTTPHost → SNI → dial host if it is a
// domain, else fall back to the URL authority (host:port).
func authorityHost(ep config.Endpoint) string {
	if domain(ep.HTTPHost) {
		return ep.HTTPHost
	}
	switch {
	case domain(ep.SNI):
		return ep.SNI
	case domain(ep.Host):
		return ep.Host
	}
	return ""
}

func domain(s string) bool {
	if s == "" {
		return false
	}
	if _, err := netip.ParseAddr(s); err == nil {
		return false // an IP address, not a domain
	}
	return true
}

// NewXHTTPDialer builds a standalone VLESS+XHTTP dialer from an endpoint
// description. It is the platform-neutral seam used by the mobile engine
// (internal/transport/android) to carry xhttp endpoints that sing-box
// v1.14 cannot; the desktop tunnel uses the same client internally.
func NewXHTTPDialer(ep config.Endpoint, logger *slog.Logger) (func(ctx context.Context, dst netip.AddrPort) (net.Conn, error), error) {
	p, err := newXHTTPPath(ep, logger)
	if err != nil {
		return nil, err
	}
	return p.dial, nil
}

// streamContext — контекст времени жизни потока: значения из родителя,
// но БЕЗ его отмены. Поток обязан пережить свой dial-ctx (tcpterm и probe
// отменяют его сразу после Connect), иначе все POST/GET умирают на старте.
func streamContext(ctx context.Context) (context.Context, context.CancelFunc) {
	return context.WithCancel(context.WithoutCancel(ctx))
}

func (p *xhttpPath) dial(ctx context.Context, dst netip.AddrPort) (net.Conn, error) {
	a := dst.Addr().Unmap()
	var atyp byte
	var addr []byte
	switch {
	case a.Is4():
		atyp = 0x01
		b4 := a.As4()
		addr = b4[:]
	default:
		atyp = 0x03
		b16 := a.As16()
		addr = b16[:]
	}
	return p.dialAddr(ctx, atyp, addr, dst.Port())
}

func (p *xhttpPath) dialHost(ctx context.Context, host string, port uint16) (net.Conn, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return p.dial(ctx, netip.AddrPortFrom(ip.Unmap(), port))
	}
	if len(host) > 255 {
		return nil, errors.New("xhttp: host name too long")
	}
	return p.dialAddr(ctx, 0x02, append([]byte{byte(len(host))}, host...), port)
}

// dialAddr opens one VLESS-over-XHTTP session toward atyp:addr:port.
func (p *xhttpPath) dialAddr(ctx context.Context, atyp byte, addr []byte, port uint16) (net.Conn, error) {
	dctx, cancel := context.WithTimeout(ctx, xhttpSetupTimeout)
	defer cancel()
	tconn, err := p.dialTLS(dctx)
	if err != nil {
		return nil, fmt.Errorf("xhttp: tls: %w", err)
	}
	cc, err := (&http2.Transport{}).NewClientConn(tconn)
	if err != nil {
		tconn.Close()
		return nil, fmt.Errorf("xhttp: h2 conn: %w", err)
	}
	sid, err := randomSessionID()
	if err != nil {
		tconn.Close()
		return nil, err
	}
	// ВАЖНО: поток живёт дольше своего dial. Вызывающий cancels dial-ctx
	// сразу после установления потока (tcpterm: defer cancel() после
	// dialWait; probe: dcancel() после Connect). Раньше sctx наследовал эту
	// отмену — и все POST/GET умирали через миг после старта: отправка
	// медиа замирала на середине, скачивание обрывалось. Значения из ctx
	// сохраняем, отмену — нет: поток закрывается своим Close().
	sctx, scancel := streamContext(ctx)
	c := &xhttpConn{
		path:   p,
		cc:     cc,
		tconn:  tconn,
		sid:    sid,
		sctx:   sctx,
		cancel: scancel,
		sem:    make(chan struct{}, xhttpInflight),
	}
	if err := c.start(atyp, addr, port); err != nil {
		c.Close()
		return nil, err
	}
	return c, nil
}

// dialTLS performs the uTLS handshake (fingerprint + ALPN, h2 required).
func (p *xhttpPath) dialTLS(ctx context.Context) (net.Conn, error) {
	d := net.Dialer{}
	raw, err := d.DialContext(ctx, "tcp", p.hostPort)
	if err != nil {
		return nil, err
	}
	cfg := &utls.Config{
		ServerName: p.ep.SNI,
		NextProtos: alpnOrDefault(p.ep.ALPN),
	}
	uconn := utls.UClient(raw, cfg, xhttpFingerprint(p.ep.Fingerprint))
	done := make(chan error, 1)
	go func() { done <- uconn.Handshake() }()
	select {
	case err := <-done:
		if err != nil {
			raw.Close()
			// Если сокет закрыли мы сами по ctx.Done, настоящая причина —
			// таймаут/отмена, а не "use of closed network connection":
			// именно эта строка уходила в UI профиля.
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return nil, err
		}
	case <-ctx.Done():
		raw.Close()
		return nil, ctx.Err()
	}
	if proto := uconn.ConnectionState().NegotiatedProtocol; proto != "h2" {
		uconn.Close()
		return nil, fmt.Errorf("xhttp: server negotiated ALPN %q, want h2", proto)
	}
	return uconn, nil
}

func alpnOrDefault(alpn []string) []string {
	if len(alpn) == 0 {
		return []string{"h2", "http/1.1"}
	}
	return alpn
}

// xhttpFingerprint maps the config fingerprint to a uTLS ClientHelloID.
func xhttpFingerprint(fp string) utls.ClientHelloID {
	switch strings.ToLower(strings.TrimSpace(fp)) {
	case "firefox":
		return utls.HelloFirefox_Auto
	case "safari":
		return utls.HelloSafari_16_0
	case "edge":
		return utls.HelloEdge_106
	case "ios":
		return utls.HelloIOS_Auto
	case "android":
		return utls.HelloAndroid_11_OkHttp
	case "random", "randomized":
		return utls.HelloRandomized
	default:
		return utls.HelloChrome_Auto
	}
}

// parseVLESSUUID parses the canonical 8-4-4-4-12 hex form into 16 bytes.
func parseVLESSUUID(s string) ([16]byte, error) {
	var id [16]byte
	hexs := strings.ReplaceAll(s, "-", "")
	if len(hexs) != 32 {
		return id, fmt.Errorf("bad uuid %q", s)
	}
	for i := 0; i < 16; i++ {
		v, err := strconv.ParseUint(hexs[i*2:i*2+2], 16, 8)
		if err != nil {
			return id, fmt.Errorf("bad uuid %q", s)
		}
		id[i] = byte(v)
	}
	return id, nil
}

// randomSessionID returns a fresh random v4 UUID string (XHTTP session id).
func randomSessionID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("xhttp: session id: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:16]), nil
}

// paddingLen is the random padding length within [padLo, padHi].
func (p *xhttpPath) paddingLen() int {
	lo, hi := p.padLo, p.padHi
	if hi < lo {
		lo, hi = hi, lo
	}
	n := lo
	if hi > lo {
		var b [1]byte
		if _, err := rand.Read(b[:]); err == nil {
			n = lo + int(b[0])%(hi-lo+1)
		}
	}
	return n
}

// paddingReferer mirrors Xray's client (config.go GetRequestHeader,
// v25.4.30): the padding is carried as the query of a Referer URL. The
// 'X' filler is HPACK/huffman-neutral on h2 (8-bit static-table code), so
// the on-wire padding length stays exact.
func (p *xhttpPath) paddingReferer(u *url.URL) string {
	padded := *u
	q := padded.Query()
	q.Set("x_padding", strings.Repeat("X", p.paddingLen()))
	padded.RawQuery = q.Encode()
	if p.authority != "" {
		padded.Host = p.authority
	}
	return padded.String()
}

// xhttpConn is one VLESS+XHTTP session as a net.Conn: writes become
// packet-up POSTs, reads drain the download GET body.
type xhttpConn struct {
	path   *xhttpPath
	cc     *http2.ClientConn
	tconn  net.Conn
	sid    string
	sctx   context.Context
	cancel context.CancelFunc

	sem       chan struct{} // bounds in-flight POSTs
	seq       atomic.Int64
	wg        sync.WaitGroup
	writeErr  error
	writeErrM sync.Mutex
	postFailN atomic.Int64  // failed packet-up POSTs (data loss events)
	closedCh  chan struct{} // test hook: closed when the stream is torn down
	closeOnce sync.Once     // Close is idempotent: a POST failure races the relay's own Close
	body      io.ReadCloser // download stream (VLESS response header skipped lazily)
	respGone  bool          // VLESS response header consumed
	pending   []byte        // VLESS request header, prepended to POST seq 0
}

// start opens the download GET (response headers only — data flows once
// the server sees the first upload POST) and stashes the VLESS request
// header for the first Write.
func (c *xhttpConn) start(atyp byte, addr []byte, port uint16) error {
	dlURL := c.path.base.JoinPath(c.sid).String()
	get, err := http.NewRequestWithContext(c.sctx, http.MethodGet, dlURL, nil)
	if err != nil {
		return err
	}
	// :authority must be the camouflage domain the inbound validates against.
	// Xray's host check compares the request authority with its xhttp "host"
	// config (404: "failed to validate host") — the dial address (an IP here)
	// does not pass. Bare-domain :authority is exactly what Xray's client
	// sends (requestURL.Host = targ config's host setting, no port).
	if c.path.authority != "" {
		get.Host = c.path.authority
	}
	// Xray v25.4.30 computes the padding length ONLY from the URL query or
	// the Referer query ("X-Padding" header lengths read as zero → 400).
	// Mirror the native client: Referer carries `?x_padding=` of 'X's.
	get.Header.Set("Referer", c.path.paddingReferer(c.path.base.JoinPath(c.sid)))
	resp, err := c.cc.RoundTrip(get)
	if err != nil {
		return fmt.Errorf("xhttp: download stream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return fmt.Errorf("xhttp: download stream status %d", resp.StatusCode)
	}
	uuid, _ := parseVLESSUUID(c.path.ep.UUID) // validated in newXHTTPPath
	hdr := make([]byte, 0, 24+len(addr))
	hdr = append(hdr, 0x00) // version
	hdr = append(hdr, uuid[:]...)
	hdr = append(hdr, 0x00) // addon length
	hdr = append(hdr, 0x01) // command: TCP
	hdr = binary.BigEndian.AppendUint16(hdr, port)
	hdr = append(hdr, atyp)
	hdr = append(hdr, addr...)
	c.body = resp.Body
	c.pending = hdr
	return nil
}

func (c *xhttpConn) Write(b []byte) (int, error) {
	c.writeErrM.Lock()
	err := c.writeErr
	c.writeErrM.Unlock()
	if err != nil {
		return 0, err
	}
	if c.sctx.Err() != nil {
		return 0, net.ErrClosed
	}
	total := len(b)
	for len(b) > 0 {
		n := len(b)
		if n > xhttpMaxPost {
			n = xhttpMaxPost
		}
		chunk := b[:n]
		b = b[n:]
		head := c.pending
		c.pending = nil
		if err := c.post(head, chunk); err != nil {
			c.setWriteErr(err)
			return 0, err
		}
	}
	return total, nil
}

// post sends one packet-up POST (seq increments per POST) and drains its
// response asynchronously under the in-flight semaphore.
func (c *xhttpConn) post(head, chunk []byte) error {
	seq := c.seq.Add(1) - 1
	u := c.path.base.JoinPath(c.sid, strconv.FormatInt(seq, 10)).String()
	body := append(head, chunk...)
	req, err := http.NewRequestWithContext(c.sctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return err
	}
	// :authority — same host pin as the GET (xray's host check applies to
	// every packet-up POST independently).
	if c.path.authority != "" {
		req.Host = c.path.authority
	}
	req.Header.Set("Referer", c.path.paddingReferer(c.path.base.JoinPath(c.sid, strconv.FormatInt(seq, 10))))
	req.ContentLength = int64(len(body))
	// Bound in-flight POSTs; a full semaphore means the server is not
	// draining — surface as a write error after a bounded wait.
	select {
	case c.sem <- struct{}{}:
	case <-c.sctx.Done():
		return net.ErrClosed
	case <-time.After(xhttpSetupTimeout):
		return errors.New("xhttp: too many in-flight posts")
	}
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		defer func() { <-c.sem }()
		resp, err := c.cc.RoundTrip(req)
		if err != nil {
			c.setWriteErr(err)
			return
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck // packet-up responses carry no data
		resp.Body.Close()              //nolint:errcheck
	}()
	return nil
}

// Read drains the download stream, lazily skipping the VLESS response
// header (present only after the server processed the first upload POST).
func (c *xhttpConn) Read(b []byte) (int, error) {
	if !c.respGone {
		var h [2]byte
		if _, err := io.ReadFull(c.body, h[:]); err != nil {
			return 0, fmt.Errorf("xhttp: vless response header: %w", err)
		}
		if h[0] != 0x00 {
			return 0, fmt.Errorf("xhttp: unexpected vless response version %d", h[0])
		}
		if n := int(h[1]); n > 0 {
			addon := make([]byte, n)
			if _, err := io.ReadFull(c.body, addon); err != nil {
				return 0, fmt.Errorf("xhttp: vless response addons: %w", err)
			}
		}
		c.respGone = true
	}
	return c.body.Read(b)
}

func (c *xhttpConn) Close() error {
	c.closeOnce.Do(func() {
		c.cancel()
		if c.tconn != nil {
			c.tconn.Close() //nolint:errcheck // best-effort teardown
		}
		c.wg.Wait()
		if c.body != nil {
			c.body.Close() //nolint:errcheck
		}
	})
	return nil
}

func (c *xhttpConn) LocalAddr() net.Addr  { return c.tconn.LocalAddr() }
func (c *xhttpConn) RemoteAddr() net.Addr { return c.tconn.RemoteAddr() }

func (c *xhttpConn) SetDeadline(t time.Time) error      { return c.tconn.SetDeadline(t) }
func (c *xhttpConn) SetReadDeadline(t time.Time) error  { return c.tconn.SetReadDeadline(t) }
func (c *xhttpConn) SetWriteDeadline(t time.Time) error { return c.tconn.SetWriteDeadline(t) }

func (c *xhttpConn) setWriteErr(err error) {
	c.writeErrM.Lock()
	first := c.writeErr == nil
	if first {
		c.writeErr = err
	}
	c.writeErrM.Unlock()
	if !first {
		return
	}
	// A failed packet-up POST means bytes the client already got an ACK for
	// will never reach the server. Waiting for the next Write to notice is a
	// silent hang: an idle upload (Telegram waiting for its own ack) simply
	// never writes again. Tear the stream down NOW so the TCP terminator
	// RSTs the client and the application-level retry happens.
	c.postFailN.Add(1)
	go c.cancelAndClose()
}

// cancelAndClose aborts the stream once: cancel makes every in-flight
// request and blocked Read return, Close waits for the POST goroutines.
func (c *xhttpConn) cancelAndClose() {
	if c.closedCh != nil {
		close(c.closedCh)
	}
	c.cancel()
	_ = c.Close()
}
