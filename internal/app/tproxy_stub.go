package app

import (
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"sync/atomic"
)

// DefaultTProxyPort is the loopback port TUNNEL-verdict flows are
// NAT-redirected to (SYSTEM_DESIGN §3.3). It deliberately sits outside
// 443 and the [50000,65535] UDP relay range the capture filter claims.
const DefaultTProxyPort uint16 = 12713

// TProxyStub is the wave-3 stand-in for the sing-box tproxy inbound: it
// accepts NAT-redirected flows, counts them, logs honestly that the real
// tunnel core lands in wave 4 and closes. Without it TUNNEL-verdict
// flows would be NAT'd to a dead loopback port and hang silently.
//
// It listens on both TCP and UDP on the same port: the capture NAT branch
// redirects Telegram TCP and Discord-relay UDP alike (§3.3).
type TProxyStub struct {
	ln     net.Listener
	pc     *net.UDPConn
	conns  atomic.Int64
	dgrams atomic.Int64
	log    *log.Logger
	once   sync.Once
}

// StartTProxyStub brings the stub listener up. port 0 asks the system for
// an ephemeral TCP port (used by tests; the UDP side gets its own
// ephemeral port then).
func StartTProxyStub(port uint16, logger *log.Logger) (*TProxyStub, error) {
	if logger == nil {
		logger = log.New(io.Discard, "", 0)
	}
	ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return nil, fmt.Errorf("tproxy stub: listen tcp 127.0.0.1:%d: %w", port, err)
	}
	pc, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)})
	if err != nil {
		ln.Close()
		return nil, fmt.Errorf("tproxy stub: listen udp 127.0.0.1:%d: %w", port, err)
	}
	s := &TProxyStub{ln: ln, pc: pc, log: logger}
	logger.Printf("tproxy stub: listening on 127.0.0.1:%d (tcp+udp); the real tunnel inbound lands in wave 4", port)
	go s.acceptLoop()
	go s.udpLoop()
	return s, nil
}

func (s *TProxyStub) acceptLoop() {
	for {
		c, err := s.ln.Accept()
		if err != nil {
			return
		}
		n := s.conns.Add(1)
		if n <= 3 || n%50 == 0 {
			s.log.Printf("tproxy stub: flow #%d redirected here; dropped (tunnel core comes in wave 4)", n)
		}
		c.Close()
	}
}

func (s *TProxyStub) udpLoop() {
	buf := make([]byte, 2048)
	for {
		if _, _, err := s.pc.ReadFrom(buf); err != nil {
			return
		}
		n := s.dgrams.Add(1)
		if n <= 3 || n%100 == 0 {
			s.log.Printf("tproxy stub: datagram #%d relayed here; dropped (tunnel core comes in wave 4)", n)
		}
	}
}

// Stop closes both listeners. Idempotent.
func (s *TProxyStub) Stop() {
	s.once.Do(func() {
		s.ln.Close()
		s.pc.Close()
	})
}

// Conns reports how many TCP flows were NAT-redirected here.
func (s *TProxyStub) Conns() int64 { return s.conns.Load() }

// Dgrams reports how many UDP datagrams were NAT-redirected here.
func (s *TProxyStub) Dgrams() int64 { return s.dgrams.Load() }

// TCPPort returns the actual TCP port (differs from the request when 0).
func (s *TProxyStub) TCPPort() uint16 {
	if ta, ok := s.ln.Addr().(*net.TCPAddr); ok {
		return uint16(ta.Port)
	}
	return 0
}

// UDPPort returns the actual UDP port (differs from the request when 0).
func (s *TProxyStub) UDPPort() uint16 {
	if ua, ok := s.pc.LocalAddr().(*net.UDPAddr); ok {
		return uint16(ua.Port)
	}
	return 0
}
