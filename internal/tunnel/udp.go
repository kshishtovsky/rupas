package tunnel

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"
)

// udpTable maps client src 4-tuples (as seen by the tproxy UDP listener,
// i.e. after the capture-layer NAT rewrote the packet dst) to UDP
// pseudo-sessions (§3.3: "UDP Discord … тот же NAT → tun-core,
// XUDP-инкапсуляция"). Sessions idle for t.udpTimeout are closed.
type udpTable struct {
	t  *tunnel
	mu sync.Mutex
	m  map[netip.AddrPort]*udpSession
}

func newUDPTable(t *tunnel) *udpTable {
	return &udpTable{t: t, m: make(map[netip.AddrPort]*udpSession)}
}

type udpSession struct {
	table      *udpTable
	client     netip.AddrPort
	dst        netip.AddrPort
	relay      packetRelay
	timer      *time.Timer
	lastActive time.Time
	closed     *sync.Once
}

func (s *udpSession) touch() {
	s.table.mu.Lock()
	defer s.table.mu.Unlock()
	s.lastActive = time.Now()
	if s.timer != nil {
		s.timer.Reset(s.table.t.udpTimeout)
	}
}

func (s *udpSession) close() {
	s.closed.Do(func() {
		s.table.mu.Lock()
		if s.timer != nil {
			s.timer.Stop()
		}
		if s.table.m[s.client] == s {
			delete(s.table.m, s.client)
		}
		s.table.mu.Unlock()
		s.relay.close()
	})
}

// udpLoop reads client datagrams from the tproxy listener forever.
func (t *tunnel) udpLoop() {
	defer t.wg.Done()
	buf := make([]byte, maxUDPFrame)
	for {
		n, src, err := t.udpConn.ReadFromUDP(buf)
		if err != nil {
			if !t.stopped.Load() {
				t.logger.Error("udp read failed", slog.Any("err", err))
			}
			return
		}
		if t.stopped.Load() {
			return
		}
		payload := make([]byte, n)
		copy(payload, buf[:n])
		t.handleUDPPacket(src, payload)
	}
}

// handleUDPPacket routes one datagram through an existing or new session.
func (t *tunnel) handleUDPPacket(src *net.UDPAddr, payload []byte) {
	t.udpDgrams.Add(1)
	srcIP, srcPort, ok := splitAddr(src)
	if !ok {
		return
	}
	key := joinAddr(srcIP, srcPort)

	t.sessions.mu.Lock()
	sess, ok := t.sessions.m[key]
	t.sessions.mu.Unlock()
	if ok {
		if err := sess.relay.send(sess.dst, payload); err != nil {
			t.logger.Warn("udp: relay send failed",
				slog.String("src", key.String()), slog.Any("err", err))
			t.drop()
			sess.close()
		} else {
			t.txBytes.Add(uint64(len(payload)))
			sess.touch()
		}
		return
	}

	// HOLD (§6): marker failed 3× — refuse new pseudo-sessions with a
	// counter instead of relaying into a dead tunnel.
	if t.held() {
		t.logger.Warn("udp: tunnel HELD, dropping datagram",
			slog.String("src", key.String()),
			slog.Int("fail_streak", int(t.failStreak.Load())))
		t.drop()
		return
	}

	// New pseudo-session: resolve the original destination via the NAT.
	dstIP, dstPort, ok := t.lookupOriginalDst(srcIP, srcPort)
	if !ok {
		t.logger.Warn("udp: no original dst for flow; dropping",
			slog.String("src", key.String()))
		t.drop()
		return
	}
	dst := joinAddr(dstIP, dstPort)
	path := t.activeUDPPath()
	if path.c == nil {
		t.logger.Warn("udp: no UDP carrier available",
			slog.String("src", key.String()))
		t.drop()
		return
	}
	ctx, cancel := context.WithTimeout(ctxOrBackground(t.ctx), t.dialTimeout)
	relay, err := path.c.udpAssociate(ctx)
	cancel()
	if err != nil {
		t.logger.Warn("udp: associate failed",
			slog.String("path", path.name),
			slog.String("src", key.String()), slog.Any("err", err))
		t.drop()
		return
	}
	sess = &udpSession{
		table:      t.sessions,
		client:     key,
		dst:        dst,
		relay:      relay,
		lastActive: time.Now(),
		closed:     &sync.Once{},
	}
	t.sessions.mu.Lock()
	if t.sessions.m[key] != nil { // lost a race with a concurrent session
		t.sessions.mu.Unlock()
		relay.close()
		return
	}
	t.sessions.m[key] = sess
	sess.timer = time.AfterFunc(t.udpTimeout, sess.close)
	t.sessions.mu.Unlock()

	t.logger.Debug("udp session established",
		slog.String("src", key.String()), slog.String("dst", dst.String()))

	// Reply pump: relay → tproxy listener → client.
	go func() {
		buf := make([]byte, maxUDPFrame)
		for {
			_, payload, err := relay.receive(buf)
			if err != nil {
				sess.close()
				return
			}
			if len(payload) == 0 {
				continue // associate ack / keepalive frame
			}
			reply := make([]byte, len(payload))
			copy(reply, payload)
			if _, err := t.udpConn.WriteToUDPAddrPort(reply, key); err != nil {
				sess.close()
				return
			}
			t.rxBytes.Add(uint64(len(reply)))
			sess.touch()
		}
	}()

	if err := relay.send(dst, payload); err != nil {
		t.logger.Warn("udp: first relay send failed",
			slog.String("src", key.String()), slog.Any("err", err))
		t.drop()
		sess.close()
	} else {
		t.txBytes.Add(uint64(len(payload)))
	}
}

func (tab *udpTable) closeAll() {
	tab.mu.Lock()
	sessions := make([]*udpSession, 0, len(tab.m))
	for _, s := range tab.m {
		sessions = append(sessions, s)
	}
	tab.mu.Unlock()
	for _, s := range sessions {
		s.close()
	}
}

// len reports the number of live sessions (tests).
func (tab *udpTable) len() int {
	tab.mu.Lock()
	defer tab.mu.Unlock()
	return len(tab.m)
}
