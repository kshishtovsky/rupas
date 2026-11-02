package tunnel

// UDP flows over TMN/1. tuman v0.2.0 gave the protocol datagrams: a UDP
// pseudo-session is a mux stream opened with FlagUDP, and each datagram
// travels as "u16 length + payload". One stream per destination — the exit
// keeps one real UDP socket per target, so mixing targets in one stream
// would need per-datagram addressing that the frame format does not carry.
//
// Why this matters: before, a tmn-only profile carried voice and QUIC
// nowhere, and those flows fell through to direct (or died). The xudp
// fallback needs a VLESS outbound, which a tmn-only profile does not have.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/kshishtovsky/tuman/mux"
)

const (
	// tmnMaxDatagram matches the server's limit: a larger frame tears the
	// stream (the exit refuses it), so the carrier rejects it up front with a
	// clear error instead.
	tmnMaxDatagram = 8 << 10
	// tmnUDPDest caps concurrent destinations in one association. QUIC web
	// browsing opens a handful; the cap only stops a scanner (or a broken
	// client) from turning one association into thousands of streams.
	tmnUDPDest = 64
	// tmnUDPIdle closes a destination the app stopped using: the exit holds a
	// real socket (and a conntrack entry) for every one of them.
	tmnUDPIdle = 60 * time.Second
	// tmnUDPDialTimeout bounds opening one destination stream (a cold pool
	// dials a session, which is a full TLS handshake behind a cover request).
	tmnUDPDialTimeout = 20 * time.Second
	// tmnUDPReap is how often the reaper looks for idle destinations.
	tmnUDPReap = 15 * time.Second
	// tmnUDPQueue is the receive queue: datagrams from every destination land
	// here and receive() drains it.
	tmnUDPQueue = 256
)

var errTMNUDPTooBig = errors.New("tmn: datagram larger than 8 KiB")

// tmnDest is one destination: its stream and the last time it was used.
type tmnDest struct {
	st   *mux.Stream
	last atomic.Int64 // unix nanos
}

// dgram is one received datagram with its source.
type dgram struct {
	src  netip.AddrPort
	data []byte
}

// udpAssociate opens one association (one relay object). Destinations are
// created lazily on the first send.
func (p *tmnPath) udpAssociate(ctx context.Context) (packetRelay, error) {
	r := &tmnRelay{
		c:    p.c,
		in:   make(chan dgram, tmnUDPQueue),
		dest: make(map[netip.AddrPort]*tmnDest),
	}
	// ctx here is dial-scoped: the engine cancels it right after the call
	// returns (tunnel/udp.go), so inheriting it would kill the association
	// before the first datagram. The relay lives until close().
	r.ctx, r.cancel = context.WithCancel(context.WithoutCancel(ctx))
	go r.reap()
	return r, nil
}

type tmnRelay struct {
	c      tmUDPClient
	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	dest   map[netip.AddrPort]*tmnDest
	closed atomic.Bool

	in chan dgram
	wg sync.WaitGroup
}

// tmUDPClient is the slice of *client.Client the relay needs; a test seam.
type tmUDPClient interface {
	OpenUDP(ctx context.Context, host, port string) (*mux.Stream, error)
}

func (r *tmnRelay) send(dst netip.AddrPort, payload []byte) error {
	if r.closed.Load() {
		return errTMNClosed
	}
	if len(payload) > tmnMaxDatagram {
		return errTMNUDPTooBig
	}
	d, err := r.destFor(dst)
	if err != nil {
		return err
	}
	d.last.Store(time.Now().UnixNano())
	var h [2]byte
	binary.BigEndian.PutUint16(h[:], uint16(len(payload)))
	// One write for the frame: two writes on a stream with a window can cost
	// an extra round trip per datagram (Nagle is off inside mux).
	frame := make([]byte, 2+len(payload))
	copy(frame[:2], h[:])
	copy(frame[2:], payload)
	if _, err := d.st.Write(frame); err != nil {
		r.drop(dst)
		return fmt.Errorf("tmn: udp send: %w", err)
	}
	return nil
}

// destFor returns the stream for dst, creating it (and its reader) once.
func (r *tmnRelay) destFor(dst netip.AddrPort) (*tmnDest, error) {
	r.mu.Lock()
	if d, ok := r.dest[dst]; ok {
		r.mu.Unlock()
		return d, nil
	}
	if len(r.dest) >= tmnUDPDest {
		// Evict the least recently used destination instead of failing the
		// new one: a burst of new targets must not break a working flow.
		var victim netip.AddrPort
		oldest := int64(1<<63 - 1)
		for a, d := range r.dest {
			if l := d.last.Load(); l < oldest {
				oldest, victim = l, a
			}
		}
		if d, ok := r.dest[victim]; ok {
			delete(r.dest, victim)
			d.st.Close()
		}
	}
	r.mu.Unlock()

	// Open outside the lock: a cold pool blocks here for seconds, so the
	// caller's send is not held by the mutex. The deadline is per stream: a
	// dead endpoint must fail this destination, not the whole association.
	openCtx, cancel := context.WithTimeout(r.ctx, tmnUDPDialTimeout)
	st, err := r.c.OpenUDP(openCtx, dst.Addr().Unmap().String(), strconv.Itoa(int(dst.Port())))
	cancel()
	if err != nil {
		return nil, fmt.Errorf("tmn: udp open: %w", err)
	}
	d := &tmnDest{st: st}
	d.last.Store(time.Now().UnixNano())

	r.mu.Lock()
	if r.closed.Load() {
		r.mu.Unlock()
		st.Close()
		return nil, errTMNClosed
	}
	// Another sender may have won the race: keep one stream, drop ours.
	if prev, ok := r.dest[dst]; ok {
		r.mu.Unlock()
		st.Close()
		return prev, nil
	}
	r.dest[dst] = d
	r.mu.Unlock()

	r.wg.Add(1)
	go r.read(dst, d)
	return d, nil
}

// read drains one destination's stream into the shared queue.
func (r *tmnRelay) read(src netip.AddrPort, d *tmnDest) {
	defer r.wg.Done()
	buf := make([]byte, tmnMaxDatagram)
	for {
		var h [2]byte
		if _, err := io.ReadFull(d.st, h[:]); err != nil {
			return
		}
		n := int(binary.BigEndian.Uint16(h[:]))
		if n == 0 || n > len(buf) {
			r.drop(src) // the exit broke the frame format: kill the stream
			return
		}
		if _, err := io.ReadFull(d.st, buf[:n]); err != nil {
			return
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		select {
		case r.in <- dgram{src: src, data: pkt}:
		case <-r.ctx.Done():
			return
		}
	}
}

// drop closes and forgets one destination.
func (r *tmnRelay) drop(dst netip.AddrPort) {
	r.mu.Lock()
	d, ok := r.dest[dst]
	delete(r.dest, dst)
	r.mu.Unlock()
	if ok {
		d.st.Close()
	}
}

// reap closes destinations the app stopped using.
func (r *tmnRelay) reap() {
	t := time.NewTicker(tmnUDPReap)
	defer t.Stop()
	for {
		select {
		case <-r.ctx.Done():
			return
		case now := <-t.C:
			cut := now.Add(-tmnUDPIdle).UnixNano()
			r.mu.Lock()
			var dead []*mux.Stream
			for a, d := range r.dest {
				if d.last.Load() < cut {
					delete(r.dest, a)
					dead = append(dead, d.st)
				}
			}
			r.mu.Unlock()
			for _, st := range dead {
				st.Close()
			}
		}
	}
}

// receive returns the next datagram; payload aliases buf.
func (r *tmnRelay) receive(buf []byte) (netip.AddrPort, []byte, error) {
	// A datagram may already sit in the queue when close() lands: delivering
	// it after teardown would let a closed session look alive for one packet,
	// so the closed flag wins over the queue.
	for {
		if r.closed.Load() {
			return netip.AddrPort{}, nil, errTMNClosed
		}
		select {
		case d := <-r.in:
			if r.closed.Load() {
				return netip.AddrPort{}, nil, errTMNClosed
			}
			n := copy(buf, d.data)
			return d.src, buf[:n], nil
		case <-r.ctx.Done():
			return netip.AddrPort{}, nil, errTMNClosed
		}
	}
}

func (r *tmnRelay) close() {
	if r.closed.Swap(true) {
		return
	}
	r.cancel()
	r.mu.Lock()
	for a, d := range r.dest {
		delete(r.dest, a)
		d.st.Close()
	}
	r.mu.Unlock()
	r.wg.Wait()
}
