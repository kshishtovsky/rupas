package android

// ClientHello peek (W3): on a TCP flow, before any egress dial, look at
// the first ClientHello to classify the flow by SNI/ECH. The peek is
// bounded and passive: the bytes read are replayed to the relay through a
// prefix wrapper, so the connection is never damaged.

import (
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/rupas/rupas/internal/inspector"
)

const (
	// sniPeekTimeout bounds the wait for the ClientHello bytes. Flows
	// where the server speaks first (SSH, SMTP, ...) pay the full timeout
	// once before falling through to the default action.
	sniPeekTimeout = 2 * time.Second
	// sniPeekLimit caps the peek. Classic ClientHellos fit in ~600 B, but
	// post-quantum hellos (Chrome ≥124, ML-KEM key share) are ~1.4–1.8 KB;
	// a 600 B cut would truncate their SNI (which sits in the extensions
	// block) and misroute RU-zone flows into the tunnel. 2 KiB covers the
	// real-world maximum with a margin.
	sniPeekLimit = 2048
)

// prefixConn replays the peeked bytes before the live stream.
type prefixConn struct {
	net.Conn
	prefix []byte
}

func (c *prefixConn) Read(p []byte) (int, error) {
	if len(c.prefix) > 0 {
		n := copy(p, c.prefix)
		c.prefix = c.prefix[n:]
		return n, nil
	}
	return c.Conn.Read(p)
}

// peekBufPool recycles the peek read buffer: one 4 KiB allocation per TLS
// flow adds up on a browser-heavy session.
var peekBufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 4096)
		return &b
	},
}

// peekClientHello reads the head of conn (bounded by sniPeekTimeout /
// sniPeekLimit), parses the first ClientHello through the inspector and
// returns the lower-cased SNI, the real-ECH flag (GREASE is filtered by
// the inspector) and a conn that must be used from now on — it replays the
// peeked bytes first.
func peekClientHello(conn net.Conn) (sni string, ech bool, wrapped net.Conn) {
	_ = conn.SetReadDeadline(time.Now().Add(sniPeekTimeout)) //nolint:errcheck
	st := inspector.NewStream()
	seen := make([]byte, 0, sniPeekLimit)
	bufp := peekBufPool.Get().(*[]byte)
	defer peekBufPool.Put(bufp)
	buf := *bufp
	for len(seen) < sniPeekLimit {
		n, rErr := conn.Read(buf)
		if n > 0 {
			seen = append(seen, buf[:n]...)
			res, fErr := st.Feed(buf[:n])
			if fErr == nil {
				// Complete ClientHello.
				if res.SNIFound {
					sni = strings.ToLower(string(res.SNI))
				}
				ech = res.ECH
				break
			}
			if !errors.Is(fErr, inspector.ErrNeedMore) {
				break // not TLS / malformed: no SNI, default rules
			}
		}
		if rErr != nil {
			break // timeout/EOF with a partial hello: decide as-is
		}
	}
	_ = conn.SetReadDeadline(time.Time{}) //nolint:errcheck
	if len(seen) == 0 {
		return sni, ech, conn
	}
	return sni, ech, &prefixConn{Conn: conn, prefix: seen}
}

// errFlowBlocked is returned by dialEgress for ActionBlock flows; the
// netstack endpoint is closed without a dial.
var errFlowBlocked = fmt.Errorf("android: flow blocked by rules")
