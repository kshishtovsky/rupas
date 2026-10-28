package tunnel

import (
	"context"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

// A flow that dies while its carrier dial is still in flight must not leave a
// pump parked in Read forever: Terminator.Close waits for it and would wedge
// the whole daemon (pipeline mutex held -> no capture, no RPC status).
func TestCloseAfterRSTDuringDial(t *testing.T) {
	released := make(chan struct{})
	tm := NewTerminator(&fakeTermSender{}, func(ctx context.Context, dst string) (net.Conn, error) {
		client, _ := net.Pipe() // the far end is never used by the terminator
		<-released              // hold the dial open until after the client RST
		return client, nil
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))

	p := TermPkt{SrcIP: [4]byte{10, 0, 0, 2}, DstIP: [4]byte{149, 154, 167, 51},
		SrcPort: 41000, DstPort: 443, Seq: 1000, Flags: termSYN, Window: 65535}
	tm.Feed(p) // SYN -> SYN-ACK + carrier dial (parked on released)

	// The client gives up before the dial resolves.
	tm.Feed(TermPkt{SrcIP: p.SrcIP, DstIP: p.DstIP, SrcPort: p.SrcPort, DstPort: p.DstPort,
		Seq: 1001, Flags: termRST})

	close(released) // the dial now returns a live conn for a DEAD flow

	done := make(chan struct{})
	go func() {
		tm.Close()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Terminator.Close hung: a pump is blocked on a conn nobody closes")
	}
}
