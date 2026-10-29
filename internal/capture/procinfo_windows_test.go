package capture

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ownName is the basename this test binary runs under — the name the
// attribution must report for a socket this process owns.
func ownName(t *testing.T) string {
	t.Helper()
	return strings.ToLower(filepath.Base(os.Args[0]))
}

// waitProcName polls procName until the cached snapshot catches the socket
// (snapshotTTL = 100 ms) or the deadline expires.
func waitProcName(t testing.TB, port uint16, udp bool) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for {
		if name := procName(port, udp); name != "" || time.Now().After(deadline) {
			return name
		}
		time.Sleep(snapshotTTL)
	}
}

// TestSnapshotTCPHasRows proves the decode: rows come back and each one
// carries a local port and an owning PID.
func TestSnapshotTCPHasRows(t *testing.T) {
	m := snapshotTCP()
	if len(m) == 0 {
		t.Fatal("snapshotTCP returned no owned rows")
	}
	for port, pid := range m {
		// A decoded 0 port means the network-order field was read wrongly;
		// PID 0 rows (TIME_WAIT) are filtered by the snapshot itself.
		if port == 0 || pid == 0 {
			t.Fatalf("bad row: port %d, pid %d (%d rows)", port, pid, len(m))
		}
	}
}

// TestProcNameOwnPortTCP: the loopback listener's local port resolves to
// this process — proves port decode, snapshot stride and PID→name.
func TestProcNameOwnPortTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	if got, want := waitProcName(t, port, false), ownName(t); got != want {
		t.Fatalf("procName(tcp %d) = %q, want %q", port, got, want)
	}
}

// TestProcNameOwnPortUDP does the same on the 12-byte UDP row layout.
func TestProcNameOwnPortUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	defer pc.Close()
	port := uint16(pc.LocalAddr().(*net.UDPAddr).Port)
	if got, want := waitProcName(t, port, true), ownName(t); got != want {
		t.Fatalf("procName(udp %d) = %q, want %q", port, got, want)
	}
}

// TestProcNameUnknownIsEmpty: an unattributed port must fail open (""),
// never guess.
func TestProcNameUnknownIsEmpty(t *testing.T) {
	if got := procName(0, false); got != "" {
		t.Errorf("procName(0) = %q, want \"\"", got)
	}
	// Port 1 is never a client's local port on this host.
	if got := procName(1, true); got != "" {
		t.Errorf("procName(udp 1) = %q, want \"\"", got)
	}
}

// BenchmarkProcNameCached measures the per-packet cost: a map probe plus a
// cached PID→name hit (snapshot taken at most once per 100 ms).
func BenchmarkProcNameCached(b *testing.B) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	// Warm both caches; the snapshot TTL (100 ms) can still hold the table
	// taken before this listener existed, hence the poll.
	if waitProcName(b, port, false) == "" {
		b.Fatalf("no attribution for own port %d", port)
	}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if procName(port, false) == "" {
			b.Fatalf("procName(%d) lost the owner, %d rows cached", port, len(procs.tcp))
		}
	}
}

// BenchmarkSnapshotTCP measures one full iphlpapi snapshot — the cost the
// engine pays at most 10×/s (PLAN-0.8 §2).
func BenchmarkSnapshotTCP(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if snapshotTCP() == nil {
			b.Fatal("snapshotTCP failed")
		}
	}
}
