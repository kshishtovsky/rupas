//go:build windows && live

package capture

// TestLiveSegSniff passively logs every outbound TCP:443 data packet's
// payload size / IP total length for RUPAS_SEGSNIFF_SECONDS seconds —
// Phase-1 wire truth: what segmentation actually reaches the engine
// (real MSS chunks vs LSO over-MTU super-packets). Sniff-only: the driver
// copies packets, traffic continues uninterrupted.
//
//	RUPAS_SEGSNIFF_SECONDS=20 go test -tags live -v -run TestLiveSegSniff ./internal/capture/
import (
	"encoding/binary"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/rupas/rupas/pkg/windivert"
)

func TestLiveSegSniff(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	secsStr := os.Getenv("RUPAS_SEGSNIFF_SECONDS")
	if secsStr == "" {
		t.Skip("RUPAS_SEGSNIFF_SECONDS not set")
	}
	secs, err := strconv.Atoi(secsStr)
	if err != nil || secs <= 0 {
		t.Skipf("bad RUPAS_SEGSNIFF_SECONDS=%q", secsStr)
	}
	sniff, err := windivert.OpenWithFlags(
		"outbound and tcp and tcp.DstPort == 443 and tcp.PayloadLength > 0",
		windivert.LayerNetwork, 0, windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer open (admin + driver): %v", err)
	}
	defer sniff.Close()

	deadline := time.Now().Add(time.Duration(secs) * time.Second)
	go func() { // unblock the final blocking Recv at the deadline
		time.Sleep(time.Until(deadline))
		_ = sniff.Shutdown(windivert.ShutdownRecv)
	}()
	buf := make([]byte, 65535)
	var addr windivert.Address
	n := 0
	for time.Now().Before(deadline) {
		m, err := sniff.Recv(buf, &addr)
		if err != nil {
			break
		}
		p := buf[:m]
		if len(p) < 40 || p[0]>>4 != 4 || p[9] != 6 {
			continue
		}
		ihl := int(p[0]&0x0f) * 4
		total := int(binary.BigEndian.Uint16(p[2:4]))
		tcp := p[ihl:total]
		if len(tcp) < 20 {
			continue
		}
		tcpHl := int(tcp[12]>>4) * 4
		dport := binary.BigEndian.Uint16(tcp[2:4])
		seq := binary.BigEndian.Uint32(tcp[4:8])
		_ = dport
		n++
		t.Logf("pkt#%d ip.total=%d payload=%d seq=%d flags=%02x ttl=%d %s",
			n, total, total-ihl-tcpHl, seq, tcp[13], p[8],
			map[bool]string{true: "OVER-MTU!", false: ""}[total > 1500])
	}
	t.Logf("=== sniffed %d data packet(s) in %ds ===", n, secs)
}
