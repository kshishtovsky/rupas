//go:build windows && live

package capture

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kshishtovsky/rupas/internal/inspector"
	"github.com/kshishtovsky/rupas/pkg/windivert"
)

// TestLiveCHSniff is an on-the-machine diagnostic: for RUPAS_CH_SNIFF_SECONDS
// seconds it passively sniffs outbound TCP 443 traffic at the NETWORK layer
// and reports the SNI/ALPN/ECH of every first ClientHello it reassembles,
// using internal/inspector (the same parser the hot path feeds).
//
// Non-destructive: the handle opens with FlagSniff|FlagRecvOnly — the driver
// copies matching packets while they continue on the wire ("Do not
// intercept; observe only"), so the sniffing never swallows traffic. No
// Send/re-injection happens, matching the proven pattern of the other zz_
// live captures (TestLiveLoopbackDiag et al.).
//
// The header parse below is a minimal IPv4+TCP fork of pkt.go's logic,
// kept inline here so no production file needs exported test helpers. IPv4
// only: the shipped driver build has the IPv6 stack stripped.
//
// Usage (Administrator console, WinDivert driver installed):
//
//	build\sniffch.cmd
//	RUPAS_CH_SNIFF_SECONDS=10 go test -tags live -v -run TestLiveCHSniff ./internal/capture/
//
// Without the env var set (or with a non-positive/non-numeric value) the
// test skips itself, so a plain `go test -count=1 ./internal/capture/`
// stays green.
func TestLiveCHSniff(t *testing.T) {
	if !dllAvailable(t) {
		t.Skip("WinDivert.dll not loadable")
	}
	secsStr := os.Getenv("RUPAS_CH_SNIFF_SECONDS")
	if secsStr == "" {
		t.Skip("RUPAS_CH_SNIFF_SECONDS not set — set it to a positive number of seconds to sniff live traffic")
	}
	secs, err := strconv.ParseFloat(secsStr, 64)
	if err != nil || secs <= 0 {
		t.Skipf("RUPAS_CH_SNIFF_SECONDS=%q is not seconds > 0", secsStr)
	}
	d := time.Duration(secs * float64(time.Second))

	const filter = "outbound and tcp and tcp.DstPort == 443"
	if err := windivertValidate(filter); err != nil {
		t.Fatalf("filter: %v", err)
	}
	sniff, err := windivert.OpenWithFlags(filter, windivert.LayerNetwork, 0,
		windivert.FlagSniff|windivert.FlagRecvOnly)
	if err != nil {
		t.Skipf("sniffer open (requires admin + WinDivert driver): %v", err)
	}
	defer sniff.Close() // the driver re-injects anything still queued

	// Per-flow ClientHello reassembly, keyed "srcIP:srcPort-dstIP:dstPort".
	// Written only by the recv goroutine; read by the test goroutine only
	// after <-done, so no locking is needed (same shape as
	// TestLiveLoopbackDiag).
	flows := map[string]*inspector.Stream{}

	var (
		lines   []string // one line per terminal stream outcome
		totalCH int      // ClientHellos parsed
		echCH   int      // of those, with the ECH extension
	)

	runCtx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	done := make(chan struct{})

	go func() {
		defer close(done)
		buf := make([]byte, 65535)
		var addr windivert.Address
		deadline := time.Now().Add(d)
		for time.Now().Before(deadline) {
			n, err := sniff.Recv(buf, &addr)
			if err != nil {
				return
			}
			p := buf[:n]
			// --- minimal IPv4 + TCP header parse ---
			if len(p) < 20 || p[0]>>4 != 4 || p[9] != 6 { // IPv4, IPPROTO_TCP
				continue
			}
			ihl := int(p[0]&0x0f) * 4
			if ihl < 20 || ihl > len(p) {
				continue
			}
			if p[6]&0x1f != 0 || p[7] != 0 { // not the first IP fragment
				continue
			}
			tcp := p[ihl:]
			if len(tcp) < 20 {
				continue
			}
			thl := int(tcp[12]>>4) * 4
			if thl < 20 || thl > len(tcp) {
				continue
			}
			var s4, d4 [4]byte
			copy(s4[:], p[12:16])
			copy(d4[:], p[16:20])
			src, dst := netip.AddrFrom4(s4), netip.AddrFrom4(d4)
			sport := binary.BigEndian.Uint16(tcp[0:2])
			dport := binary.BigEndian.Uint16(tcp[2:4])
			flags := tcp[13]
			payload := tcp[thl:]

			key := fmt.Sprintf("%s:%d-%s:%d", src, sport, dst, dport)
			// A plain SYN restarts the tuple: forget any stale reassembler.
			if flags&0x02 != 0 && flags&0x10 == 0 && len(payload) == 0 {
				delete(flows, key)
				continue
			}
			if len(payload) == 0 {
				continue // pure ACK/keepalive noise
			}
			st := flows[key]
			if st == nil {
				st = inspector.NewStream()
				flows[key] = st
			}
			if st.Done() {
				continue // flow already reported
			}
			res, ferr := st.Feed(payload)
			if !st.Done() {
				continue // NeedMore: keep reassembling
			}
			when := time.Now().Format("15:04:05")
			switch {
			case ferr == nil:
				sni := ""
				if res.SNIFound {
					sni = string(res.SNI)
				}
				alpn := ""
				if len(res.ALPN) > 0 {
					alpn = string(res.ALPN)
				}
				lines = append(lines, fmt.Sprintf("%s %s:%d -> %s:%d sni=%q ech=%t alpn=%v",
					when, src, sport, dst, dport, sni, res.ECH, alpn))
				totalCH++
				if res.ECH {
					echCH++
				}
			case errors.Is(ferr, inspector.ErrNotTLS):
				lines = append(lines, fmt.Sprintf("%s %s:%d -> %s:%d not-tls",
					when, src, sport, dst, dport))
			default: // ErrMalformed or something unexpected
				lines = append(lines, fmt.Sprintf("%s %s:%d -> %s:%d rejected (%v)",
					when, src, sport, dst, dport, ferr))
			}
		}
	}()

	select {
	case <-done: // recv loop already ended (quiet window or handle error)
	case <-runCtx.Done(): // window over with Recv parked: unblock it
		_ = sniff.Shutdown(windivert.ShutdownRecv)
		<-done
	}

	for _, l := range lines {
		t.Log(l)
	}
	t.Logf("=== sniffed %v, filter %q: %d ClientHello(s), %d with ECH, %d flow(s) fed ===",
		d, filter, totalCH, echCH, len(flows))
}
