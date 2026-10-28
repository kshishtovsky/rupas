package core

// Single-profile probe (docs/VPN_PROFILES_SPEC.md §5.3): one share link in,
// one JSON verdict out. It is deliberately the same path the tunnel takes —
// its own sing-box relay with a private cache dir, a SOCKS5 CONNECT through
// that relay, then a real TLS handshake (verified certificate) to a fixed
// external target. Nothing here touches the production relay: this is a
// throwaway box, started and closed inside the call.

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/rupas/rupas/internal/transport/android"
)

const (
	// Probe target: an IP literal (no DNS of its own on the phone) plus the
	// matching SNI name, so the handshake is a certificate-verified one.
	probeAddr = "104.16.124.96:443"
	probeName = "medium.com"

	// Stage budgets (§5.5); probeTotal caps the whole call. Start has no budget
	// of its own: it shares probeTotal with the stages, because its ctx must
	// outlive Start (see TestProfile).
	probeDial    = 3 * time.Second
	probePayload = 2 * time.Second
	probeTotal   = 8 * time.Second

	probeErrMax = 240
)

// probeMu serialises probes: a second call while one is running answers
// "busy" instead of queueing (two sing-boxes at once is what we are avoiding).
var probeMu sync.Mutex

// probeResult is the frozen JSON contract the Java side parses.
type probeResult struct {
	OK    bool   `json:"ok"`
	MS    int64  `json:"ms"`
	Stage string `json:"stage"`
	Err   string `json:"err"`
}

// TestProfile checks one share link end-to-end. Stage values: payload (ok),
// start, dial, busy. ms is 0 whenever ok is false.
func TestProfile(link, filesDir string) string {
	res := probeResult{Stage: "busy", Err: "уже идёт проверка другого профиля"}
	if probeMu.TryLock() {
		defer probeMu.Unlock()
		res = runProbe(link, filesDir)
	}
	b, mErr := json.Marshal(res)
	if mErr != nil { // unreachable for this struct; keep the contract anyway
		return `{"ok":false,"ms":0,"stage":"start","err":"probe: marshal"}`
	}
	return string(b)
}

func runProbe(link, filesDir string) (res probeResult) {
	started := time.Now()
	link = strings.TrimSpace(link)

	// Parsed only for redaction: a bad link must fail in relay.Start below,
	// which keeps a single failure path (stage "start").
	ep, _ := android.ParseShareLink(link)
	secrets := []string{ep.UUID, ep.PBK, ep.SID}

	// Own cache subdir: the live relay owns filesDir/cache.db, and two
	// sing-boxes must not share it (§5.4).
	dir := filepath.Join(filesDir, "probe")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return probeResult{Stage: "start", Err: redact("probe dir: "+err.Error(), link, secrets...)}
	}

	ctx, cancel := context.WithTimeout(context.Background(), probeTotal)
	defer cancel()

	var rl probeLog
	relay := android.NewRelay(&android.Settings{Links: []string{link}, Fallback: true}, rl.add)
	defer func() {
		if err := relay.Close(); err != nil && res.OK {
			res = probeResult{Stage: "start", Err: redact("relay close: "+err.Error(), link, secrets...)}
		}
	}()

	// The relay keeps this ctx for the lifetime of its sing-box: cancelling it
	// after Start tears the outbound down, and every later dial fails with
	// "operation was canceled" at 0 ms. So Start gets the run's ctx, and the
	// per-stage budgets below are applied to the calls, never to the box.
	err := relay.Start(ctx, nil, dir)
	if err != nil {
		return probeResult{Stage: "start", Err: redact(err.Error(), link, secrets...)}
	}

	dctx, dcancel := context.WithTimeout(ctx, probeDial)
	conn, err := relay.DialTCPIndex(0, dctx, netip.MustParseAddrPort(probeAddr))
	dcancel()
	if err != nil {
		// The box log says WHY the outbound refused; without it the app can
		// only show "socks5: reply code 1" and the user is stuck.
		return probeResult{Stage: "dial", Err: redact(err.Error()+rl.tail(), link, secrets...)}
	}
	defer conn.Close() //nolint:errcheck // read side only; relay.Close tears it down

	tctx, tcancel := context.WithTimeout(ctx, probePayload)
	defer tcancel()
	tc := tls.Client(conn, &tls.Config{ServerName: probeName, MinVersion: tls.VersionTLS12})
	if err := tc.HandshakeContext(tctx); err != nil {
		return probeResult{Stage: "payload", Err: redact("tls handshake: "+err.Error(), link, secrets...)}
	}
	return probeResult{OK: true, MS: time.Since(started).Milliseconds(), Stage: "payload"}
}

// probeLog keeps the tail of one probe's sing-box log so a failed dial can say
// WHY (the SOCKS error alone is "reply code 1"). One probe at a time, so a
// small ring is enough — no need for a lock-free structure.
type probeLog struct {
	mu   sync.Mutex
	ring [8]string
	n    int
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*[A-Za-z]")

func (p *probeLog) add(line string) {
	line = strings.TrimSpace(ansiRe.ReplaceAllString(line, ""))
	if line == "" {
		return
	}
	// sing-box prefixes the line with "android: sing-box info: INFO[0000] [...]";
	// keep from the message itself.
	if i := strings.Index(line, "] "); i >= 0 && i < len(line)-2 {
		line = line[i+2:]
	}
	p.mu.Lock()
	p.ring[p.n%len(p.ring)] = line
	p.n++
	p.mu.Unlock()
}

// tail returns " · <why>" with the most explanatory line of the ring: the last
// one mentioning a failure, else the last line at all.
func (p *probeLog) tail() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	var last, why string
	for i := 0; i < len(p.ring) && i < p.n; i++ {
		line := p.ring[(p.n-1-i+len(p.ring)*2)%len(p.ring)]
		if line == "" {
			continue
		}
		if last == "" {
			last = line
		}
		lower := strings.ToLower(line)
		// "denied" is deliberately absent: Android always logs a benign
		// "router: failed to search process: dial netlink: permission denied".
		for _, k := range []string{"error", "refus", "timeout", "cancel", "invalid"} {
			if strings.Contains(lower, k) {
				why = line
				break
			}
		}
		if why != "" {
			break
		}
	}
	if why == "" {
		why = last
	}
	if why == "" {
		return ""
	}
	return " · " + why
}

// redact keeps the secret out of the JSON: the whole link, any prefix of it
// (sharelink echoes 48-byte excerpts of the raw link) and the credential
// fields; then the 200-byte cap.
func redact(msg, link string, secrets ...string) string {
	for _, s := range secrets {
		if s != "" {
			msg = strings.ReplaceAll(msg, s, "***")
		}
	}
	if link != "" {
		msg = strings.ReplaceAll(msg, link, "***")
		for n := len(link); n >= 16; n-- {
			msg = strings.ReplaceAll(msg, link[:n], "***")
		}
	}
	if len(msg) > probeErrMax {
		msg = strings.ToValidUTF8(msg[:probeErrMax], "")
	}
	return msg
}
