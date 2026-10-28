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

	// Stage budgets (§5.5); the total caps the sum.
	probeStart   = 3 * time.Second
	probeDial    = 3 * time.Second
	probePayload = 2 * time.Second
	probeTotal   = 8 * time.Second

	probeErrMax = 200
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

	relay := android.NewRelay(&android.Settings{Links: []string{link}, Fallback: true}, nil)
	defer func() {
		if err := relay.Close(); err != nil && res.OK {
			res = probeResult{Stage: "start", Err: redact("relay close: "+err.Error(), link, secrets...)}
		}
	}()

	sctx, scancel := context.WithTimeout(ctx, probeStart)
	err := relay.Start(sctx, nil, dir)
	scancel()
	if err != nil {
		return probeResult{Stage: "start", Err: redact(err.Error(), link, secrets...)}
	}

	dctx, dcancel := context.WithTimeout(ctx, probeDial)
	conn, err := relay.DialTCPIndex(0, dctx, netip.MustParseAddrPort(probeAddr))
	dcancel()
	if err != nil {
		return probeResult{Stage: "dial", Err: redact(err.Error(), link, secrets...)}
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
