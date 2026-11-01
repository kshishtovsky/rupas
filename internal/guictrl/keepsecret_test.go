package guictrl

import (
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

// A stale links.json with a placeholder PSK must not overwrite the secret the
// daemon is actually dialing; a different server keeps whatever was pasted.
func TestKeepLiveSecret(t *testing.T) {
	live := &config.Endpoint{Kind: config.KindTMN, Host: "1.2.3.4", Port: 18443, PSK: "live-psk"}
	stale := &config.Endpoint{Kind: config.KindTMN, Host: "1.2.3.4", Port: 18443, PSK: "stale-psk"}

	w := keepLiveSecret(stale, live)
	if w == "" {
		t.Fatal("want a warning when the secret is replaced")
	}
	if stale.PSK != "live-psk" {
		t.Fatalf("psk = %q, want the live one", stale.PSK)
	}

	other := &config.Endpoint{Kind: config.KindTMN, Host: "9.9.9.9", Port: 18443, PSK: "new-psk"}
	if w := keepLiveSecret(other, live); w != "" || other.PSK != "new-psk" {
		t.Fatalf("different host must keep the pasted secret (warn=%q psk=%q)", w, other.PSK)
	}

	same := &config.Endpoint{Kind: config.KindTMN, Host: "1.2.3.4", Port: 18443, PSK: "live-psk"}
	if w := keepLiveSecret(same, live); w != "" {
		t.Fatalf("identical secret must not warn, got %q", w)
	}
}
