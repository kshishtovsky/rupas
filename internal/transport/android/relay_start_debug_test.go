//go:build live && with_utls

package android

import (
	"context"
	"testing"
	"time"
)

// TestRelayStartLiveShape reproduces the on-device relay start with the
// legacy flat settings (vless tcp): Start must not panic and must report
// its failure reason clearly.
func TestRelayStartLiveShape(t *testing.T) {
	s, err := ParseSettings(`{"uuid":"6ba3bb34-c41d-4e47-a724-18aac84b4d4f","server":"45.67.202.247","port":12341,"sni":"mylifemyrulesonline.ru","fallback":true}`)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	r := NewRelay(s, func(line string) { t.Logf("relay: %s", line) })
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := r.Start(ctx, nil, t.TempDir()); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	defer r.Close()
	if !r.Available() {
		t.Fatal("relay not available after successful start")
	}
	t.Logf("socks=%s", r.socksAddr)
}
