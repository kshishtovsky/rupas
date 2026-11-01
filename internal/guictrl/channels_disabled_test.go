package guictrl

import "testing"

// A '#'-prefixed channel is the GUI's "switched off" state: it must stay in
// the list (order and label are the user's) but never reach the plan.
func TestDisabledChannelKeptButNotPlanned(t *testing.T) {
	const (
		tmn  = "tmn://aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa@example.com:18443?sni=example.com&conns=4#tmn"
		hy2  = "hysteria2://secret@example.com:53552?sni=example.com#hy2"
		xhtt = "vless://11111111-2222-3333-4444-555555555555@example.com:4443?type=xhttp&security=tls&sni=example.com#xhttp"
	)
	blob := tmn + "\n" + "#" + hy2 + "\n" + xhtt

	chans, err := ParseChannels(blob)
	if err != nil {
		t.Fatalf("ParseChannels: %v", err)
	}
	if len(chans) != 3 {
		t.Fatalf("channels = %d, want 3 (disabled one is kept)", len(chans))
	}
	if !chans[1].Disabled {
		t.Fatal("hy2 channel must be marked disabled")
	}
	if chans[1].Link != hy2 {
		t.Fatalf("disabled link = %q, want the bare link without '#'", chans[1].Link)
	}

	tcp, udp, fb, _, err := channelsToPlan(blob)
	if err != nil {
		t.Fatalf("channelsToPlan: %v", err)
	}
	if tcp == nil || tcp.Kind != "tmn" {
		t.Fatalf("tcp = %+v, want the tmn channel", tcp)
	}
	if udp != nil {
		t.Fatalf("udp = %+v, want nil: the only hy2 channel is switched off", udp)
	}
	if fb == nil || fb.Kind != "vless_xhttp" {
		t.Fatalf("fallback = %+v, want the xhttp channel", fb)
	}

	// Only a disabled channel left: nothing to dial, and SaveLinks refuses.
	if c, u, f, _, err := channelsToPlan("#" + tmn); err != nil || c != nil || u != nil || f != nil {
		t.Fatalf("all-disabled plan = %v/%v/%v err=%v, want empty", c, u, f, err)
	}
}
