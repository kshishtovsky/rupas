//go:build live && with_utls

package android

// Bisect helper: the relay box with a BARE context (no relayBoxContext
// registries) and no platform log writer. If this passes while
// TestRelayDialLive fails, the poison is in relayBoxContext or the log
// writer; if it fails too, the poison is in relayOptions output or the
// module build (tags/deps).

import (
	"context"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

func TestRelayBareBox(t *testing.T) {
	// Bare JSON link array from the environment: no credentials in git
	// (AGENTS.md invariant 6).
	links := os.Getenv("RELAY_LINKS")
	if links == "" {
		t.Skip("set RELAY_LINKS to run against a real endpoint")
	}
	s, err := ParseSettings(`{"fallback":true,"links":` + links + `}`)
	if err != nil {
		t.Fatalf("ParseSettings: %v", err)
	}
	eps, err := s.Endpoints()
	if err != nil {
		t.Fatalf("Endpoints: %v", err)
	}
	port, err := freeTCPPort()
	if err != nil {
		t.Fatalf("port: %v", err)
	}
	opts := relayOptions([]indexedEndpoint{{idx: 0, ep: eps[0]}}, []string{eps[0].Host}, []uint16{port}, "")
	opts.Experimental = nil
	opts.Log = &option.LogOptions{Disabled: false, Level: "debug", DisableColor: true}
	ctx := include.Context(context.Background())
	engine, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := engine.Start(); err != nil {
		t.Fatalf("start: %v", err)
	}
	defer engine.Close()
	// NOTE: probe on :80 — GFE closes a PLAINTEXT request on :443 with zero
	// bytes (empty EOF) for any client, always. Same for :443+TLS use probeGoogle
	// in relay_dial_live_test.go; here the bare box needs only one cheap probe.
	addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port).String()
	conn, err := socks5Connect(context.Background(), addr, netip.MustParseAddrPort(probeIP+":80"))
	if err != nil {
		t.Fatalf("socks dial: %v", err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: " + probeHost + "\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 128)
	n, rerr := conn.Read(buf)
	t.Logf("read n=%d err=%v %q", n, rerr, string(buf[:min(n, 40)]))
	if n == 0 {
		t.Fatalf("no data")
	}
}
