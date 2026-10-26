package android

// Live test of the W3 relay against the real VPS endpoint from
// configs/rupas.yaml (desktop config — the same endpoint the desktop
// rupasd uses right now). Skipped unless RUN_RELAY_LIVE=1: it needs the
// network and touches a production endpoint.
//
//	go test -tags "with_utls with_quic with_gvisor" -run TestRelayLive ./internal/transport/android/ -v

import (
	"bufio"
	"context"
	"net"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

type yamlTunnel struct {
	Host string `yaml:"host"`
	Port int    `yaml:"port"`
	UUID string `yaml:"uuid"`
	SNI  string `yaml:"sni"`
}

type yamlRoot struct {
	Tunnels struct {
		TCP yamlTunnel `yaml:"tcp"`
	} `yaml:"tunnels"`
}

func TestRelayLive(t *testing.T) {
	if os.Getenv("RUN_RELAY_LIVE") != "1" {
		t.Skip("RUN_RELAY_LIVE=1 to run against the real endpoint")
	}
	raw, err := os.ReadFile(`E:\rupas\configs\rupas.yaml`)
	if err != nil {
		t.Fatal(err)
	}
	var root yamlRoot
	if err := yaml.Unmarshal(raw, &root); err != nil {
		t.Fatal(err)
	}
	tc := root.Tunnels.TCP
	t.Logf("endpoint: %s:%d sni=%s uuid_len=%d", tc.Host, tc.Port, tc.SNI, len(tc.UUID))

	s, err := ParseSettings(`{"uuid":"` + tc.UUID + `","server":"` + tc.Host +
		`","port":` + itoa(tc.Port) + `,"sni":"` + tc.SNI + `","fallback":true}`)
	if err != nil {
		t.Fatal(err)
	}

	r := NewRelay(s, func(line string) { t.Log("relay:", line) })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := r.Start(ctx, func(fd int) bool { return true }, os.TempDir()); err != nil {
		t.Fatalf("relay start: %v", err)
	}
	defer r.Close() //nolint:errcheck

	// Plain HTTP over the tunnel to 1.1.1.1 — proves TLS+VLESS+CONNECT chain.
	conn, err := r.DialTCP(ctx, netip.MustParseAddrPort("1.1.1.1:80"))
	if err != nil {
		t.Fatalf("DialTCP: %v", err)
	}
	defer conn.Close()                                 //nolint:errcheck
	conn.SetDeadline(time.Now().Add(15 * time.Second)) //nolint:errcheck
	if _, err := conn.Write([]byte("GET / HTTP/1.1\r\nHost: 1.1.1.1\r\nConnection: close\r\n\r\n")); err != nil {
		t.Fatalf("write: %v", err)
	}
	br := bufio.NewReader(conn)
	line, err := br.ReadString('\n')
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	t.Logf("HTTP via tunnel: %s", strings.TrimSpace(line))
	if !strings.Contains(line, "200") && !strings.Contains(line, "301") && !strings.Contains(line, "302") {
		t.Fatalf("unexpected status line: %q", line)
	}
	_ = net.IPv4len // keep net import used on refactors
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
