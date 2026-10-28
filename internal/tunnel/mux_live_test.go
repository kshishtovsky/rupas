//go:build live

package tunnel

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/option"
)

// TestLiveMuxThroughput measures aggregate throughput through a real endpoint
// with sing-mux enabled, so the mux_conns knob is verified against the server
// that actually answers. xray demuxes smux (Mux.Cool); h2mux is sing-box-only.
//
// Run:
//
//	RELAY_MUX_ENDPOINT='{"host":"…","port":12341,"uuid":"…","sni":"…","pbk":"…","sid":"…","flow":"xtls-rprx-vision"}' \
//	RELAY_MUX_PROTOCOL=smux RELAY_MUX_CONNS=4 RELAY_MUX_URL=http://ftp.fi.muni.cz/…/file.iso \
//	RELAY_MUX_PARALLEL=4 RELAY_MUX_SECONDS=20 \
//	  go test -tags live -run TestLiveMuxThroughput -v ./internal/tunnel
//
// The endpoint comes from the environment: hardcoding it would commit a live
// credential (AGENTS.md invariant 6).
func TestLiveMuxThroughput(t *testing.T) {
	raw := os.Getenv("RELAY_MUX_ENDPOINT")
	if raw == "" {
		t.Skip("set RELAY_MUX_ENDPOINT to run against a real endpoint")
	}
	target := os.Getenv("RELAY_MUX_URL")
	if target == "" {
		t.Skip("set RELAY_MUX_URL to run the throughput measurement")
	}
	proto := envOr("RELAY_MUX_PROTOCOL", "smux")
	conns := envInt("RELAY_MUX_CONNS", 1)
	parallel := envInt("RELAY_MUX_PARALLEL", 1)
	seconds := envInt("RELAY_MUX_SECONDS", 20)
	muxOn := envOr("RELAY_MUX", "on") == "on"

	var ep JSONEndpoint
	if err := json.Unmarshal([]byte(raw), &ep); err != nil {
		t.Fatalf("RELAY_MUX_ENDPOINT: %v", err)
	}

	port, err := muxFreePort()
	if err != nil {
		t.Fatal(err)
	}
	vless := &option.VLESSOutboundOptions{
		ServerOptions: option.ServerOptions{Server: ep.Host, ServerPort: uint16(ep.Port)},
		UUID:          ep.UUID,
		Flow:          ep.Flow,
		OutboundTLSOptionsContainer: option.OutboundTLSOptionsContainer{
			TLS: &option.OutboundTLSOptions{
				Enabled:    true,
				ServerName: ep.SNI,
				UTLS: &option.OutboundUTLSOptions{
					Enabled:     true,
					Fingerprint: fingerprintOf("chrome"),
				},
				Reality: &option.OutboundRealityOptions{
					Enabled:   true,
					PublicKey: ep.PBK,
					ShortID:   ep.SID,
				},
			},
		},
	}
	if muxOn {
		vless.Multiplex = &option.OutboundMultiplexOptions{
			Enabled:        true,
			Protocol:       proto,
			MaxConnections: conns,
		}
	}
	opts := option.Options{
		Log: &option.LogOptions{Disabled: true},
		Inbounds: []option.Inbound{{
			Type: "mixed",
			Tag:  "in",
			Options: &option.HTTPMixedInboundOptions{
				ListenOptions: option.ListenOptions{
					Listen:     listenAddr("127.0.0.1"),
					ListenPort: port,
				},
			},
		}},
		Outbounds: []option.Outbound{{Type: "vless", Tag: "out", Options: vless}},
	}

	inst, err := box.New(box.Options{Context: minimalBoxContext(context.Background()), Options: opts})
	if err != nil {
		t.Fatalf("box.New: %v", err)
	}
	if err := inst.Start(); err != nil {
		t.Fatalf("box.Start: %v", err)
	}
	defer inst.Close()

	proxy := netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), port)

	uo, err := url.Parse(target)
	if err != nil {
		t.Fatalf("RELAY_MUX_URL: %v", err)
	}
	host := uo.Hostname()
	portNum, _ := strconv.Atoi(uo.Port())
	if portNum == 0 {
		portNum = 80
	}
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		t.Fatalf("resolve %s: %v", host, err)
	}
	var v4 netip.Addr
	for _, ip := range ips {
		if a, ok := netip.AddrFromSlice(ip.To4()); ok {
			v4 = a
			break
		}
	}
	if !v4.IsValid() {
		t.Fatalf("%s: нет IPv4", host)
	}
	dst := netip.AddrPortFrom(v4, uint16(portNum))

	var (
		mu    sync.Mutex
		total int64
		wg    sync.WaitGroup
	)
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(seconds)*time.Second)
	defer cancel()
	start := time.Now()
	for i := 0; i < parallel; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			n := fetchThrough(ctx, proxy.String(), dst, target)
			mu.Lock()
			total += n
			mu.Unlock()
		}()
	}
	wg.Wait()
	elapsed := time.Since(start).Seconds()
	mbps := float64(total) * 8 / elapsed / 1e6
	t.Logf("mux=%v protocol=%s conns=%d parallel=%d: %.0f МБ за %.1f с = %.0f Мбит/с",
		muxOn, proto, conns, parallel, float64(total)/1e6, elapsed, mbps)
	fmt.Printf("RESULT mux=%v proto=%s conns=%d parallel=%d mbit=%.0f\n", muxOn, proto, conns, parallel, mbps)
}

type JSONEndpoint struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	UUID string `json:"uuid"`
	SNI  string `json:"sni"`
	PBK  string `json:"pbk"`
	SID  string `json:"sid"`
	Flow string `json:"flow"`
}

// fetchThrough reads the URL body through the SOCKS inbound until ctx expires.
func fetchThrough(ctx context.Context, proxy string, dst netip.AddrPort, target string) int64 {
	tr := &http.Transport{
		DisableCompression: true,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return socks5Connect(ctx, proxy, dst)
		},
	}
	req, err := http.NewRequestWithContext(ctx, "GET", target, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")
	resp, err := (&http.Client{Transport: tr}).Do(req)
	if err != nil {
		return 0
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		return 0
	}
	n, _ := io.Copy(io.Discard, resp.Body)
	return n
}

func envOr(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func envInt(k string, def int) int {
	v, err := strconv.Atoi(os.Getenv(k))
	if err != nil || v <= 0 {
		return def
	}
	return v
}

func muxFreePort() (uint16, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return uint16(l.Addr().(*net.TCPAddr).Port), nil
}
