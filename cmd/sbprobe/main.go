package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"github.com/rupas/rupas/internal/transport/android"
)

func main() {
	links := `["vless://332a87e4-4321-4027-ae49-72a6b67641af@127.0.0.1:12341?type=tcp&security=reality&pbk=shVXc1efjMDpqp8787otzjXqH2xByJTvXkHHLx2PFAQ&sid=999e2fd9&fp=chrome&sni=aws.amazon.com&flow=xtls-rprx-vision#rupas-reality"]`
	if env := os.Getenv("RELAY_LINKS"); env != "" {
		links = env
	}
	s, err := android.ParseSettings(`{"fallback":true,"links":` + links + `}`)
	if err != nil {
		fmt.Println("settings:", err)
		os.Exit(1)
	}
	logf := func(line string) { fmt.Printf("LOG: %s\n", line) }
	r := android.NewRelay(s, logf)
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if err := r.Start(ctx, nil, os.TempDir()); err != nil {
		fmt.Println("start failed:", err)
		os.Exit(1)
	}
	defer r.Close()
	fmt.Printf("UP socks=%v\n", r.Available())
	// Probe a real-GFE shape: plaintext HTTP on :80. GFE closes a plaintext
	// request on its TLS port :443 with zero bytes (empty EOF) for any
	// client — never use it as a tunnel probe.
	conn, derr := r.DialTCPIndex(0, ctx, netip.MustParseAddrPort("142.250.150.99:80"))
	if derr != nil {
		fmt.Println("dial:", derr)
		os.Exit(1)
	}
	req := "GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"
	if _, werr := conn.Write([]byte(req)); werr != nil {
		fmt.Println("write:", werr)
		os.Exit(1)
	}
	conn.SetReadDeadline(time.Now().Add(8 * time.Second))
	buf := make([]byte, 256)
	n, rerr := conn.Read(buf)
	fmt.Printf("read n=%d err=%v %q\n", n, rerr, string(buf[:min(n, 40)]))
	conn.Close()
	if n == 0 {
		os.Exit(1)
	}
	fmt.Println("OK")
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
