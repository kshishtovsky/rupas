// Standalone on-device repro for the relay crash: starts exactly the same
// sing-box relay the app starts (legacy flat settings), waits, exits.
// Run via adb shell; the Go runtime stderr (panic stacks!) lands in the
// shell where it is actually readable, unlike the app's logcat truncation.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/rupas/rupas/internal/transport/android"
)

func main() {
	json := `{"uuid":"6ba3bb34-c41d-4e47-a724-18aac84b4d4f","server":"203.0.113.10","port":12341,"sni":"example.com","fallback":true}`
	s, err := android.ParseSettings(json)
	if err != nil {
		fmt.Println("settings:", err)
		os.Exit(1)
	}
	logf := func(line string) { fmt.Println("LOG:", line) }
	r := android.NewRelay(s, logf)
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()
	if err := r.Start(ctx, nil, "/data/local/tmp/rupas-files"); err != nil {
		fmt.Println("start failed:", err)
		os.Exit(1)
	}
	fmt.Println("RELAY UP, socks=", r.Available())
	// Raw probe: what does the endpoint actually answer to a plain
	// TLS+HTTP request? Dumps the first response bytes for diagnosis.
	probeTLS("203.0.113.10:12341", "example.com")
	// Exercise a dial through the relay exactly like a TUNNEL flow would.
	conn, derr := r.DialTCP(ctx, netip.MustParseAddrPort("142.250.150.99:443"))
	if derr != nil {
		fmt.Println("dial:", derr)
	} else {
		conn.Write([]byte("GET /generate_204 HTTP/1.1\r\nHost: www.gstatic.com\r\nConnection: close\r\n\r\n"))
		buf := make([]byte, 512)
		n, rerr := conn.Read(buf)
		fmt.Printf("read n=%d err=%v %q\n", n, rerr, string(buf[:min(n, 120)]))
		conn.Close()
	}
	time.Sleep(5 * time.Second)
	fmt.Println("SURVIVED")
}


func probeTLS(addr, sni string) {
	d := &net.Dialer{Timeout: 8 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{
		ServerName: sni,
		NextProtos: []string{"h2", "http/1.1"},
	})
	if err != nil {
		fmt.Println("probe: tls:", err)
		return
	}
	defer c.Close()
	fmt.Println("probe: tls ok alpn=", c.ConnectionState().NegotiatedProtocol)
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = c.Write([]byte("GET / HTTP/1.1\r\nHost: " + sni + "\r\nConnection: close\r\n\r\n"))
	buf := make([]byte, 400)
	n, rerr := c.Read(buf)
	fmt.Printf("probe: read n=%d err=%v body=%q\n", n, rerr, string(buf[:min(n, 200)]))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}