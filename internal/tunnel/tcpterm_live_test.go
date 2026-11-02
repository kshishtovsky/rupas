//go:build live && with_utls

package tunnel

import (
	"context"
	"encoding/hex"
	"net"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/kshishtovsky/tuman/client"
)

// TestLiveTerminatorThroughput меряет СКОРОСТЬ СКАЧИВАНИЯ через терминатор
// на реальном carrier до VPS и реальном HTTP-источнике.
//
// Синтетический клиент ведёт себя как настоящий: подтверждает присланное,
// держит окно открытым и отправляет запрос. Так видно, ограничивает ли
// скорость сам терминатор или канал.
//
//	TMN_LIVE_ADDR=host:port TMN_LIVE_SNI=... TMN_LIVE_PSK=<64 hex>
func TestLiveTerminatorThroughput(t *testing.T) {
	addr, sni, psk := os.Getenv("TMN_LIVE_ADDR"), os.Getenv("TMN_LIVE_SNI"), os.Getenv("TMN_LIVE_PSK")
	if addr == "" || psk == "" {
		t.Skip("TMN_LIVE_* не заданы")
	}
	host := os.Getenv("TMN_LIVE_HOST")
	if host == "" {
		host = "proof.ovh.net"
	}
	rtt := 60 * time.Millisecond
	if v := os.Getenv("TMN_LIVE_RTT"); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			rtt = d
		}
	}

	ip, err := net.ResolveIPAddr("ip4", host)
	if err != nil {
		t.Fatalf("резолв %s: %v", host, err)
	}
	var dstIP [4]byte
	copy(dstIP[:], ip.IP.To4())

	key, err := hex.DecodeString(psk)
	if err != nil {
		t.Fatalf("psk: %v", err)
	}
	pool, err := client.New(client.Config{
		Servers: []client.Endpoint{{Addr: addr, SNI: sni}},
		PSK:     key, SNI: sni, Insecure: true, Conns: 2,
		AuthV2: true, Fingerprint: "chrome",
	})
	if err != nil {
		t.Fatalf("carrier: %v", err)
	}
	defer pool.Close()

	snd := &flowSender{}
	dial := func(ctx context.Context, dst string) (net.Conn, error) {
		return pool.DialContext(ctx, "tcp", dst)
	}
	tm := NewTerminator(snd, dial, testLogger())
	defer tm.Close()

	src, dport := [4]byte{10, 0, 0, 5}, uint16(19092)
	if v := os.Getenv("TMN_LIVE_PORT"); v != "" {
		if p, err := strconv.Atoi(v); err == nil {
			dport = uint16(p)
		}
	}
	reqPath := os.Getenv("TMN_LIVE_PATH")
	if reqPath == "" {
		reqPath = "/100mb.bin"
	}
	const sport = 51000
	fk := termKey{srcIP: src, dstIP: dstIP, srcPort: sport, dstPort: dport}

	tm.Feed(TermPkt{SrcIP: src, DstIP: dstIP, SrcPort: sport, DstPort: dport,
		IfIdx: 1, Flags: termSYN, Window: 65535, WScale: 8, Seq: 1000})

	var conn *termConn
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		tm.mu.Lock()
		conn = tm.conns[fk]
		tm.mu.Unlock()
		if conn != nil {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if conn == nil {
		t.Fatal("терминатор не принял SYN")
	}

	// Клиент подтверждает ровно то, что терминатор отправил, раз в RTT.
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		tick := time.NewTicker(rtt)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			conn.mu.Lock()
			acked := conn.serverNext
			conn.mu.Unlock()
			tm.Feed(TermPkt{SrcIP: src, DstIP: dstIP, SrcPort: sport, DstPort: dport,
				Flags: termACK, Window: 65535, Seq: 1001, Ack: acked, IfIdx: 1})
		}
	}()

	req := "GET " + reqPath + " HTTP/1.0\r\nHost: " + host + "\r\n\r\n"
	tm.Feed(TermPkt{SrcIP: src, DstIP: dstIP, SrcPort: sport, DstPort: dport,
		Flags: termACK | termPSH, Window: 65535, Seq: 1001, Payload: []byte(req), IfIdx: 1})

	deadline = time.Now().Add(20 * time.Second)
	for snd.bytes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if snd.bytes.Load() == 0 {
		close(stop)
		<-done
		t.Fatalf("за 20 с не пришло ни байта от %s", host)
	}

	before := snd.bytes.Load()
	const window = 3 * time.Second
	time.Sleep(window)
	got := snd.bytes.Load() - before
	close(stop)
	<-done

	rate := float64(got) / window.Seconds()
	t.Logf("%s, RTT %v: %.2f МБ/с (%.0f Мбит/с)", host, rtt, rate/1e6, rate*8/1e6)
}
