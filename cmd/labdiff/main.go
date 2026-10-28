//go:build windows

// labdiff: live differential probe for the fake-inject mechanics (wave 4A).
//
// Runs identical crypto/tls dials (SNI www.youtube.com) under three
// interception conditions while a low-priority SNIFF WinDivert handle
// records the final egress packet order:
//
//	labdiff -phase baseline            no interception (channel state)
//	labdiff -phase winws -ttl 12       reference winws.exe with --dpi-desync-ttl
//	labdiff -phase engine -ttl 12      our capture.Engine (current mechanics)
//
// The recorder sees packets after every desync handle has released them
// (priority 30000), i.e. the order the ISP DPI observes. Delete after the
// wave; not part of the shipped daemon.
package main

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/kshishtovsky/rupas/internal/capture"
	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/desync"
	"github.com/kshishtovsky/rupas/internal/rules"
	"github.com/kshishtovsky/rupas/pkg/windivert"
)

var (
	phase    = flag.String("phase", "baseline", "baseline | winws | engine")
	ttl      = flag.Int("ttl", 12, "fake TTL")
	repeats  = flag.Int("repeats", 6, "fake repeats")
	dials    = flag.Int("dial", 3, "dial attempts")
	target   = flag.String("target", "www.youtube.com", "dial target host")
	sni      = flag.String("sni", "www.youtube.com", "SNI to present")
	forceIP  = flag.String("ip", "", "force target IP (skip resolve)")
	thin     = flag.Bool("thin", false, "thin TLS1.2/P256 ClientHello (single segment)")
	holdSecs = flag.Int("hold", 0, "seconds to keep the phase engine alive after dials")
	winws    = flag.String("winws", `E:\zapret-discord-youtube-1.10.2\zapret-discord-youtube-1.10.2\bin\winws.exe`, "winws.exe path")
	tplPath  = flag.String("tpl", "", "fake template (default build/desync/fake-chrome.bin)")
)

func main() {
	flag.Parse()
	wd, _ := os.Getwd()
	if *tplPath == "" {
		*tplPath = filepath.Join(wd, "build", "desync", "fake-chrome.bin")
	}
	tpl, err := os.ReadFile(*tplPath)
	fatal(err)

	ip := resolve4(*target)
	if *forceIP != "" {
		ip = *forceIP
	}
	fmt.Printf("phase=%s ttl=%d repeats=%d target=%s(%s) sni=%s tpl=%d bytes\n",
		*phase, *ttl, *repeats, *target, ip, *sni, len(tpl))

	rec := startRecorder(ip)

	var stop func()
	switch *phase {
	case "baseline":
	case "winws":
		stop = startWinws(ip)
	case "engine":
		stop = startEngine(tpl)
	case "rawttl":
		rawTTLProbe(ip)
	default:
		fatal(fmt.Errorf("unknown phase %q", *phase))
	}
	if stop != nil {
		defer stop()
	}

	okCount := 0
	for i := 1; i <= *dials; i++ {
		t0 := time.Now()
		err := dialOnce(ip, *sni)
		d := time.Since(t0)
		if err == nil {
			okCount++
		}
		fmt.Printf("dial %d/%d: %v (%.0f ms)\n", i, *dials, res(err), float64(d.Microseconds())/1000)
		time.Sleep(700 * time.Millisecond)
	}
	fmt.Printf("RESULT phase=%s ttl=%d ok=%d/%d\n", *phase, *ttl, okCount, *dials)
	if *holdSecs > 0 {
		time.Sleep(time.Duration(*holdSecs) * time.Second)
	}

	rec.stop()
	for _, line := range rec.lines() {
		fmt.Println(line)
	}
}

func res(err error) string {
	if err == nil {
		return "OK"
	}
	s := err.Error()
	if len(s) > 120 {
		s = s[:120]
	}
	return "FAIL: " + s
}

func resolve4(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIP(ctx, "ip4", host)
	fatal(err)
	if len(ips) == 0 {
		fatal(fmt.Errorf("no A records for %s", host))
	}
	return ips[0].String()
}

func dialOnce(ip, sni string) error {
	cfg := &tls.Config{
		ServerName:         sni,
		InsecureSkipVerify: true,
	}
	if *thin {
		cfg.MaxVersion = tls.VersionTLS12
		cfg.CurvePreferences = []tls.CurveID{tls.CurveP256}
		cfg.CipherSuites = []uint16{tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256}
	}
	d := &net.Dialer{Timeout: 8 * time.Second}
	conn, err := tls.DialWithDialer(d, "tcp", net.JoinHostPort(ip, "443"), cfg)
	if err != nil {
		return err
	}
	return conn.Close()
}

// ---------------------------------------------------------------- recorder

type recorder struct {
	mu     sync.Mutex
	ev     []string
	t0     time.Time
	done   chan struct{}
	h      *windivert.Handle
	loIP   [4]byte
	anyIP  bool
	winner sync.WaitGroup
}

func startRecorder(ip string) *recorder {
	filter := fmt.Sprintf("tcp and (ip.SrcAddr == %s or ip.DstAddr == %s)", ip, ip)
	h, err := windivert.OpenWithFlags(filter, windivert.LayerNetwork, 30000, windivert.FlagSniff)
	fatal(err)
	r := &recorder{h: h, t0: time.Now(), done: make(chan struct{})}
	parts := strings.Split(ip, ".")
	for i := 0; i < 4; i++ {
		r.loIP[i] = byte(parseInt(parts[i]))
	}
	r.winner.Add(1)
	go r.loop()
	return r
}

func parseInt(s string) int {
	n := 0
	for _, c := range s {
		n = n*10 + int(c-'0')
	}
	return n
}

func (r *recorder) loop() {
	defer r.winner.Done()
	buf := make([]byte, 65575)
	var a windivert.Address
	for {
		n, err := r.h.Recv(buf, &a)
		if err != nil {
			return
		}
		line := describe(buf[:n], &a, time.Since(r.t0))
		r.mu.Lock()
		r.ev = append(r.ev, line)
		r.mu.Unlock()
		select {
		case <-r.done:
			return
		default:
		}
	}
}

func (r *recorder) stop() {
	close(r.done)
	_ = r.h.Shutdown(windivert.ShutdownRecv)
	r.winner.Wait()
	_ = r.h.Close()
	time.Sleep(150 * time.Millisecond) // drain in-flight lines
}

func (r *recorder) lines() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]string, len(r.ev))
	copy(out, r.ev)
	return out
}

func describe(pkt []byte, a *windivert.Address, since time.Duration) string {
	if len(pkt) < 40 || pkt[0]>>4 != 4 {
		return fmt.Sprintf("[%8.1fms] non-ipv4 %d bytes", float64(since.Microseconds())/1000, len(pkt))
	}
	ipLen := int(pkt[0]&0x0f) * 4
	if len(pkt) < ipLen+20 || pkt[9] != 6 {
		return fmt.Sprintf("[%8.1fms] non-tcp %d bytes", float64(since.Microseconds())/1000, len(pkt))
	}
	src := net.IP(pkt[12:16]).String()
	dst := net.IP(pkt[16:20]).String()
	ttlv := pkt[8]
	ipid := binary.BigEndian.Uint16(pkt[4:6])
	flags := pkt[ipLen+13] // control bits; ipLen+12 is data offset + NS
	sport := binary.BigEndian.Uint16(pkt[ipLen : ipLen+2])
	dport := binary.BigEndian.Uint16(pkt[ipLen+2 : ipLen+4])
	seq := binary.BigEndian.Uint32(pkt[ipLen+4 : ipLen+8])
	ack := binary.BigEndian.Uint32(pkt[ipLen+8 : ipLen+12])
	win := binary.BigEndian.Uint16(pkt[ipLen+14 : ipLen+16])
	dataOff := int(pkt[ipLen+12]>>4) * 4
	if dataOff < 20 || ipLen+dataOff > len(pkt) {
		// Legal-but-unusual or garbage doff (nibble up to 15 = 60 bytes):
		// never slice past the captured packet.
		return fmt.Sprintf("[%8.1fms] bad tcp doff %d len=%d", float64(since.Microseconds())/1000, dataOff, len(pkt))
	}
	pay := pkt[ipLen+dataOff:]
	fl := []byte{}
	for _, f := range []struct {
		b byte
		s string
	}{{0x01, "FIN"}, {0x02, "SYN"}, {0x04, "RST"}, {0x08, "PSH"}, {0x10, "ACK"}} {
		if flags&f.b != 0 {
			fl = append(fl, f.s...)
			fl = append(fl, '|')
		}
	}
	fs := strings.TrimSuffix(string(fl), "|")
	dir := "in "
	if a.Outbound() {
		dir = "out"
	}
	csum := "ok"
	if a.TCPChecksum() && !tcpCsumOK(pkt) {
		csum = "BAD"
	} else if !a.TCPChecksum() {
		csum = "offloaded"
	}
	head := 8
	if len(pay) < head {
		head = len(pay)
	}
	return fmt.Sprintf("[%8.1fms] %s %s:%d -> %s:%d seq=%d ack=%d ttl=%d ipid=%04x flags=%s win=%d pay=%d csum=%s head=%s",
		float64(since.Microseconds())/1000, dir, src, sport, dst, dport, seq, ack, ttlv, ipid, fs, win, len(pay), csum, hex.EncodeToString(pay[:head]))
}

func tcpCsumOK(pkt []byte) bool {
	ipLen := int(pkt[0]&0x0f) * 4
	seg := pkt[ipLen:]
	// zero the checksum field for computation on a copy
	if len(seg) < 20 {
		return false
	}
	copied := make([]byte, len(seg))
	copy(copied, seg)
	binary.BigEndian.PutUint16(copied[16:18], 0)
	pseudo := make([]byte, 12+len(copied))
	copy(pseudo[0:4], pkt[12:16])
	copy(pseudo[4:8], pkt[16:20])
	pseudo[8] = 0
	pseudo[9] = 6
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(copied)))
	copy(pseudo[12:], copied)
	return checksum16(pseudo) == 0xFFFF
}

func checksum16(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return uint16(sum)
}

// ---------------------------------------------------------------- engines

// rawTTLProbe isolates the phantom TTL decrement: clone the first outbound
// SYN three times with a marker TTL (33) and marker IP IDs, send each with a
// different address treatment, then watch the NIC capture for which TTL
// actually egresses.
func rawTTLProbe(ip string) {
	filter := fmt.Sprintf("outbound and tcp and ip.DstAddr == %s and tcp.DstPort == 443", ip)
	h, err := windivert.OpenWithFlags(filter, windivert.LayerNetwork, 0, 0)
	fatal(err)
	defer h.Close()
	done := make(chan struct{})
	go func() { // dial to generate a SYN
		defer close(done)
		c, err := net.DialTimeout("tcp", net.JoinHostPort(ip, "443"), 3*time.Second)
		if err == nil {
			time.Sleep(200 * time.Millisecond)
			c.Close()
		}
	}()
	buf := make([]byte, 65575)
	var a windivert.Address
	sentVariants := 0
	deadline := time.Now().Add(5 * time.Second)
	go func() {
		<-done
		time.Sleep(500 * time.Millisecond)
		_ = h.Shutdown(windivert.ShutdownRecv)
	}()
	for time.Now().Before(deadline) {
		n, err := h.Recv(buf, &a)
		if err != nil {
			break
		}
		pkt := buf[:n]
		if sentVariants == 0 && n >= 20 {
			variants := []struct {
				ipid    uint16
				setImp  bool
				clrCsum bool
			}{
				{0xdead, false, false}, // A: addr verbatim
				{0xbeef, true, false},  // B: impostor bit set
				{0xcafe, false, true},  // C: checksum-valid flags cleared
			}
			for _, v := range variants {
				cp := append([]byte(nil), pkt...)
				cp[8] = 33
				binary.BigEndian.PutUint16(cp[4:6], v.ipid)
				va := a
				raw := va.Raw()
				if v.setImp {
					raw[10] |= 1 << 3
				}
				if v.clrCsum {
					raw[10] &^= 3 << 5 // clear IPChecksum|TCPChecksum
				}
				va, err = windivert.ParseAddress(raw[:])
				fatal(err)
				fatal(windivert.CalcChecksums(cp, &va))
				if err := h.Send(cp, &va); err != nil {
					fmt.Printf("variant %04x send: %v\n", v.ipid, err)
				}
				sentVariants++
				time.Sleep(40 * time.Millisecond)
			}
		}
		fatal2(h.Send(pkt, &a))
	}
	fmt.Printf("rawttl: sent %d variants\n", sentVariants)
}

func fatal2(err error) {
	if err != nil {
		fmt.Println("labdiff send:", err)
	}
}

func startWinws(ip string) func() {
	dir := filepath.Dir(*winws)
	ipFile := filepath.Join(os.TempDir(), "labdiff-ipset.txt")
	fatal(os.WriteFile(ipFile, []byte(ip+"\n"), 0644))
	tpl, _ := filepath.Abs(*tplPath)
	args := []string{
		"--wf-tcp=443",
		"--filter-tcp=443",
		"--ipset=" + ipFile,
		"--dpi-desync=fake",
		fmt.Sprintf("--dpi-desync-repeats=%d", *repeats),
		fmt.Sprintf("--dpi-desync-ttl=%d", *ttl),
		"--dpi-desync-fake-tls=" + tpl,
	}
	fmt.Printf("winws: %s %s\n", *winws, strings.Join(args, " "))
	cmd := exec.Command(*winws, args...)
	cmd.Dir = dir
	out, err := os.Create(filepath.Join(os.TempDir(), "labdiff-winws.log"))
	fatal(err)
	cmd.Stdout, cmd.Stderr = out, out
	fatal(cmd.Start())
	time.Sleep(1200 * time.Millisecond)
	return func() {
		_ = cmd.Process.Kill()
		_, _ = cmd.Process.Wait()
		out.Close()
	}
}

func startEngine(tpl []byte) func() {
	cfg := config.Default()
	cfg.Rules = []config.Rule{
		{SNI: *sni, Action: config.ActionDesync},
		{Action: config.ActionDirect},
	}
	cfg.Desync = config.DesyncParams{
		Strategy: "fake",
		TTL:      *ttl,
		Repeats:  *repeats,
	}
	tbl, err := rules.Compile(cfg)
	fatal(err)
	if _, err := desync.New(cfg.Desync, tpl); err != nil {
		fatal(err)
	}
	eng, err := capture.New(capture.Options{
		Rules:        tbl,
		Desync:       cfg.Desync,
		FakeTemplate: tpl,
	})
	fatal(err)
	go func() { _ = eng.Run(context.Background()) }()
	time.Sleep(1200 * time.Millisecond)
	return func() { eng.Stop() }
}

func fatal(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, "labdiff:", err)
		os.Exit(1)
	}
}
