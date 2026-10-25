package android

import (
	"io"
	"net"
	"sync"
	"testing"
)

func TestCountersLifecycle(t *testing.T) {
	var c Counters

	c.TCPFlowOpen()
	c.TCPFlowOpen()
	c.UDPSessionOpen()
	c.TCPFlowClose()
	c.AddRx(100)
	c.AddTx(50)
	c.Drop()

	snap := c.Snapshot()
	if snap.TCPFlows != 1 {
		t.Errorf("tcp_flows = %d, want 1", snap.TCPFlows)
	}
	if snap.UDPSessions != 1 {
		t.Errorf("udp_sessions = %d, want 1", snap.UDPSessions)
	}
	if snap.RxBytes != 100 || snap.TxBytes != 50 {
		t.Errorf("rx/tx = %d/%d, want 100/50", snap.RxBytes, snap.TxBytes)
	}
	if snap.TCPTotal != 2 {
		t.Errorf("tcp_total = %d, want 2", snap.TCPTotal)
	}
	if snap.Dropped != 1 {
		t.Errorf("dropped = %d, want 1", snap.Dropped)
	}

	c.UDPSessionClose()
	if s := c.Snapshot(); s.UDPSessions != 0 {
		t.Errorf("udp_sessions after close = %d, want 0", s.UDPSessions)
	}
}

func TestCountersIgnoreNegativeAndZero(t *testing.T) {
	var c Counters
	c.AddRx(0)
	c.AddRx(-5)
	c.AddTx(-1)
	if s := c.Snapshot(); s.RxBytes != 0 || s.TxBytes != 0 {
		t.Errorf("rx/tx = %d/%d, want 0/0", s.RxBytes, s.TxBytes)
	}
}

func TestCountersConcurrent(t *testing.T) {
	var c Counters
	const workers, iters = 8, 1000
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range iters {
				c.AddRx(1)
				c.AddTx(2)
				c.TCPFlowOpen()
				c.TCPFlowClose()
				c.Drop()
			}
		}()
	}
	wg.Wait()

	snap := c.Snapshot()
	wantRx := uint64(workers * iters)
	if snap.RxBytes != wantRx {
		t.Errorf("rx = %d, want %d", snap.RxBytes, wantRx)
	}
	if snap.TxBytes != wantRx*2 {
		t.Errorf("tx = %d, want %d", snap.TxBytes, wantRx*2)
	}
	if snap.TCPFlows != 0 {
		t.Errorf("active tcp_flows = %d, want 0", snap.TCPFlows)
	}
	if snap.TCPTotal != wantRx {
		t.Errorf("tcp_total = %d, want %d", snap.TCPTotal, wantRx)
	}
}

// TestEnginePumpCountsBytes verifies the relay pump byte accounting.
// Topology note: over real TCP, a Write on one endpoint is readable on the
// PEER endpoint (unlike a gVisor netstack endpoint, where the handler's
// conn is the app's own socket). So the pump here reads from pair1's
// server side (where the "app" data lands) and writes into pair2, whose
// other end plays the internet.
func TestEnginePumpCountsBytes(t *testing.T) {
	appConn, relayIn := tcpPair(t)   // app writes → relay reads
	relayOut, internet := tcpPair(t) // relay writes → internet reads

	payload := make([]byte, 4096)
	for i := range payload {
		payload[i] = byte(i)
	}
	go func() {
		appConn.Write(payload) //nolint:errcheck
		appConn.Close()
	}()

	e := NewEngine(nil, nil, nil)
	var rx int64
	pumped := make(chan struct{})
	go func() {
		e.pump(relayOut, relayIn, func(n int64) { rx += n }) // app → internet
		close(pumped)
	}()

	got := make([]byte, len(payload))
	if _, err := io.ReadFull(internet, got); err != nil {
		t.Fatalf("read relayed payload: %v", err)
	}
	<-pumped // pump's counter update lands after its final write
	if rx != int64(len(payload)) {
		t.Errorf("pump counted %d bytes, want %d", rx, len(payload))
	}
	if string(got[len(got)-4:]) != string(payload[len(payload)-4:]) {
		t.Error("relayed payload corrupted")
	}
}

// tcpPair returns a connected loopback TCP pair (a, b): writes on a are
// readable on b and vice versa.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	type result struct {
		conn net.Conn
		err  error
	}
	serverCh := make(chan result, 1)
	go func() {
		c, err := ln.Accept()
		serverCh <- result{c, err}
	}()
	a, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { a.Close() })
	r := <-serverCh
	if r.err != nil {
		t.Fatalf("accept: %v", r.err)
	}
	t.Cleanup(func() { r.conn.Close() })
	return a, r.conn
}

func TestVerdictDefaultDirect(t *testing.T) {
	if ActionDirect != 0 {
		t.Fatal("ActionDirect must be the zero value (default = Direct)")
	}
	meta := FlowMeta{Network: "tcp"}
	if got := DirectVerdict(meta); got != ActionDirect {
		t.Errorf("DirectVerdict = %v, want DIRECT", got)
	}
	if ActionBlock.String() != "BLOCK" || ActionDirect.String() != "DIRECT" {
		t.Fatalf("Action.String() broken: %v %v", ActionDirect, ActionBlock)
	}
}
