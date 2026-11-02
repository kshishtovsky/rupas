package tunnel

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"
)

// recv ждёт датаграмму с таймаутом: receive() блокирующий, а тест не должен
// висеть до таймаута пакета при регрессе.
func recv(t *testing.T, r packetRelay, timeout time.Duration) (netip.AddrPort, []byte) {
	t.Helper()
	type res struct {
		src  netip.AddrPort
		data []byte
	}
	ch := make(chan res, 1)
	go func() {
		buf := make([]byte, tmnMaxDatagram)
		src, p, err := r.receive(buf)
		if err != nil {
			ch <- res{}
			return
		}
		out := make([]byte, len(p))
		copy(out, p)
		ch <- res{src: src, data: out}
	}()
	select {
	case v := <-ch:
		if v.data == nil {
			t.Fatalf("receive: ассоциация закрыта, ждали датаграмму")
		}
		return v.src, v.data
	case <-time.After(timeout):
		t.Fatalf("receive: нет датаграммы за %v", timeout)
		return netip.AddrPort{}, nil
	}
}

// Датаграмма возвращается в кадре «u16 длина + payload», источник — та цель,
// в которую её отправили: ответы разных целей не смешиваются.
func TestTMNUDPRoundTrip(t *testing.T) {
	s := newTMNServer(t)
	l := tmnCarrier(t, s)

	r, err := l.udpAssociate(context.Background())
	if err != nil {
		t.Fatalf("udpAssociate: %v", err)
	}
	defer r.close()

	dns := netip.MustParseAddrPort("1.1.1.1:53")
	want := []byte("query-payload-0123456789")
	if err := r.send(dns, want); err != nil {
		t.Fatalf("send: %v", err)
	}
	src, got := recv(t, r, 5*time.Second)
	if src != dns {
		t.Fatalf("источник %v, ждали %v", src, dns)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload %q, ждали %q", got, want)
	}

	// Вторая цель — своя датаграмма со своим источником.
	quic := netip.MustParseAddrPort("142.250.74.78:443")
	if err := r.send(quic, []byte("h3")); err != nil {
		t.Fatalf("send второй цели: %v", err)
	}
	src2, got2 := recv(t, r, 5*time.Second)
	if src2 != quic || string(got2) != "h3" {
		t.Fatalf("вторая датаграмма: src=%v payload=%q", src2, got2)
	}

	// Обе цели открылись отдельными потоками: на сервере их две.
	s.mu.Lock()
	seen := len(s.targets)
	s.mu.Unlock()
	if seen != 2 {
		t.Fatalf("сервер принял %d потоков, ждали 2 (по одному на цель)", seen)
	}
}

// Датаграмма больше 8 КиБ рвёт поток на выходе, поэтому каретка отказывает
// сразу — иначе приложение получало бы невнятную ошибку закрытия потока.
func TestTMNUDPTooBig(t *testing.T) {
	s := newTMNServer(t)
	l := tmnCarrier(t, s)

	r, err := l.udpAssociate(context.Background())
	if err != nil {
		t.Fatalf("udpAssociate: %v", err)
	}
	defer r.close()

	if err := r.send(netip.MustParseAddrPort("1.1.1.1:53"), make([]byte, tmnMaxDatagram+1)); err == nil {
		t.Fatal("send принял датаграмму больше лимита")
	}
}

// После close отправка и приём отвечают ошибкой, а не висят.
func TestTMNUDPClose(t *testing.T) {
	s := newTMNServer(t)
	l := tmnCarrier(t, s)

	r, err := l.udpAssociate(context.Background())
	if err != nil {
		t.Fatalf("udpAssociate: %v", err)
	}
	if err := r.send(netip.MustParseAddrPort("1.1.1.1:53"), []byte("x")); err != nil {
		t.Fatalf("send: %v", err)
	}
	r.close()
	r.close() // идемпотентно

	if err := r.send(netip.MustParseAddrPort("1.1.1.1:53"), []byte("x")); err == nil {
		t.Fatal("send после close не вернул ошибку")
	}
	done := make(chan struct{})
	go func() {
		buf := make([]byte, 64)
		_, _, err := r.receive(buf)
		if err == nil {
			t.Error("receive после close не вернул ошибку")
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("receive после close висит")
	}
}
