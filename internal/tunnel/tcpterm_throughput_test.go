package tunnel

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// flowSender считает только полезные байты, доставленные клиенту: этого
// достаточно, чтобы измерить пропускную способность терминатора.
type flowSender struct{ bytes atomic.Int64 }

func (s *flowSender) SendInboundTCP(pkt []byte, _, _ uint32) error {
	ipLen := int(pkt[0]&0x0f) * 4
	tcpOff := int(pkt[ipLen+12]>>4) * 4
	if n := len(pkt) - ipLen - tcpOff; n > 0 {
		s.bytes.Add(int64(n))
	}
	return nil
}

// TestTerminatorWindowScaleThroughput — регресс на потолок 64 КиБ в полёте.
//
// Клиент присылает окно, поделённое на 2^shift (WS из SYN). Пока терминатор
// читал поле буквально, в полёте было не больше 64 КиБ, и пропускная
// способность упиралась в 64 КиБ / RTT: на пути 71 мс это 0.9 МБ/с на поток
// — ровно то, что видно при скачивании файлов, тогда как многопоточный тест
// показывает гигабит.
//
// Здесь RTT искусственный: ACK приходит раз в 30 мс. Без масштабирования
// тест получает ~2 МБ/с, с ним — на порядок больше.
func TestTerminatorWindowScaleThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("замер пропускной способности")
	}
	snd := &flowSender{}
	var zeroed atomic.Bool

	// Кэрриер отдаёт бесконечный поток: узкое место должно быть в окне.
	dial := func(ctx context.Context, dst string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			buf := make([]byte, 32<<10)
			for {
				if _, err := b.Write(buf); err != nil {
					return
				}
			}
		}()
		return a, nil
	}

	tm := NewTerminator(snd, dial, testLogger())
	defer tm.Close()

	src, dst := [4]byte{10, 0, 0, 5}, [4]byte{93, 184, 216, 34}
	key := TermPkt{SrcIP: src, DstIP: dst, SrcPort: 51000, DstPort: 443, IfIdx: 1}

	// SYN с WS=8: клиент будет присылать окно, поделённое на 256.
	syn := key
	syn.Flags = termSYN
	syn.Window = 65535
	syn.WScale = 8
	syn.Seq = 1000
	tm.Feed(syn)

	// ACK раз в 30 мс: «RTT» замера. Поле окна 65535 при shift=8 — это
	// ~16 МиБ реального окна; без масштабирования те же 64 КиБ.
	stop := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tick := time.NewTicker(30 * time.Millisecond)
		defer tick.Stop()
		var acked uint32
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
			}
			// Подтверждаем всё, что успело уйти: терминатор двигает
			// serverNext, читаем его через сам поток ACK.
			acked += 1 << 20
			tm.Feed(TermPkt{
				SrcIP: src, DstIP: dst, SrcPort: 51000, DstPort: 443,
				Flags: termACK, Window: 65535, Seq: 1001 + acked, Ack: acked, IfIdx: 1,
			})
		}
	}()

	// Прогрев: пока кэрриер не ответил, потоков данных нет.
	deadline := time.Now().Add(200 * time.Millisecond)
	for snd.bytes.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	before := snd.bytes.Load()
	time.Sleep(600 * time.Millisecond)
	got := snd.bytes.Load() - before
	close(stop)
	wg.Wait()
	_ = zeroed.Load()

	// 0.6 с при потолке 64 КиБ / 30 мс = ~1.3 МБ. С масштабированием
	// ограничителем становится сам кэрриер и планировщик.
	const want = 4 << 20
	if got < want {
		t.Fatalf("за 0.6 с доставлено %d байт (< %d): окно клиента не масштабируется", got, want)
	}
	t.Logf("доставлено %d байт за 0.6 с (%.1f МБ/с)", got, float64(got)/0.6/1e6)
	_ = binary.BigEndian
	_ = io.Discard
}
