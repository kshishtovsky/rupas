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

// winEdge — клиентская сторона замера upload: правый край нашего окна приёма
// (ack + win<<shift) и сдвиг, объявленный в SYN-ACK.
type winEdge struct {
	shift atomic.Uint32
	edge  atomic.Uint32
}

func (s *winEdge) SendInboundTCP(pkt []byte, _, _ uint32) error {
	ipLen := int(pkt[0]&0x0f) * 4
	if len(pkt) < ipLen+20 {
		return nil
	}
	tcp := pkt[ipLen:]
	if tcp[13]&termSYN != 0 {
		// MSS(20..23) + NOP + WS(25..27): сдвиг читаем ровно так же, как
		// его прочтёт настоящий клиент.
		sh := uint32(0)
		if off := int(tcp[12]>>4) * 4; off >= 28 && tcp[25] == 3 && tcp[26] == 3 {
			sh = uint32(tcp[27])
		}
		s.shift.Store(sh)
	}
	e := binary.BigEndian.Uint32(tcp[8:]) + uint32(binary.BigEndian.Uint16(tcp[14:16]))<<s.shift.Load()
	for {
		old := s.edge.Load()
		if e <= old || s.edge.CompareAndSwap(old, e) {
			return nil
		}
	}
}

// uploadRate заливает данные «клиентом», который раз в 30 мс (это и есть RTT
// замера) узнаёт правый край нашего окна и льёт ровно до него. Кэрриер
// забирает всё сразу, так что узкое место — объявленное окно, а не сток.
// Возвращает принятые байты на тик и счётчики потерь терминатора.
func uploadRate(t *testing.T, wscale uint8, ticks int) (perTick int64, drops, defers uint64) {
	t.Helper()
	const ackEvery = 30 * time.Millisecond
	snd := &winEdge{}
	var carried atomic.Int64

	dial := func(ctx context.Context, dst string) (net.Conn, error) {
		a, b := net.Pipe()
		go func() {
			buf := make([]byte, 32<<10)
			for {
				n, err := b.Read(buf)
				carried.Add(int64(n))
				if err != nil {
					return
				}
			}
		}()
		return a, nil
	}
	tm := NewTerminator(snd, dial, testLogger())
	defer tm.Close()

	src, dst := [4]byte{10, 0, 0, 7}, [4]byte{93, 184, 216, 34}
	const base = 7000
	feed := func(flags byte, seq uint32, payload []byte) {
		tm.Feed(TermPkt{SrcIP: src, DstIP: dst, SrcPort: 51002, DstPort: 443,
			Flags: flags, Window: 65535, WScale: wscale, Seq: seq, IfIdx: 1, Payload: payload})
	}
	feed(termSYN, base-1, nil)

	// Без SYN-ACK клиент не знает сдвига нашего окна.
	for deadline := time.Now().Add(2 * time.Second); snd.edge.Load() == 0; {
		if time.Now().After(deadline) {
			t.Fatal("нет SYN-ACK с окном")
		}
		time.Sleep(2 * time.Millisecond)
	}

	next := uint32(base)
	for i := 0; i < ticks; i++ {
		start := time.Now()
		edge := uint64(snd.edge.Load())
		for uint64(next)+termMSS <= edge {
			feed(termACK|termPSH, next, make([]byte, termMSS))
			next += termMSS
		}
		if d := time.Until(start.Add(ackEvery)); d > 0 {
			time.Sleep(d)
		}
	}

	// Дождаться, пока последний тик уедет в кэрриер, чтобы байты не
	// потерялись в очереди при замере.
	c := termConnOf(tm)
	for deadline := time.Now().Add(2 * time.Second); ; {
		if c.queuedBytes.Load() == 0 && len(c.writeCh) == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("очередь не опустела: кэрриер не забирает данные")
		}
		time.Sleep(2 * time.Millisecond)
	}
	return carried.Load() / int64(ticks), c.oooDropN.Load(), c.qFullN.Load()
}

// TestTerminatorUploadThroughput — регресс на потолок 64 КиБ в ОБРАТНУЮ
// сторону: наше приёмное окно.
//
// Пока SYN-ACK объявлял сдвиг 0, поле окна не могло быть больше 65535, и
// upload одного потока упирался в 64 КиБ / RTT — 21 Мбит/с на пути 25 мс,
// 7.4 Мбит/с на 71 мс. Теперь объявленный сдвиг масштабирует поле, и в полёте
// помещается весь приёмный буфер (512 КиБ). Синтетический RTT — те же 30 мс,
// что у скачивания: за тик клиент обязан залить заметно больше 64 КиБ.
func TestTerminatorUploadThroughput(t *testing.T) {
	if testing.Short() {
		t.Skip("замер пропускной способности")
	}
	const ticks = 20
	perTick, drops, defers := uploadRate(t, 8, ticks)

	if drops != 0 || defers != 0 {
		t.Fatalf("oooDropN = %d, qFullN = %d: окно объявлено больше буфера", drops, defers)
	}
	if want := int64(4 * 65535); perTick < want {
		t.Fatalf("за RTT принято %d байт (< %d): окно приёма не масштабируется", perTick, want)
	}
	t.Logf("upload: %d байт за RTT (%d тиков) — %.1f Мбит/с при RTT 30 мс",
		perTick, ticks, float64(perTick)*8/0.03/1e6)
}
