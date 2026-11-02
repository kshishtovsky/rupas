package tunnel

import "testing"

// SYN-ACK обязан нести опцию WS (kind 3). Без неё RFC 7323 §2.2 запрещает
// клиенту масштабировать окно: он шлёт окно приёма буквально, и оно упирается
// в 65535 байт. Наш поток отправки тогда равен 64 КиБ / RTT — 0.9 МБ/с на
// пути 71 мс, то есть те самые 2-3 МБ/с в три потока на десктопе.
func TestSynAckCarriesWindowScale(t *testing.T) {
	tm := &Terminator{log: testLogger(), send: &fakeTermSender{}}
	c := newTermConn(tm, termKey{dstPort: 443, srcPort: 51000}, TermPkt{Window: 65535, WScale: 8})

	pkt := c.craft(c.serverISN, c.clientNext, termSYN|termACK, nil, termWindow)
	ipLen := int(pkt[0]&0x0f) * 4
	tcp := pkt[ipLen:]
	off := int(tcp[12]>>4) * 4

	if off != 28 {
		t.Fatalf("data offset = %d, ждали 28 (20 + MSS + NOP + WS)", off)
	}
	var mss, ws = -1, -1
	for i := 20; i < off; {
		switch tcp[i] {
		case 0:
			i = off
		case 1:
			i++
		default:
			ln := int(tcp[i+1])
			if ln < 2 {
				t.Fatalf("битая опция %d в SYN-ACK", tcp[i])
			}
			switch tcp[i] {
			case 2:
				mss = int(tcp[i+2])<<8 | int(tcp[i+3])
			case 3:
				ws = int(tcp[i+2])
			}
			i += ln
		}
	}
	if mss != termMSS {
		t.Fatalf("MSS = %d, ждали %d", mss, termMSS)
	}
	if ws != 0 {
		t.Fatalf("WS = %d, ждали 0 (наш буфер 64 КиБ)", ws)
	}
	// Сумма опций должна быть кратна 4, иначе ядро отвергнет сегмент.
	if (off-20)%4 != 0 {
		t.Fatalf("длина опций %d не кратна 4", off-20)
	}
}

// Обычные пакеты данных по-прежнему без опций: лишние байты в каждом
// сегменте — это паддинг поверх всей полосы.
func TestDataSegmentsCarryNoOptions(t *testing.T) {
	tm := &Terminator{log: testLogger(), send: &fakeTermSender{}}
	c := newTermConn(tm, termKey{dstPort: 443, srcPort: 51000}, TermPkt{Window: 65535})
	pkt := c.craft(c.serverISN, c.clientNext, termACK|termPSH, []byte("hello"), termWindow)
	ipLen := int(pkt[0]&0x0f) * 4
	if off := int(pkt[ipLen+12]>>4) * 4; off != 20 {
		t.Fatalf("data offset данных = %d, ждали 20", off)
	}
}
