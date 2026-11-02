package tunnel

import "testing"

// SYN-ACK обязан нести опцию WS (kind 3). Без неё RFC 7323 §2.2 запрещает
// клиенту масштабировать окно: он шлёт окно приёма буквально, и оно упирается
// в 65535 байт. Наш поток отправки тогда равен 64 КиБ / RTT — 0.9 МБ/с на
// пути 71 мс, то есть те самые 2-3 МБ/с в три потока на десктопе.
// Значение опции — сдвиг НАШЕГО приёмного окна: он поднимает upload с того же
// потолка 64 КиБ / RTT.
func TestSynAckCarriesWindowScale(t *testing.T) {
	tm := &Terminator{log: testLogger(), send: &fakeTermSender{}}
	c := newTermConn(tm, termKey{dstPort: 443, srcPort: 51000}, TermPkt{Window: 65535, WScale: 8, HasWS: true})

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
	if ws != recvWSShift {
		t.Fatalf("WS = %d, ждали %d (наш приёмный буфер %d КиБ)", ws, recvWSShift, recvBufCap>>10)
	}
	if got := tcp[27]; int(got) != recvWSShift {
		t.Fatalf("tcp[27] = %d, ждали %d", got, recvWSShift)
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

// TestNoWSClientStaysUnscaled: клиент, не предложивший WS в SYN, масштабирование
// не поймёт (RFC 7323 §2.2). Ему объявляем сдвиг 0 и окно не больше 64 КиБ —
// обратная совместимость важнее скорости такого (редкого) потока.
func TestNoWSClientStaysUnscaled(t *testing.T) {
	tm := &Terminator{log: testLogger(), send: &fakeTermSender{}}
	c := newTermConn(tm, termKey{dstPort: 443, srcPort: 51000}, TermPkt{Window: 65535})

	if c.wsShift != 0 {
		t.Fatalf("wsShift = %d для клиента без WS, ждали 0", c.wsShift)
	}
	pkt := c.craft(c.serverISN, c.clientNext, termSYN|termACK, nil, termWindow)
	if got := pkt[int(pkt[0]&0x0f)*4+27]; got != 0 {
		t.Fatalf("WS в SYN-ACK = %d, ждали 0", got)
	}
	// Пустой буфер: без сдвига поле упирается в 0xFFFF, то есть в полёте не
	// может быть больше 64 КиБ — прежний потолок upload сохраняется.
	if w := c.recvWindowLocked(); w != 0xFFFF {
		t.Fatalf("окно без WS = %d, ждали 0xFFFF", w)
	}
	if testing.Short() {
		return
	}
	// Поведенческая проверка: за один «RTT» клиент не может залить больше
	// 64 КиБ, потому что правый край окна ack+win дальше не уходит.
	perTick, drops, defers := uploadRate(t, 0, 3)
	if perTick > 64<<10 {
		t.Fatalf("за RTT принято %d байт (> 64 КиБ): окно без WS масштабируется", perTick)
	}
	if drops != 0 || defers != 0 {
		t.Fatalf("oooDropN = %d, qFullN = %d без масштабирования", drops, defers)
	}
}

// TestRecvWindowScaled: объявленное поле — это СВОБОДНОЕ место буфера,
// поделённое на 2^wsShift (RFC 7323), а не байты. Ноль остаётся нулём
// (persist-логика клиента жива), пустой буфер даёт recvBufCap>>5 = 0x4000.
func TestRecvWindowScaled(t *testing.T) {
	mk := func(shift uint8) *termConn {
		return &termConn{writeCh: make(chan []byte, termQueueSlots), wsShift: shift}
	}

	if w := mk(recvWSShift).recvWindowLocked(); w != termWindow {
		t.Fatalf("пустой буфер: поле %d, ждали termWindow = %d", w, termWindow)
	}

	// 64 КиБ в очереди: свободно 448 КиБ → поле 448 КиБ >> 5.
	c := mk(recvWSShift)
	c.queuedBytes.Store(64 << 10)
	if w, want := c.recvWindowLocked(), uint16((recvBufCap-(64<<10))>>recvWSShift); w != want {
		t.Fatalf("64 КиБ в очереди: поле %d, ждали %d", w, want)
	}

	// Полный буфер: ровно 0 — клиент встаёт на persist, пока не освободим.
	c = mk(recvWSShift)
	c.queuedBytes.Store(recvBufCap)
	if w := c.recvWindowLocked(); w != 0 {
		t.Fatalf("полный буфер: поле %d, ждали 0", w)
	}

	// Out-of-order занимает то же место, что и очередь.
	c = mk(recvWSShift)
	c.queuedBytes.Store(recvBufCap / 2)
	c.oooBytes = recvBufCap / 2
	if w := c.recvWindowLocked(); w != 0 {
		t.Fatalf("буфер занят ooo-сегментами: поле %d, ждали 0", w)
	}

	// Слотовая граница остаётся вторым ограничителем: мелкими сегментами
	// нельзя залить больше, чем влезает в очередь.
	c = mk(recvWSShift)
	for i := 0; i < cap(c.writeCh)-oooBatchReserve; i++ {
		c.writeCh <- []byte{1}
	}
	if w := c.recvWindowLocked(); w != 0 {
		t.Fatalf("очередь на слотовой границе: поле %d, ждали 0", w)
	}

	// Клиент без WS: поле в байтах и ограничено 0xFFFF, хотя буфер 512 КиБ.
	if w := mk(0).recvWindowLocked(); w != 0xFFFF {
		t.Fatalf("без WS: поле %d, ждали 0xFFFF", w)
	}
}
