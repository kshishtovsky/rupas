package tunnel

import "testing"

// Окно клиента приходит 16-битным и уже поделённым на 2^shift. Без
// масштабирования поток упирается в 64 КиБ в полёте: на пути 71 мс это
// 0.9 МБ/с — ровно та скорость скачивания, что видна в поле при том, что
// многопоточный тест показывает 700 Мбит/с.
func TestWinApplyScales(t *testing.T) {
	for _, c := range []struct {
		shift uint8
		field uint16
		want  uint32
	}{
		{0, 65535, 65535},      // клиент без WS: поле и есть окно
		{7, 512, 512 << 7},     // 64 КиБ
		{8, 256, 256 << 8},     // 64 КиБ при shift=8 (Windows)
		{8, 65535, 65535 << 8}, // ~16 МиБ
		{0, 0, 0},              // нулевое окно остаётся нулевым
	} {
		got := (&termConn{clientShift: c.shift}).winApply(c.field)
		if got != c.want {
			t.Fatalf("shift=%d поле=%d → %d, ждали %d", c.shift, c.field, got, c.want)
		}
	}
}

// Соединение берёт сдвиг из SYN, а не из первого ACK: SYN приходит раньше.
func TestNewTermConnTakesShiftFromSYN(t *testing.T) {
	tm := &Terminator{log: testLogger(), send: &fakeTermSender{}}
	c := newTermConn(tm, termKey{}, TermPkt{Window: 65535, WScale: 8})
	if c.clientShift != 8 {
		t.Fatalf("clientShift = %d, ждали 8", c.clientShift)
	}
	// Окно самого SYN по RFC 7323 не масштабируется.
	if c.clientWin != 65535 {
		t.Fatalf("окно SYN отмасштабировано (%d) — RFC 7323 §2.2 запрещает", c.clientWin)
	}
	// А последующее окно — масштабируется.
	c.clientWin = c.winApply(256)
	if c.clientWin != 256<<8 {
		t.Fatalf("окно ACK = %d, ждали %d", c.clientWin, 256<<8)
	}
}
