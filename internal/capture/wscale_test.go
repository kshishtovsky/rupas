package capture

import "testing"

// synWScale: без этой опции каждый поток стоит на 64 КиБ в полёте, то есть
// 0.9 МБ/с на пути в 71 мс — ровно та скорость, что видна в поле.
func TestSynWScale(t *testing.T) {
	mk := func(opts ...byte) []byte {
		seg := make([]byte, 20+len(opts)+4)
		seg[12] = byte((20+len(opts))/4) << 4
		copy(seg[20:], opts)
		return seg
	}
	cases := []struct {
		name string
		seg  []byte
		hdr  int
		want uint8
		ws   bool // опция присутствует
	}{
		{"нет опций", mk(), 20, 0, false},
		{"WS=8 как у Windows", mk(2, 4, 0x05, 0xb4, 1, 3, 3, 8), 28, 8, true},
		{"WS=7", mk(1, 3, 3, 7), 24, 7, true},
		{"WS=0 — легальный ноль", mk(3, 3, 0), 24, 0, true},
		{"WS=14 предел", mk(3, 3, 14), 24, 14, true},
		{"WS=15 вне RFC", mk(3, 3, 15), 24, 0, false},
		{"обрезка заголовка", mk(3, 3, 8), 20, 0, false},
	}
	for _, c := range cases {
		got, present := synWScale(c.seg, c.hdr)
		if got != c.want || present != c.ws {
			t.Fatalf("%s: synWScale = (%d,%v), ждали (%d,%v)", c.name, got, present, c.want, c.ws)
		}
	}
	// Мусор в опциях не должен паниковать: пакет приходит из сети.
	garbage := [][]byte{
		{3},
		{3, 0},
		{3, 200, 8},
		{1, 1, 1},
		{0, 3, 3, 8},
	}
	for _, g := range garbage {
		if s, ok := synWScale(append([]byte{}, append(make([]byte, 20), g...)...), 20+len(g)); s > 14 || (ok && g[0] != 3) {
			t.Fatalf("мусор %v дал (%d,%v)", g, s, ok)
		}
	}
}
