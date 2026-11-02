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
	}{
		{"нет опций", mk(), 20, 0},
		{"WS=8 как у Windows", mk(2, 4, 0x05, 0xb4, 1, 3, 3, 8), 28, 8},
		{"WS=7", mk(1, 3, 3, 7), 24, 7},
		{"WS=0", mk(3, 3, 0), 24, 0},
		{"WS=14 предел", mk(3, 3, 14), 24, 14},
		{"WS=15 вне RFC", mk(3, 3, 15), 24, 0},
		{"обрезка заголовка", mk(3, 3, 8), 20, 0},
	}
	for _, c := range cases {
		if got := synWScale(c.seg, c.hdr); got != c.want {
			t.Fatalf("%s: synWScale = %d, ждали %d", c.name, got, c.want)
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
		if s := synWScale(append([]byte{}, append(make([]byte, 20), g...)...), 20+len(g)); s > 14 {
			t.Fatalf("мусор %v дал shift %d", g, s)
		}
	}
}
