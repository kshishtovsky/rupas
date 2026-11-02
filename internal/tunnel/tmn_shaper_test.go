package tunnel

import "testing"

// Профиль по умолчанию — browse, а не off: у шейпера нет смысла «выключено
// по умолчанию», иначе протокол маскировки отдаёт постоянный размер записи
// всем, кто не вписал настройку руками. Явный off остаётся явным.
func TestTMNProfileDefault(t *testing.T) {
	for in, want := range map[string]string{
		"":       "off",
		"browse": "browse",
		"off":    "off",
		"video":  "video",
	} {
		if got := tmnProfile(in); got != want {
			t.Fatalf("tmnProfile(%q) = %q, ждали %q", in, got, want)
		}
	}
}
