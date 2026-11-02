package guictrl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDetailedLogsBigLogReadsTailOnly: первый вызов на огромном файле читает
// только хвост maxTailBytes и не тащит в память весь лог (в поле он был 129 МиБ).
func TestDetailedLogsBigLogReadsTailOnly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	// 2 МиБ: по 100 байт на строку.
	line := strings.Repeat("y", 99) + "\n"
	var b strings.Builder
	for b.Len() < 2<<20 {
		b.WriteString(line)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Options{LogPath: path})
	got, err := c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if c.logTail.off != int64(b.Len()) {
		t.Fatalf("off = %d, ждали конец файла %d", c.logTail.off, b.Len())
	}
	// В кэше не больше, чем влезает в прочитанный хвост — и заведомо меньше
	// всего файла (иначе читали бы всё).
	if len(got) > maxTailBytes/len(line)+1 {
		t.Fatalf("в кэше %d строк — похоже, прочитан весь файл", len(got))
	}
	for _, l := range got {
		if l != strings.Repeat("y", 99) {
			t.Fatalf("строка испорчена на стыке: %q", l)
		}
	}
}
