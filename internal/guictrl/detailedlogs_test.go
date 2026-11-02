package guictrl

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestDetailedLogsIncremental: второй вызов не перечитывает файл — он
// возвращает кэш плюс только дописанное. Проверяется по содержимому (никаких
// дублей и потерь на стыке) и по смещению, которое кэш держит.
func TestDetailedLogsIncremental(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("line ")
		b.WriteString(strings.Repeat("x", 40))
		b.WriteString("\n")
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := New(Options{LogPath: path})
	if err != nil {
		t.Fatal(err)
	}

	first, err := c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(first) != 5000 {
		t.Fatalf("первый вызов: %d строк, ждали 5000", len(first))
	}
	off := c.logTail.off
	if off == 0 {
		t.Fatal("offset не сдвинулся: файл прочитан не до конца")
	}

	// Ничего не дописано: тот же ответ, файл не перечитывался.
	same, err := c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(same) != 5000 || c.logTail.off != off {
		t.Fatalf("пустой опрос: %d строк, off %d -> %d", len(same), off, c.logTail.off)
	}

	// Дописали 10 строк: они добавляются, старое не дублируется.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		if _, err := f.WriteString("appended line\n"); err != nil {
			t.Fatal(err)
		}
	}
	f.Close()

	got, err := c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 5010 {
		t.Fatalf("после дописывания: %d строк, ждали 5010", len(got))
	}
	if got[len(got)-1] != "appended line" {
		t.Fatalf("последняя строка = %q", got[len(got)-1])
	}
	if got[0][:5] != "line " {
		t.Fatalf("первая строка испорчена: %q", got[0])
	}
}

// TestDetailedLogsPartialLine: недописанная строка показывается, но не
// фиксируется — иначе при следующем опросе она появилась бы дважды.
func TestDetailedLogsPartialLine(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	if err := os.WriteFile(path, []byte("one\ntwo\npart"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Options{LogPath: path})
	got, err := c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "part" {
		t.Fatalf("ждали [one two part], получили %q", got)
	}
	f, _ := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	f.WriteString("ial\n")
	f.Close()
	got, err = c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[2] != "partial" {
		t.Fatalf("после дописывания хвоста ждали [one two partial], получили %q", got)
	}
	if strings.Count(strings.Join(got, "|"), "part") != 1 {
		t.Fatalf("строка размножилась: %q", got)
	}
}

// TestDetailedLogsTruncated: ротация (файл стал короче) сбрасывает кэш, иначе
// панель покажет смесь двух поколений файла.
func TestDetailedLogsTruncated(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	if err := os.WriteFile(path, []byte("old1\nold2\nold3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Options{LogPath: path})
	if got, _ := c.DetailedLogs(0); len(got) != 3 {
		t.Fatalf("старое поколение: %q", got)
	}
	if err := os.WriteFile(path, []byte("new1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := c.DetailedLogs(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "new1" {
		t.Fatalf("после усечения ждали [new1], получили %q", got)
	}
}

// TestDetailedLogsLimit: limit отдаёт ровно N последних строк.
func TestDetailedLogsLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "rupasd.log")
	var b strings.Builder
	for i := 0; i < 5000; i++ {
		b.WriteString("row\n")
	}
	b.WriteString("last\n")
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	c, _ := New(Options{LogPath: path})
	got, err := c.DetailedLogs(1500)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1500 {
		t.Fatalf("%d строк, ждали 1500", len(got))
	}
	if got[1499] != "last" {
		t.Fatalf("последняя строка = %q", got[1499])
	}
}

// TestDetailedLogsMissingFile: демон ещё не писал лог — пусто, без ошибки.
func TestDetailedLogsMissingFile(t *testing.T) {
	c, _ := New(Options{LogPath: filepath.Join(t.TempDir(), "nope.log")})
	got, err := c.DetailedLogs(0)
	if err != nil || got != nil {
		t.Fatalf("ждали (nil, nil), получили (%q, %v)", got, err)
	}
}
