package guictrl

// Круг «экспорт → QR → импорт» проверяется без камеры и без GUI: полезная
// нагрузка — обычный текст, а раскладку QR рисует фронтенд. Здесь проверяем
// то, что может испортить конфиг: сжатие, устойчивость к переносам строк от
// мессенджеров, отказ на чужом payload'е и то, что импорт идёт тем же путём,
// что «Сохранить» (валидация, .bak, атомарная замена).

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/kshishtovsky/rupas/internal/config"
)

const qrTestYAML = `profile: gui
rules:
    - geoip: ru
      action: desync
    - sni: youtube.com
      action: tunnel
    - ports: 443
      proto: tcp
      action: direct
desync:
    strategy: fake_split
    ttl: 4
    repeats: 3
tunnels:
    tcp:
        kind: tmn
        host: 203.0.113.10
        port: 18443
        sni: example.com
        psk: 00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff
        conns: 2
exclusions:
    cidrs:
        - 203.0.113.10/32
    domains:
        - spiderssense.com
`

func qrController(t *testing.T, yaml string) *Controller {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "configs", "rupas.yaml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}
	// Демона в тесте нет: writeConfig вернёт ErrDaemonDown, но файл уже
	// заменён атомарно — этого достаточно, чтобы проверить применяемость.
	return &Controller{opts: Options{ConfigPath: path}}
}

func TestQRRoundTripKeepsWholeConfig(t *testing.T) {
	c := qrController(t, qrTestYAML)
	b, err := c.ExportQR()
	if err != nil {
		t.Fatalf("ExportQR: %v", err)
	}
	if !strings.HasPrefix(b.Text, qrPrefix) {
		t.Fatalf("префикс потерян: %.20q", b.Text)
	}
	if len(b.Text) > qrMaxText {
		t.Fatalf("payload %d байт не влезет в один QR (предел %d)", len(b.Text), qrMaxText)
	}
	if b.TooBig {
		t.Fatal("маленький конфиг помечен как не влезающий")
	}
	if want := "3 правил"; !strings.Contains(b.Summary, want) {
		t.Fatalf("сводка %q без %q", b.Summary, want)
	}

	// Импорт в ЧИСТЫЙ каталог: конфиг должен появиться целиком.
	c2 := &Controller{opts: Options{ConfigPath: filepath.Join(t.TempDir(), "configs", "rupas.yaml")}}
	if err := os.MkdirAll(filepath.Dir(c2.configPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	// Демона нет — контракт writeConfig: файл записан, демон не подтвердил.
	if _, err := c2.ImportQR(b.Text); err != nil && !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("ImportQR: %v", err)
	}
	got, err := config.Load(c2.configPath())
	if err != nil {
		t.Fatalf("применённый конфиг не читается: %v", err)
	}
	if len(got.Rules) != 3 || got.Desync.Strategy != "fake_split" || got.Desync.TTL != 4 {
		t.Fatalf("правила/desync потерялись: %+v / %+v", got.Rules, got.Desync)
	}
	if got.Tunnels == nil || got.Tunnels.TCP == nil || got.Tunnels.TCP.Port != 18443 {
		t.Fatalf("канал потерян: %+v", got.Tunnels)
	}
	if len(got.Exclusions.CIDRs) != 1 || len(got.Exclusions.Domains) != 1 {
		t.Fatalf("исключения потеряны: %+v", got.Exclusions)
	}
}

// Мессенджеры и буфер обмена ломают переносы: payload должен пережить.
func TestImportQRToleratesWrappedText(t *testing.T) {
	c := qrController(t, qrTestYAML)
	b, err := c.ExportQR()
	if err != nil {
		t.Fatal(err)
	}
	var wrapped strings.Builder
	for i := 0; i < len(b.Text); i += 40 {
		end := min(i+40, len(b.Text))
		wrapped.WriteString(b.Text[i:end])
		wrapped.WriteString("\r\n ")
	}
	target := &Controller{opts: Options{ConfigPath: filepath.Join(t.TempDir(), "configs", "rupas.yaml")}}
	if err := os.MkdirAll(filepath.Dir(target.configPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := target.ImportQR(wrapped.String()); err != nil && !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("перенесённый текст не принят: %v", err)
	}
	if _, err := config.Load(target.configPath()); err != nil {
		t.Fatalf("перенесённый конфиг не читается: %v", err)
	}
}

func TestImportQRRejectsForeignPayload(t *testing.T) {
	for name, in := range map[string]string{
		"пусто":       "   ",
		"не base64":   "RUPAS1:это точно не конфиг",
		"не gzip":     "RUPAS1:aGVsbG8gd29ybGQ",
		"чужой gzip":  "RUPAS1:" + encodeB64ForTest([]byte("some other application payload")),
		"обрезанный":  "RUPAS1:H4sIAAAAAAAA",
		"постороннее": "vless://uuid@host:443",
	} {
		if _, err := (&Controller{}).ImportQR(in); err == nil {
			t.Fatalf("%s: импорт принял мусор", name)
		}
	}
}

// Валидация остаётся на месте: payload с известными полями, но недопустимым
// значением не должен попасть в файл.
func TestImportQRRejectsInvalidConfig(t *testing.T) {
	bad := strings.Replace(qrTestYAML, "ttl: 4", "ttl: 99", 1)
	text, err := encodeQRPayload([]byte(bad))
	if err != nil {
		t.Fatal(err)
	}
	c := &Controller{opts: Options{ConfigPath: filepath.Join(t.TempDir(), "configs", "rupas.yaml")}}
	if err := os.MkdirAll(filepath.Dir(c.configPath()), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportQR(text); err == nil {
		t.Fatal("ttl=99 принят")
	}
	if _, err := os.Stat(c.configPath()); err == nil {
		t.Fatal("битый конфиг записан на диск")
	}
}

func compressForTest(raw []byte) []byte {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write(raw)
	_ = zw.Close()
	return buf.Bytes()
}

func encodeB64ForTest(raw []byte) string {
	var buf strings.Builder
	enc := base64.RawURLEncoding.EncodeToString(compressForTest(raw))
	buf.WriteString(enc)
	return buf.String()
}
