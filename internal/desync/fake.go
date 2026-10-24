package desync

import (
	"fmt"
	"os"
)

// LoadTemplate читает файл с payload фейкового ClientHello (например,
// build/desync/fake-chrome.bin — uTLS chrome) и санирует его: данные обязаны
// начинаться с TLS handshake record (content_type 0x16, version major 0x03).
func LoadTemplate(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("desync: read template: %w", err)
	}
	if err := checkTemplate(data); err != nil {
		return nil, fmt.Errorf("desync: template %s: %w", path, err)
	}
	return data, nil
}

// checkTemplate санирует fake-payload: непустой, минимум 2 байта и начинается
// с record layer TLS handshake (0x16 0x03) — иначе это не ClientHello-record.
func checkTemplate(b []byte) error {
	if len(b) == 0 {
		return fmt.Errorf("fake template is empty")
	}
	if len(b) < 2 {
		return fmt.Errorf("fake template too short (%d bytes) for a TLS record header", len(b))
	}
	if b[0] != 0x16 || b[1] != 0x03 {
		return fmt.Errorf("fake template is not a TLS handshake record: want prefix 0x16 0x03, got %#02x %#02x", b[0], b[1])
	}
	return nil
}
