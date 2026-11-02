// qr.go — «Поделиться конфигом» и импорт из QR. Уезжает ВЕСЬ конфиг: правила
// маршрутизации, desync-параметры, каналы, исключения, geoip — то же, что
// лежит в rupas.yaml. Формат намеренно тупой и версионированный:
//
//	RUPAS1:<base64url без padding(gzip(yaml))>
//
// Версия в префиксе нужна, чтобы будущий Android-клиент (или старый десктоп)
// отказался от чужой раскладки вслух, а не импортировал мусор молча.
// Раскладка QR целиком — забота GUI (`qrcode-generator` рисует, `jsQR` читает):
// Go отдаёт только текст, поэтому провязка не зависит от камеры и от того,
// есть ли в системе декодер.
package guictrl

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/kshishtovsky/rupas/internal/config"
)

const (
	qrPrefix = "RUPAS1:"
	// qrMaxText — предел одного QR в байтовом режиме (40-L: 2953 байта).
	// Выше — текст всё равно отдаём, но GUI честно скажет «копируй текстом».
	qrMaxText = 2900
	// qrMaxRaw — потолок распаковки: импорт чужого QR не должен съесть память
	// (gzip 1 КБ разворачивается в гигабайты).
	qrMaxRaw = 4 << 20
)

// QRBundle — то, что «Поделиться» отдаёт в GUI.
type QRBundle struct {
	Text    string `json:"text"`    // RUPAS1:… — и для QR, и для буфера обмена
	Summary string `json:"summary"` // «17 правил · 1 канал · 4 исключения · 1.1 КБ»
	Bytes   int    `json:"bytes"`   // размер yaml до сжатия
	TooBig  bool   `json:"tooBig"`  // в один QR не влезает: только текстом
}

// ExportQR собирает payload из живого конфига. Файл, а не память демона:
// GUI пишет конфиг сам (writeConfig), так что файл — единственный источник,
// который видят и демон, и следующий запуск.
func (c *Controller) ExportQR() (QRBundle, error) {
	path := c.configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return QRBundle{}, fmt.Errorf("конфиг не прочитан: %w", err)
	}
	text, err := encodeQRPayload(data)
	if err != nil {
		return QRBundle{}, err
	}
	cfg, err := config.Unmarshal(data)
	if err != nil {
		return QRBundle{}, err // битый конфиг не отдаём наружу как «готовый»
	}
	return QRBundle{
		Text:    text,
		Summary: qrSummary(cfg, len(data)),
		Bytes:   len(data),
		TooBig:  len(text) > qrMaxText,
	}, nil
}

// ImportQR принимает payload, проверяет его как обычный конфиг и применяет тем
// же путём, что «Сохранить»: валидация → .bak → атомарная замена → reload
// демона → откат, если демон отказал. Возвращает сводку применённого.
func (c *Controller) ImportQR(text string) (string, error) {
	data, err := decodeQRPayload(text)
	if err != nil {
		return "", err
	}
	cfg, err := config.Unmarshal(data)
	if err != nil {
		return "", fmt.Errorf("конфиг из QR не принят: %w", err)
	}
	if err := c.writeConfig(*cfg); err != nil {
		return "", err
	}
	return qrSummary(cfg, len(data)), nil
}

func encodeQRPayload(yaml []byte) (string, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(yaml); err != nil {
		return "", err
	}
	if err := zw.Close(); err != nil {
		return "", err
	}
	return qrPrefix + base64.RawURLEncoding.EncodeToString(buf.Bytes()), nil
}

// decodeQRPayload принимает и «сырой» payload, и текст, склеенный из мессенджера
// с переносами строк, и голый base64 без префикса (человек скопировал часть).
func decodeQRPayload(text string) ([]byte, error) {
	s := strings.TrimSpace(text)
	// Переносы и пробелы внутри — от копирования через мессенджеры.
	s = strings.NewReplacer("\n", "", "\r", "", " ", "", "\t", "").Replace(s)
	body, ok := strings.CutPrefix(s, qrPrefix)
	if !ok {
		// Терпим к обрезанному префиксу, но не к пустой строке.
		body = strings.TrimPrefix(s, strings.TrimSuffix(qrPrefix, ":"))
	}
	if body == "" {
		return nil, errors.New("пустые данные: вставь текст из QR или отсканируй его")
	}
	raw, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		// Тот же payload в стандартном base64 (например, из чужого генератора).
		if raw, err = base64.StdEncoding.DecodeString(body); err != nil {
			return nil, errors.New("это не конфиг Rupas: base64 не разобрался")
		}
	}
	if len(raw) < 2 || raw[0] != 0x1f || raw[1] != 0x8b {
		return nil, errors.New("это не конфиг Rupas: нет gzip-заголовка")
	}
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, errors.New("это не конфиг Rupas: gzip битый")
	}
	defer zr.Close() //nolint:errcheck // только чтение
	out, err := io.ReadAll(io.LimitReader(zr, qrMaxRaw+1))
	if err != nil {
		return nil, fmt.Errorf("распаковка: %w", err)
	}
	if len(out) > qrMaxRaw {
		return nil, fmt.Errorf("конфиг больше %d КБ — это не конфиг Rupas", qrMaxRaw>>10)
	}
	return out, nil
}

// qrSummary — одна строка для экрана: человек должен видеть, что именно он
// сейчас отдаёт или забирает, не открывая YAML.
func qrSummary(cfg *config.Config, yamlLen int) string {
	channels := 0
	if cfg.Tunnels != nil {
		for _, ep := range []*config.Endpoint{cfg.Tunnels.TCP, cfg.Tunnels.UDP, cfg.Tunnels.Fallback} {
			if ep != nil {
				channels++
			}
		}
	}
	if cfg.Tunnel.Address != "" {
		channels++
	}
	excl := len(cfg.Exclusions.CIDRs) + len(cfg.Exclusions.Domains)
	parts := []string{
		fmt.Sprintf("%d правил", len(cfg.Rules)),
		fmt.Sprintf("%d канал(ов)", channels),
		fmt.Sprintf("%d исключений", excl),
	}
	if cfg.GeoIP != nil {
		parts = append(parts, "geoip")
	}
	parts = append(parts, fmt.Sprintf("desync %s t=%d", cfg.Desync.Strategy, cfg.Desync.TTL),
		fmt.Sprintf("%.1f КБ", float64(yamlLen)/1024))
	return strings.Join(parts, " · ")
}
