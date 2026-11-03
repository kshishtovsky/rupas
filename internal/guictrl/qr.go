// qr.go — «Поделиться конфигом» и импорт из QR. Уезжает ВЕСЬ конфиг: правила
// маршрутизации, desync-параметры, каналы, исключения, geoip — то же, что
// лежит в rupas.yaml.
//
// На проводе — переносимый JSON, а не YAML: тот же payload обязан понимать
// Android, у которого из коробки есть org.json, но нет YAML-парсера. Формат
// файла на диске при этом не меняется, JSON живёт только внутри QR:
//
//	RUPAS1:<base64url без padding(gzip(json))>
//
// Версия в префиксе нужна, чтобы другая сборка отказалась от чужой раскладки
// вслух, а не импортировала мусор молча. Раскладка QR целиком — забота GUI
// (`qrcode-generator` рисует, `jsQR` читает): Go отдаёт только текст.
package guictrl

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/json"
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
	Bytes   int    `json:"bytes"`   // размер конфига до сжатия
	TooBig  bool   `json:"tooBig"`  // в один QR не влезает: только текстом
}

// qrDoc — переносимый конфиг. Поля общие для десктопа и Android; android-only
// (adblock, apps) десктоп терпит и не теряет: они возвращаются в QR как есть.
type qrDoc struct {
	V          int         `json:"v"`
	Profile    string      `json:"profile,omitempty"`
	Rules      []qrRule    `json:"rules,omitempty"`
	Links      []string    `json:"links,omitempty"`
	Desync     *qrDesync   `json:"desync,omitempty"`
	Exclusions *qrExcl     `json:"exclusions,omitempty"`
	Adblock    *qrAdblock  `json:"adblock,omitempty"`
	Apps       []qrAppRule `json:"apps,omitempty"`
}

type qrRule struct {
	App    string `json:"app,omitempty"`
	CIDR   string `json:"cidr,omitempty"`
	SNI    string `json:"sni,omitempty"`
	Ports  string `json:"ports,omitempty"`
	GeoIP  string `json:"geoip,omitempty"`
	Proto  string `json:"proto,omitempty"`
	Action string `json:"action"`
}

type qrDesync struct {
	Strategy string `json:"strategy,omitempty"`
	TTL      int    `json:"ttl,omitempty"`
	Repeats  int    `json:"repeats,omitempty"`
}

type qrExcl struct {
	CIDRs   []string `json:"cidrs,omitempty"`
	Domains []string `json:"domains,omitempty"`
}

type qrAdblock struct {
	Ads      bool `json:"ads"`
	Trackers bool `json:"trackers"`
}

type qrAppRule struct {
	Pkg    string `json:"pkg"`
	Action string `json:"action"`
}

// ExportQR собирает payload из живого конфига. Файл, а не память демона:
// GUI пишет конфиг сам (writeConfig), так что файл — единственный источник,
// который видят и демон, и следующий запуск. Каналы берутся из links.json —
// это тот же blob, что правит экран настроек, поэтому порядок перебора и
// выключенные каналы (префикс '#') доезжают как есть.
func (c *Controller) ExportQR() (QRBundle, error) {
	path := c.configPath()
	data, err := os.ReadFile(path)
	if err != nil {
		return QRBundle{}, fmt.Errorf("конфиг не прочитан: %w", err)
	}
	cfg, err := config.Unmarshal(data)
	if err != nil {
		return QRBundle{}, err // битый конфиг не отдаём наружу как «готовый»
	}
	doc := qrDoc{V: 1, Profile: cfg.Profile}
	for _, r := range cfg.Rules {
		doc.Rules = append(doc.Rules, qrRule{
			App: r.App, CIDR: r.CIDR, SNI: r.SNI, Ports: r.Ports,
			GeoIP: r.GeoIP, Proto: r.Proto, Action: strings.ToLower(r.Action.String()),
		})
	}
	if blob, err := loadLinksFile(); err == nil && strings.TrimSpace(blob) != "" {
		for _, line := range strings.Split(blob, "\n") {
			if line = strings.TrimSpace(line); line != "" {
				doc.Links = append(doc.Links, line)
			}
		}
	}
	doc.Desync = &qrDesync{Strategy: cfg.Desync.Strategy, TTL: cfg.Desync.TTL, Repeats: cfg.Desync.Repeats}
	if len(cfg.Exclusions.CIDRs) > 0 || len(cfg.Exclusions.Domains) > 0 {
		doc.Exclusions = &qrExcl{CIDRs: cfg.Exclusions.CIDRs, Domains: cfg.Exclusions.Domains}
	}
	raw, err := json.Marshal(doc)
	if err != nil {
		return QRBundle{}, err
	}
	text, err := encodeQRPayload(raw)
	if err != nil {
		return QRBundle{}, err
	}
	summary := qrSummary(cfg, &doc, len(raw))
	// Каналы уезжают из links.json. Если файла нет (руками удалили, старая
	// установка), честно предупреждаем: иначе человек отсканирует QR на
	// телефоне и получит конфиг без единого канала.
	if len(doc.Links) == 0 && cfg.Tunnels != nil {
		summary += " · ⚠ каналы не уедут: нет links.json"
	}
	return QRBundle{
		Text:    text,
		Summary: summary,
		Bytes:   len(raw),
		TooBig:  len(text) > qrMaxText,
	}, nil
}

// ImportQR принимает payload (JSON от десктопа или Android, а также старый
// YAML), проверяет его как обычный конфиг и применяет тем же путём, что
// «Сохранить»: валидация → .bak → атомарная замена → reload демона → откат,
// если демон отказал. Возвращает сводку применённого.
func (c *Controller) ImportQR(text string) (string, error) {
	raw, err := decodeQRPayload(text)
	if err != nil {
		return "", err
	}
	cfg, doc, linksBlob, err := c.applyQRPayload(raw)
	if err != nil {
		return "", err
	}
	if err := c.writeConfig(*cfg); err != nil {
		return "", err
	}
	// links.json трогаем только после успешной записи конфига: иначе отказ
	// демона оставил бы каналы в state, которых нет в rupas.yaml.
	if linksBlob != "" {
		if err := saveLinksFile(linksBlob); err != nil {
			return "", fmt.Errorf("конфиг применён, но каналы не сохранились: %w", err)
		}
	}
	return qrSummary(cfg, doc, len(raw)), nil
}

// applyQRPayload превращает payload в конфиг. Текущий файл — основа: импорт с
// телефона не должен стирать откалиброванный desync, geoip и всё, чего в
// payload нет по определению (телефон не знает про fake_template).
func (c *Controller) applyQRPayload(raw []byte) (*config.Config, *qrDoc, string, error) {
	if !looksJSON(raw) {
		cfg, err := config.Unmarshal(raw) // старый YAML-payload
		if err != nil {
			return nil, nil, "", fmt.Errorf("конфиг из QR не принят: %w", err)
		}
		return cfg, nil, "", nil
	}
	var doc qrDoc
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, nil, "", fmt.Errorf("это не конфиг Rupas: %w", err)
	}
	if doc.V != 1 {
		return nil, nil, "", fmt.Errorf("конфиг из QR версии %d — эта сборка понимает только 1", doc.V)
	}
	cur, err := loadCurrentConfig(c.configPath())
	if err != nil {
		return nil, nil, "", err
	}
	if doc.Profile != "" {
		cur.Profile = doc.Profile
	}
	if len(doc.Rules) > 0 {
		cur.Rules = nil
		// Android кладёт в конец массива правило-маркер {action:…} без
		// матчера — это выбранное на телефоне действие по умолчанию.
		// Раньше маркер ВЫБРАСЫВАЛСЯ, и конфиг уезжал без catch-all:
		// default=DIRECT (нулевое значение Action) → всё несмаченное шло
		// с реальным IP (живьём 2026-11-03). Теперь он применяется как
		// есть; отсутствие маркера закроет ensureCatchAll.
		var defAction config.Action
		var haveDefault bool
		for _, r := range doc.Rules {
			if r.App == "" && r.CIDR == "" && r.SNI == "" && r.Ports == "" && r.GeoIP == "" && r.Proto == "" {
				act, err := config.ParseAction(r.Action)
				if err != nil {
					return nil, nil, "", err
				}
				defAction, haveDefault = act, true
				continue
			}
			act, err := config.ParseAction(r.Action)
			if err != nil {
				return nil, nil, "", err
			}
			cur.Rules = append(cur.Rules, config.Rule{
				App: r.App, CIDR: r.CIDR, SNI: r.SNI, Ports: r.Ports,
				GeoIP: r.GeoIP, Proto: r.Proto, Action: act,
			})
		}
		if haveDefault {
			cur.Rules = append(cur.Rules, config.Rule{Action: defAction})
		}
	}
	if doc.Desync != nil {
		if doc.Desync.Strategy != "" {
			cur.Desync.Strategy = doc.Desync.Strategy
		}
		if doc.Desync.TTL > 0 {
			cur.Desync.TTL = doc.Desync.TTL
		}
		if doc.Desync.Repeats > 0 {
			cur.Desync.Repeats = doc.Desync.Repeats
		}
	}
	if doc.Exclusions != nil {
		cur.Exclusions = config.Exclusions{CIDRs: doc.Exclusions.CIDRs, Domains: doc.Exclusions.Domains}
	}
	// Пустой список каналов живые туннели не трогает: иначе «поделился»
	// конфиг без каналов оставил бы устройство без интернета.
	var blob string
	if len(doc.Links) > 0 {
		blob = strings.Join(doc.Links, "\n")
		tcp, udp, fb, _, err := channelsToPlan(blob)
		if err != nil {
			return nil, nil, "", fmt.Errorf("каналы из QR: %w", err)
		}
		if tcp != nil || udp != nil || fb != nil {
			cur.Tunnels = &config.TunnelConfig{TCP: tcp, UDP: udp, Fallback: fb}
		}
	}
	return cur, &doc, blob, nil
}

func looksJSON(raw []byte) bool {
	for _, b := range raw {
		switch b {
		case ' ', '\t', '\r', '\n':
			continue
		case '{':
			return true
		}
		return false
	}
	return false
}
func loadCurrentConfig(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		cfg := config.Default()
		return cfg, nil
	}
	cfg, err := config.Unmarshal(data)
	if err != nil {
		return nil, fmt.Errorf("текущий конфиг не читается, импорт отменён: %w", err)
	}
	return cfg, nil
}

func encodeQRPayload(raw []byte) (string, error) {
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return "", err
	}
	if _, err := zw.Write(raw); err != nil {
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
// сейчас отдаёт или забирает, не открывая конфиг.
func qrSummary(cfg *config.Config, doc *qrDoc, rawLen int) string {
	channels := 0
	if doc != nil {
		channels = len(doc.Links)
	}
	if channels == 0 && cfg.Tunnels != nil {
		for _, ep := range []*config.Endpoint{cfg.Tunnels.TCP, cfg.Tunnels.UDP, cfg.Tunnels.Fallback} {
			if ep != nil {
				channels++
			}
		}
	}
	if channels == 0 && cfg.Tunnel.Address != "" {
		channels++
	}
	excl := len(cfg.Exclusions.CIDRs) + len(cfg.Exclusions.Domains)
	parts := []string{
		fmt.Sprintf("%d правил", len(cfg.Rules)),
		fmt.Sprintf("%d канал(ов)", channels),
		fmt.Sprintf("%d исключений", excl),
	}
	if doc != nil {
		if len(doc.Apps) > 0 {
			parts = append(parts, fmt.Sprintf("%d приложений", len(doc.Apps)))
		}
		if doc.Adblock != nil && (doc.Adblock.Ads || doc.Adblock.Trackers) {
			parts = append(parts, "adblock")
		}
	} else if cfg.GeoIP != nil {
		parts = append(parts, "geoip")
	}
	parts = append(parts, fmt.Sprintf("desync %s t=%d", cfg.Desync.Strategy, cfg.Desync.TTL),
		fmt.Sprintf("%.1f КБ", float64(rawLen)/1024))
	return strings.Join(parts, " · ")
}
