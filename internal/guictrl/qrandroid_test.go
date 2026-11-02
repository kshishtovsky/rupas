package guictrl

// Приём payload'а от Android: телефон не знает про desync/geoip/exclusions и
// кладёт в конец массива правил маркер {action:…} без матчера (это его
// «действие по умолчанию»), а правила по именам процессов у него вообще
// отдельным списком. Десктоп обязан это понять и не подавиться на валидации.

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

const qrAndroidPayload = `{
  "v": 1,
  "links": [
    "tmn://00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff@203.0.113.10:18443?sni=example.com&conns=2"
  ],
  "adblock": {"ads": true, "trackers": false},
  "apps": [{"pkg": "org.telegram.messenger", "action": "tunnel"}],
  "rules": [
    {"cidr": "10.0.0.0/8", "action": "direct"},
    {"sni": "youtube.com", "action": "tunnel"},
    {"action": "tunnel"}
  ]
}`

func TestImportQRAcceptsAndroidPayload(t *testing.T) {
	c := qrController(t, qrTestYAML)
	text, err := encodeQRPayload([]byte(qrAndroidPayload))
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	summary, err := c.ImportQR(text)
	if err != nil && !errors.Is(err, ErrDaemonDown) {
		t.Fatalf("ImportQR: %v", err)
	}
	// Демона в тесте нет: ImportQR вернул ErrDaemonDown и пустую сводку, но
	// конфиг уже заменён атомарно — проверяем именно файл.
	if err == nil && !strings.Contains(summary, "2 правил") {
		t.Fatalf("сводка = %q, ждали 2 правила (маркер default не правило)", summary)
	}
	cfg, err := loadCurrentConfig(c.configPath())
	if err != nil {
		t.Fatalf("конфиг не читается после импорта: %v", err)
	}
	if len(cfg.Rules) != 2 {
		t.Fatalf("правил %d, ждали 2: %+v", len(cfg.Rules), cfg.Rules)
	}
	if cfg.Rules[0].CIDR != "10.0.0.0/8" || strings.ToLower(cfg.Rules[0].Action.String()) != "direct" {
		t.Fatalf("первое правило искажено: %+v", cfg.Rules[0])
	}
	if cfg.Rules[1].SNI != "youtube.com" || strings.ToLower(cfg.Rules[1].Action.String()) != "tunnel" {
		t.Fatalf("второе правило искажено: %+v", cfg.Rules[1])
	}
	// Каналы из QR применяются: без них телефон приехал бы с пустым туннелем.
	if cfg.Tunnels == nil || cfg.Tunnels.TCP == nil {
		t.Fatalf("каналы не применились: %+v", cfg.Tunnels)
	}
	if cfg.Tunnels.TCP.Host != "203.0.113.10" {
		t.Fatalf("хост канала = %q", cfg.Tunnels.TCP.Host)
	}
	// desync телефон не присылал — откалиброванное значение должно уцелеть.
	if cfg.Desync.Strategy != "fake_split" || cfg.Desync.TTL != 4 {
		t.Fatalf("desync перетёрт импортом: %+v", cfg.Desync)
	}
}

func TestExportQRCarriesChannelsAndRules(t *testing.T) {
	c := qrController(t, qrTestYAML)
	if err := saveLinksFile(qrTestYAML); err != nil {
		t.Fatalf("links: %v", err)
	}
	b, err := c.ExportQR()
	if err != nil {
		t.Fatalf("ExportQR: %v", err)
	}
	raw, err := decodeQRPayload(b.Text)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("payload не JSON: %v", err)
	}
	rules, _ := doc["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("правил в payload %d, ждали 3", len(rules))
	}
	first, _ := rules[0].(map[string]any)
	if first["geoip"] != "ru" || first["action"] != "desync" {
		t.Fatalf("правило не то: %+v", first)
	}
	if _, ok := doc["desync"]; !ok {
		t.Fatal("desync не уехал — телефон не узнает про fake_split")
	}
}
