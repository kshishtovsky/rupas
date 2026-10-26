// service.go — Wails-bound methods callable from the frontend (frontend/dist/app.js).
// Everything is a thin wrapper: RPC to the daemon, file writes for config,
// marker file for onboarding state (GUI_DESIGN §5-§6).
package guictrl

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/rupas/rupas/internal/config"
	"github.com/rupas/rupas/internal/geoip"
)

// On sends the RPC `on` (assumes EnsureDaemon already ran).
func (c *Controller) On() error { return c.simpleRPC("on") }

// Off sends the RPC `off` (interception stops, daemon keeps running).
func (c *Controller) Off() error { return c.simpleRPC("off") }

// Logs returns the daemon lifecycle log tail (last N events).
func (c *Controller) Logs() ([]string, error) {
	return CallLogs(c.opts.Pipe, 3*time.Second)
}

// ParseChannels parses the multi-line links blob for the Settings priority
// list (Android W3 parity: channels in dial order).
func (c *Controller) ParseChannels(blob string) ([]Channel, error) {
	return ParseChannels(blob)
}

func (c *Controller) simpleRPC(cmd string) error {
	resp, err := CallPipe(c.opts.Pipe, cmd, 5*time.Second)
	if err != nil {
		return fmt.Errorf("демон недоступен: %w", err)
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	return nil
}

// ReloadConfig asks the daemon to hot-reload the YAML (wizard step «assets»).
func (c *Controller) ReloadConfig() error { return c.simpleRPC("reload") }

// PrepareAssets pre-downloads the GeoIP country table used by the preset
// rules (geoip: ru) so the first daemon compile is not network-bound.
func (c *Controller) PrepareAssets() error {
	p := geoip.Params{}.WithDefaults()
	if root := c.repoRoot(); root != "" {
		p.Dir = filepath.Join(root, "build")
	}
	_, err := geoip.List(p, "ru")
	return err
}

// repoRoot guesses the repo root from the config location (<root>/configs/).
func (c *Controller) repoRoot() string {
	cfg := c.configPath()
	if cfg == "" {
		return ""
	}
	dir := filepath.Dir(cfg)
	if filepath.Base(dir) == "configs" {
		return filepath.Dir(dir)
	}
	return dir
}

func (c *Controller) configPath() string {
	if c.opts.ConfigPath != "" {
		return c.opts.ConfigPath
	}
	return DefaultConfigPath()
}

// ---------- links-based config (Android W3 "universal config" parity) ----------

// SaveLinks parses the links blob (dial order), maps channels onto the
// desktop plan (tcp/udp/fallback), writes the config (validate → .bak →
// atomic replace → daemon reload → rollback on refusal) and remembers the
// blob. Returns per-channel warnings (trojan/ws/… links are skipped).
func (c *Controller) SaveLinks(blob string) ([]string, error) {
	tcp, udp, fb, warnings, err := channelsToPlan(blob)
	if err != nil {
		return warnings, err
	}
	cfg := presetConfig(true)
	if tcp != nil || udp != nil || fb != nil {
		cfg.Tunnels = &config.TunnelConfig{TCP: tcp, UDP: udp, Fallback: fb}
	}
	if err := c.writeConfig(cfg); err != nil {
		return warnings, err
	}
	if err := saveLinksFile(blob); err != nil {
		return warnings, fmt.Errorf("конфиг сохранён, но список ссылок — нет: %w", err)
	}
	c.setGateway(tcp, udp)
	return warnings, nil
}

// writeConfig runs the TUI save contract: engine validation on a temp file,
// backup, atomic replace, hot-reload a live daemon, rollback on refusal.
func (c *Controller) writeConfig(cfg config.Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	path := c.configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if _, err := config.Load(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("конфиг не прошёл валидацию: %w", err)
	}
	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, path+".bak")
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if resp, err := CallPipe(c.opts.Pipe, "reload", 5*time.Second); err == nil && !resp.OK {
		_ = os.Rename(path+".bak", path)
		return fmt.Errorf("демон отклонил конфиг: %s (откат)", resp.Error)
	}
	return nil
}

// GUIState is everything the Settings screen loads in one call.
type GUIState struct {
	Links     string `json:"links"`
	DPI       bool   `json:"dpi"`
	Autostart bool   `json:"autostart"`
	Gateway   string `json:"gateway"`
}

// LoadState returns the persisted links blob + flags for Settings.
func (c *Controller) LoadState() GUIState {
	st := GUIState{DPI: true}
	if blob, err := loadLinksFile(); err == nil {
		st.Links = blob
	}
	st.Autostart = c.Autostart()
	if gw := c.gateway(); gw != "" {
		st.Gateway = gw
	} else if tcp, udp, _, _, err := channelsToPlan(st.Links); err == nil {
		c.setGateway(tcp, udp)
		st.Gateway = c.gateway()
	}
	return st
}

// presetConfig builds the default rule set with the owner routing policy
// (2026-10-25) + Android W3 parity: RU zones and RU-services-on-.com →
// direct, YT → desync, Discord/TG → tunnel, QUIC block, default direct.
func presetConfig(dpi bool) config.Config {
	ruServices := []string{
		"vk.com", "*.vk.com", "ok.ru", "*.ok.ru", "userapi.com", "*.userapi.com",
		"ya.ru", "*.ya.ru", "yandex.net", "*.yandex.net",
		"steamcontent.com", "steamserver.net", "steampipe.akamaized.net",
		"steamstatic.com", "steampowered.com",
	}
	rules := []config.Rule{
		{SNI: "www.youtube.com", Action: config.ActionDesync},
		{SNI: "*.googlevideo.com", Action: config.ActionDesync},
	}
	for _, d := range ruServices {
		rules = append(rules, config.Rule{SNI: d, Action: config.ActionDirect})
	}
	rules = append(rules,
		config.Rule{SNI: "discord.com", Action: config.ActionTunnel},
		config.Rule{SNI: "*.discord.gg", Action: config.ActionTunnel},
		config.Rule{SNI: "*.discordapp.com", Action: config.ActionTunnel},
		config.Rule{SNI: "*.discordapp.net", Action: config.ActionTunnel},
		config.Rule{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
		config.Rule{CIDR: "91.108.0.0/16", Action: config.ActionTunnel},
		config.Rule{CIDR: "91.105.192.0/23", Action: config.ActionTunnel},
		config.Rule{CIDR: "185.76.151.0/24", Action: config.ActionTunnel},
		config.Rule{GeoIP: "ru", Action: config.ActionDirect},
		config.Rule{Ports: "443", Proto: "udp", Action: config.ActionBlock},
		config.Rule{Action: config.ActionDirect},
	)
	cfg := config.Config{Profile: "gui", Rules: rules}
	if dpi {
		cfg.Desync = config.DesyncParams{Strategy: "fake", TTL: 13, TTLMargin: 2, Repeats: 6}
	}
	return cfg
}

// ---------- links + gateway persistence ----------

func stateDir() string {
	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "rupas")
}

func linksPath() string  { return filepath.Join(stateDir(), "links.json") }
func markerPath() string { return filepath.Join(stateDir(), "onboarded.json") }

func saveLinksFile(blob string) error {
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]string{"links": blob})
	return os.WriteFile(linksPath(), data, 0o600)
}

func loadLinksFile() (string, error) {
	data, err := os.ReadFile(linksPath())
	if err != nil {
		return "", err
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return "", err
	}
	return m["links"], nil
}

// setGateway remembers the primary channel for the Home «Шлюз» line.
func (c *Controller) setGateway(tcp, udp *config.Endpoint) {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case tcp != nil:
		c.gatewayHost = fmt.Sprintf("%s:%d (%s)", tcp.Host, tcp.Port, tcp.Kind)
	case udp != nil:
		c.gatewayHost = fmt.Sprintf("%s:%d (%s)", udp.Host, udp.Port, udp.Kind)
	default:
		c.gatewayHost = ""
	}
}

func (c *Controller) gateway() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.gatewayHost
}

// ---------- onboarding marker (GUI_DESIGN §5) ----------

// Onboarded reports whether the first-run wizard has been completed.
func (c *Controller) Onboarded() bool {
	data, err := os.ReadFile(markerPath())
	if err != nil {
		return false
	}
	var m struct {
		Done bool `json:"done"`
	}
	return json.Unmarshal(data, &m) == nil && m.Done
}

// FinishOnboarding persists the wizard completion marker.
func (c *Controller) FinishOnboarding() error {
	if err := os.MkdirAll(stateDir(), 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]any{"done": true, "at": time.Now().Format(time.RFC3339)})
	return os.WriteFile(markerPath(), data, 0o600)
}
