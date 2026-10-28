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

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
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
	// Nothing parsed: writing the bare preset would drop the live tunnels,
	// exclusions and custom rules, and nil tunnels make every TUNNEL rule
	// escalate to direct. Refuse before touching the file.
	if tcp == nil && udp == nil && fb == nil {
		return warnings, errors.New("нет рабочих ссылок: нужен vless (tcp/xhttp) или hysteria2 — trojan/ws десктоп-ядро не поддерживает")
	}
	cfg := presetConfig(true)
	cfg.Tunnels = &config.TunnelConfig{TCP: tcp, UDP: udp, Fallback: fb}
	// ErrDaemonDown means "written to disk, not confirmed": keep the file
	// (design contract) but still surface it so the UI can say so.
	err = c.writeConfig(cfg)
	if err != nil && !errors.Is(err, ErrDaemonDown) {
		return warnings, err
	}
	if lerr := saveLinksFile(blob); lerr != nil {
		return warnings, fmt.Errorf("конфиг сохранён, но список ссылок — нет: %w", lerr)
	}
	c.setGateway(tcp, udp)
	return warnings, err
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
		// No backup, no save: a failed .bak (sharing violation) would make a
		// rollback restore the PREVIOUS generation and lose the last good file.
		if err := os.Rename(path, path+".bak"); err != nil {
			_ = os.Remove(tmp)
			return fmt.Errorf("не удалось создать backup %s: %w", path+".bak", err)
		}
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	resp, err := CallPipe(c.opts.Pipe, "reload", 5*time.Second)
	if err != nil {
		// Daemon unreachable: the validated config stays on disk for its next
		// start (save contract), but the save is NOT confirmed.
		return fmt.Errorf("%w — конфиг записан, демон его не загрузил: %v", ErrDaemonDown, err)
	}
	if !resp.OK {
		if err := os.Rename(path+".bak", path); err != nil {
			return fmt.Errorf("демон отклонил конфиг: %s; откат не удался: %w", resp.Error, err)
		}
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

// presetConfig builds the full production routing policy (configs/rupas.yaml
// of the owner's box, 2026-10-25/27): LAN → direct, TG CIDRs → tunnel,
// geoip:ru + RU TLDs/services → direct, YT → desync, Discord → tunnel,
// voice/STUN UDP → tunnel, DNS → direct, QUIC → block, ВСЁ ОСТАЛЬНОЕ → tunnel.
func presetConfig(dpi bool) config.Config {
	sni := func(s string, a config.Action) config.Rule { return config.Rule{SNI: s, Action: a} }
	cidr := func(s string, a config.Action) config.Rule { return config.Rule{CIDR: s, Action: a} }

	rules := []config.Rule{
		// LAN / broadcast → direct (default=tunnel would swallow them).
		cidr("10.0.0.0/8", config.ActionDirect),
		cidr("172.16.0.0/12", config.ActionDirect),
		cidr("192.168.0.0/16", config.ActionDirect),
		cidr("169.254.0.0/16", config.ActionDirect),
		cidr("224.0.0.0/4", config.ActionDirect),
		cidr("255.255.255.255/32", config.ActionDirect),
		// Telegram DCs + media: IP-blackholed → tunnel.
		cidr("149.154.160.0/20", config.ActionTunnel),
		cidr("91.108.0.0/16", config.ActionTunnel),
		cidr("91.105.192.0/23", config.ActionTunnel),
		cidr("185.76.151.0/24", config.ActionTunnel),
		cidr("95.161.76.100/32", config.ActionTunnel),
		// Country table: every RU-hosted destination → direct (VPS cannot
		// dial RU ranges anyway).
		{GeoIP: "ru", Action: config.ActionDirect},
		// YouTube: SNI-blackholed, IP fine → local desync at full speed.
		sni("www.youtube.com", config.ActionDesync),
		sni("*.googlevideo.com", config.ActionDesync),
		sni("youtube.com", config.ActionDesync),
		sni("*.youtube.com", config.ActionDesync),
		// Discord: real ECH dropped by TSPU; the only stable path is tunnel.
		sni("discord.com", config.ActionTunnel),
		sni("updates.discord.com", config.ActionTunnel),
		sni("gateway.discord.gg", config.ActionTunnel),
		sni("discord.gg", config.ActionTunnel),
		sni("*.discord.gg", config.ActionTunnel),
		sni("discordapp.com", config.ActionTunnel),
		sni("*.discordapp.com", config.ActionTunnel),
		sni("discordapp.net", config.ActionTunnel),
		sni("*.discordapp.net", config.ActionTunnel),
		// RU zones and RU services on foreign TLDs → direct.
		sni("vk.com", config.ActionDirect),
		sni("*.vk.com", config.ActionDirect),
		sni("ok.ru", config.ActionDirect),
		sni("*.ok.ru", config.ActionDirect),
		sni("userapi.com", config.ActionDirect),
		sni("*.userapi.com", config.ActionDirect),
		sni("*.ru", config.ActionDirect),
		sni("*.su", config.ActionDirect),
		sni("*.xn--p1ai", config.ActionDirect),     // .рф
		sni("*.xn--80adxhks", config.ActionDirect), // .москва
		sni("*.xn--80asehdb", config.ActionDirect), // .онлайн
		sni("*.xn--d1acj3b", config.ActionDirect),  // .дети
		sni("*.xn--90ais", config.ActionDirect),    // .бел
		sni("*.yandex.net", config.ActionDirect),
		sni("*.ya.ru", config.ActionDirect),
		sni("*.steamcontent.com", config.ActionDirect),
		sni("*.steamserver.net", config.ActionDirect),
		sni("*.steampipe.akamaized.net", config.ActionDirect),
		sni("*.steamstatic.com", config.ActionDirect),
		sni("*.steampowered.com", config.ActionDirect),
		sni("steampipe.akamaized.net", config.ActionDirect),
		// Discord voice UDP → tunnel (XUDP/hy2).
		{Ports: "50000-65535", Proto: "udp", Action: config.ActionTunnel},
		// STUN (voice handshake): UDP :3478 is TSPU-dropped → tunnel.
		{Ports: "3478", Proto: "udp", Action: config.ActionTunnel},
		// DNS → direct (no recursion through the VPS).
		{Ports: "53", Proto: "udp", Action: config.ActionDirect},
		// QUIC → block: TSPU blackholes it with residual censorship; force
		// browsers onto TCP.
		{Ports: "443", Proto: "udp", Action: config.ActionBlock},
		// Owner policy: ВСЁ ОСТАЛЬНОЕ → tunnel.
		{Action: config.ActionTunnel},
	}
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
