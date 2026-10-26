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

// EndpointInput is the tunnel form payload from the frontend.
type EndpointInput struct {
	Host string `json:"host"`
	Port int    `json:"port"`
	UUID string `json:"uuid"`
	SNI  string `json:"sni"`
	PBK  string `json:"pbk"`
	SID  string `json:"sid"`
	DPI  bool   `json:"dpi"`
}

// On sends the RPC `on` (assumes EnsureDaemon already ran).
func (c *Controller) On() error { return c.simpleRPC("on") }

// Off sends the RPC `off` (interception stops, daemon keeps running).
func (c *Controller) Off() error { return c.simpleRPC("off") }

// Logs returns the daemon lifecycle log tail (last N events).
func (c *Controller) Logs() ([]string, error) {
	return CallLogs(c.opts.Pipe, 3*time.Second)
}

// ParseVless parses a vless:// share link for the frontend forms.
func (c *Controller) ParseVless(link string) (VlessLink, error) {
	return ParseVlessLink(link)
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

// SaveConfig writes the config from the endpoint form: validate via
// config.Load on a temp file → backup → atomic replace → daemon reload →
// rollback on reload refusal (same contract as the TUI, SYSTEM_DESIGN §9).
// An empty host clears the tunnel (desync-only mode).
func (c *Controller) SaveConfig(in EndpointInput) error {
	cfg := presetConfig(in)
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	path := c.configPath()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}

	// Validate via the engine itself (config.Load) on a temp file.
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if _, err := config.Load(tmp); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("конфиг не прошёл валидацию: %w", err)
	}

	// Backup + atomic replace.
	if _, err := os.Stat(path); err == nil {
		_ = os.Rename(path, path+".bak")
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}

	// Hot-reload a live daemon; offline daemon keeps the file (TUI contract).
	if resp, err := CallPipe(c.opts.Pipe, "reload", 5*time.Second); err == nil && !resp.OK {
		_ = os.Rename(path+".bak", path)
		return fmt.Errorf("демон отклонил конфиг: %s (откат)", resp.Error)
	}
	return nil
}

// presetConfig builds the default rule set (rupas.example.yaml preset) with
// the user's endpoint plugged into tunnels.tcp. Owner routing policy
// (2026-10-25): RU → direct, YT → desync, Discord/TG → tunnel, default direct.
func presetConfig(in EndpointInput) config.Config {
	cfg := config.Config{
		Profile: "gui-onboarding",
		Rules: []config.Rule{
			{SNI: "www.youtube.com", Action: config.ActionDesync},
			{SNI: "*.googlevideo.com", Action: config.ActionDesync},
			{SNI: "discord.com", Action: config.ActionTunnel},
			{SNI: "*.discord.gg", Action: config.ActionTunnel},
			{SNI: "*.discordapp.com", Action: config.ActionTunnel},
			{SNI: "*.discordapp.net", Action: config.ActionTunnel},
			{CIDR: "149.154.160.0/20", Action: config.ActionTunnel},
			{CIDR: "91.108.0.0/16", Action: config.ActionTunnel},
			{CIDR: "91.105.192.0/23", Action: config.ActionTunnel},
			{CIDR: "185.76.151.0/24", Action: config.ActionTunnel},
			{GeoIP: "ru", Action: config.ActionDirect},
			{Ports: "443", Proto: "udp", Action: config.ActionBlock},
			{Action: config.ActionDirect},
		},
	}
	if in.DPI {
		cfg.Desync = config.DesyncParams{Strategy: "fake", TTL: 13, TTLMargin: 2, Repeats: 6}
	}
	if in.Host != "" && in.Port > 0 && in.UUID != "" {
		ep := config.Endpoint{
			Kind: "vless_tcp",
			Host: in.Host,
			Port: uint16(in.Port),
			UUID: in.UUID,
			SNI:  in.SNI,
			ALPN: []string{"h2", "http/1.1"},
		}
		if in.PBK != "" {
			ep.Kind = "vless_reality"
			ep.RealityPBK = in.PBK
			ep.RealitySID = in.SID
		}
		cfg.Tunnels = &config.TunnelConfig{TCP: &ep}
	}
	return cfg
}

// ---------- onboarding marker (GUI_DESIGN §5) ----------

func markerPath() string {
	base := os.Getenv("LocalAppData")
	if base == "" {
		base = os.TempDir()
	}
	return filepath.Join(base, "rupas", "onboarded.json")
}

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
	p := markerPath()
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return err
	}
	data, _ := json.Marshal(map[string]any{"done": true, "at": time.Now().Format(time.RFC3339)})
	return os.WriteFile(p, data, 0o600)
}
