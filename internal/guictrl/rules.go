// rules.go — the Routing screen bridge (docs/ROUTING_UI.md §2-§6, §10).
//
// Everything here works on the YAML config file, not on the daemon: the
// screen can be opened, edited and probed while rupasd is down, and the
// engine's own validators (config.Validate + the table compiler's overlap
// check) decide what is legal. Saving goes through the same contract as the
// rest of the GUI: validate → .bak → atomic replace → daemon reload with
// rollback on refusal (writeConfig), so rules are applied without breaking
// live connections.
package guictrl

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"

	"github.com/kshishtovsky/rupas/internal/config"
	"github.com/kshishtovsky/rupas/internal/geoip"
	"github.com/kshishtovsky/rupas/internal/rules"
)

// Rule kinds rendered by the screen: one per matcher, exactly the keys the
// §10 JSON uses ("sni" covers both an exact name and a "*.suffix" wildcard).
const (
	KindCIDR    = "cidr"
	KindGeoIP   = "geoip"
	KindSNI     = "sni"
	KindPorts   = "ports"
	KindDefault = "default"
)

// RuleView is one rule as the Routing screen renders and edits it.
// Matcher is the RAW matcher value ("10.0.0.0/8", "ru", "*.googlevideo.com",
// "50000-65535") — Kind tells the UI how to decorate it (the screen shows
// geoip as "geoip: ru") and how to build the JSON back on save. Human is the
// second-line hint under the matcher.
type RuleView struct {
	Kind    string `json:"kind"`
	Matcher string `json:"matcher"`
	Human   string `json:"human"`
	Action  string `json:"action"` // DIRECT | TUNNEL | DESYNC | BLOCK
	Proto   string `json:"proto"`  // "" | "tcp" | "udp"
	Index   int    `json:"index"`  // position in the rule list (-1 when absent)
}

// RulesView is the whole data payload of the screen: the stage-ordered rule
// list, the pinned default zone and the per-stage counters.
// Error carries the engine's verbatim message when the stored rule set does
// not compile; the list is still returned so the screen can point at it.
type RulesView struct {
	Rules       []RuleView `json:"rules"`
	Default     RuleView   `json:"default"`
	StageCounts [3]int     `json:"stageCounts"` // 1 IP, 2 domains, 3 ports
	Error       string     `json:"error,omitempty"`
}

// LoadRules returns the stored rule set for the Routing screen. A read
// failure is returned as an error; a rule set that fails engine validation is
// returned in the view (Error) with a nil error, because the list must still
// be rendered (§6 "error (чтение)" vs a broken rule).
func (c *Controller) LoadRules() (RulesView, error) {
	cfg, err := c.loadConfigForRules()
	if err != nil {
		msg := "не удалось прочитать правила: " + firstLine(err)
		return RulesView{Error: msg}, errors.New(msg)
	}
	view := buildRulesView(cfg.Rules)
	// Validate a copy: ValidateRules normalizes (lower-cases) SNI in place.
	if verr := config.ValidateRules(append([]config.Rule(nil), cfg.Rules...)); verr != nil {
		view.Error = firstLine(verr)
	}
	return view, nil
}

// SaveRules validates the JSON rule array with the engine's validators and
// writes it into the config, keeping tunnel/exclusions/geoip untouched. The
// daemon is reloaded (no connection break); a refusal rolls the file back.
func (c *Controller) SaveRules(jsonRules string) error {
	newRules, err := config.ParseRulesJSON([]byte(jsonRules))
	if err != nil {
		return err
	}
	base, err := c.loadConfigForRules()
	if err != nil {
		return fmt.Errorf("конфиг недоступен: %w", err)
	}
	base.Rules = newRules
	return c.writeConfig(base)
}

// TestRoute traces a probe ("youtube.com", "8.8.8.8", "1.2.3.4:443") against
// the stored rules and returns the Trace as JSON.
func (c *Controller) TestRoute(query string) (string, error) {
	cfg, err := c.loadConfigForRules()
	if err != nil {
		return "", fmt.Errorf("правила недоступны: %w", err)
	}
	tr, err := rules.TestRouteWithGeo(cfg.Rules, query, c.geoParams(cfg))
	if err != nil {
		return "", err
	}
	b, err := json.Marshal(tr)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// PresetNames returns the preset identifiers ApplyPreset accepts, in display
// order. The screen owns the localized labels.
func PresetNames() []string {
	return []string{PresetOwner, PresetRUDirect, PresetAllTunnel, PresetAllDirect}
}

// Preset identifiers (§5.6).
const (
	// PresetOwner is the owner's production policy (configs/rupas.yaml).
	PresetOwner = "owner"
	// PresetRUDirect keeps RU destinations and the LAN off the tunnel.
	PresetRUDirect = "ru-direct"
	// PresetAllTunnel sends everything through the tunnel.
	PresetAllTunnel = "all-tunnel"
	// PresetAllDirect sends everything directly (dangerous: the real IP is
	// visible; the screen must double-confirm this one).
	PresetAllDirect = "all-direct"
)

// ApplyPreset replaces the whole rule set with a preset and applies it through
// the save contract. Presets are plain rule lists, so nothing here duplicates
// the engine: the owner preset IS the production one (presetConfig).
func (c *Controller) ApplyPreset(name string) error {
	preset, err := presetRules(name)
	if err != nil {
		return err
	}
	base, err := c.loadConfigForRules()
	if err != nil {
		return fmt.Errorf("конфиг недоступен: %w", err)
	}
	base.Rules = preset
	return c.writeConfig(base)
}

// presetRules returns the rule list of a named preset.
func presetRules(name string) ([]config.Rule, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case PresetOwner, "":
		return presetConfig(true).Rules, nil
	case PresetRUDirect:
		return ruDirectRules(), nil
	case PresetAllTunnel:
		return []config.Rule{{Action: config.ActionTunnel}}, nil
	case PresetAllDirect:
		return []config.Rule{{Action: config.ActionDirect}}, nil
	}
	return nil, fmt.Errorf("неизвестный пресет %q (want %s)", name, strings.Join(PresetNames(), "|"))
}

// ruDirectRules is the "RU напрямую, остальное в туннель" preset: the LAN and
// the RU space stay off the tunnel, everything else is tunnelled.
func ruDirectRules() []config.Rule {
	sni := func(s string) config.Rule { return config.Rule{SNI: s, Action: config.ActionDirect} }
	cidr := func(s string) config.Rule { return config.Rule{CIDR: s, Action: config.ActionDirect} }
	out := []config.Rule{
		cidr("10.0.0.0/8"),
		cidr("172.16.0.0/12"),
		cidr("192.168.0.0/16"),
		cidr("169.254.0.0/16"),
		{GeoIP: "ru", Action: config.ActionDirect},
	}
	for _, zone := range []string{"*.ru", "*.su", "*.xn--p1ai", "*.xn--80adxhks", "*.xn--80asehdb", "*.xn--d1acj3b", "*.xn--90ais"} {
		out = append(out, sni(zone))
	}
	for _, svc := range []string{"vk.com", "ok.ru", "userapi.com", "yandex.net", "ya.ru"} {
		out = append(out, sni(svc), sni("*."+svc))
	}
	return append(out, config.Rule{Action: config.ActionTunnel})
}

// buildRulesView projects the rule list onto the screen's stage sections. The
// default rule is pulled out of the list into the pinned zone (§4.1) but keeps
// its list position in Index so the editor can write it back.
func buildRulesView(list []config.Rule) RulesView {
	view := RulesView{
		Rules: make([]RuleView, 0, len(list)),
		Default: RuleView{
			Kind: KindDefault, Matcher: "default", Human: "весь прочий трафик",
			Action: config.ActionDirect.String(), Index: -1,
		},
	}
	for i, r := range list {
		rv := RuleView{Index: i, Action: r.Action.String(), Proto: r.Proto}
		switch {
		case r.CIDR != "":
			rv.Kind, rv.Matcher = KindCIDR, r.CIDR
			rv.Human = cidrHuman(r.CIDR)
			view.StageCounts[0]++
		case r.GeoIP != "":
			rv.Kind, rv.Matcher = KindGeoIP, r.GeoIP
			rv.Human = "таблица стран, обновляется раз в 30 дней"
			view.StageCounts[0]++
		case strings.HasPrefix(r.SNI, "*."):
			rv.Kind, rv.Matcher = KindSNI, r.SNI
			rv.Human = "все поддомены " + strings.TrimPrefix(r.SNI, "*.")
			view.StageCounts[1]++
		case r.SNI != "":
			rv.Kind, rv.Matcher = KindSNI, r.SNI
			rv.Human = "точное имя"
			view.StageCounts[1]++
		case r.Ports != "":
			rv.Kind, rv.Matcher = KindPorts, r.Ports
			rv.Human = portsHuman(r.Ports, r.Proto)
			view.StageCounts[2]++
		default:
			rv.Kind, rv.Matcher = KindDefault, "default"
			rv.Human = "весь прочий трафик"
			view.Default = rv
			continue
		}
		view.Rules = append(view.Rules, rv)
	}
	return view
}

// cidrHuman renders the covered address count of a CIDR ("/23 = 512 адресов").
func cidrHuman(spec string) string {
	_, ipnet, err := net.ParseCIDR(spec)
	if err != nil {
		return ""
	}
	ones, bits := ipnet.Mask.Size()
	hostBits := bits - ones
	if hostBits > 63 {
		return "диапазон IPv6"
	}
	count := uint64(1) << uint(hostBits)
	return fmt.Sprintf("%d %s", count, plural(count, "адрес", "адреса", "адресов"))
}

// portsHuman renders a port rule as prose: "порты 50000–65535 (udp)".
func portsHuman(spec, proto string) string {
	label := "порты " + strings.ReplaceAll(spec, "-", "–")
	if proto != "" {
		label += " (" + proto + ")"
	} else if !strings.Contains(spec, "-") && !strings.Contains(spec, ",") {
		label = "порт " + spec
	}
	return label
}

// plural picks the Russian plural form for n.
func plural(n uint64, one, few, many string) string {
	switch {
	case n%10 == 1 && n%100 != 11:
		return one
	case n%10 >= 2 && n%10 <= 4 && (n%100 < 12 || n%100 > 14):
		return few
	}
	return many
}

// loadConfigForRules returns the config the screen edits: the YAML on disk, or
// the production preset when onboarding has not written one yet (the screen is
// then showing exactly what the daemon would start with).
func (c *Controller) loadConfigForRules() (config.Config, error) {
	path := c.configPath()
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return presetConfig(true), nil
		}
		return config.Config{}, err
	}
	cfg, err := config.Load(path)
	if err != nil {
		return config.Config{}, err
	}
	return *cfg, nil
}

// geoParams points the tracer at the geoip cache the daemon uses: the
// configured geoip.dir, else "build" in the repo root.
func (c *Controller) geoParams(cfg config.Config) geoip.Params {
	if cfg.GeoIP != nil && cfg.GeoIP.Dir != "" {
		return geoip.Params{
			Dir:         cfg.GeoIP.Dir,
			RefreshDays: cfg.GeoIP.RefreshDays,
			Mirrors:     cfg.GeoIP.Mirrors,
		}
	}
	dir := "build"
	if root := c.repoRoot(); root != "" {
		dir = filepath.Join(root, "build")
	}
	return geoip.Params{Dir: dir}
}

// firstLine keeps UI messages to one line (§6: the first engine error line).
func firstLine(err error) string {
	if err == nil {
		return ""
	}
	line, _, _ := strings.Cut(err.Error(), "\n")
	return line
}
