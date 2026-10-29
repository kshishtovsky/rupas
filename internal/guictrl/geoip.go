// geoip.go — the Routing screen's «Обновить GeoIP» button (PLAN-0.8 §5).
package guictrl

import (
	"fmt"
	"strings"

	"github.com/kshishtovsky/rupas/internal/geoip"
)

// RefreshGeoIP force-downloads every country table the stored rules use
// (cache age ignored), then hot-reloads the daemon so the new tables take
// effect. Slow by design (up to 2×30 s per country, one mirror each) — the
// UI keeps a spinner. Returns one report line per country: "ru: 8412
// префиксов" or "ru: ошибка …"; a failed country never aborts the rest.
func (c *Controller) RefreshGeoIP() ([]string, error) {
	cfg, err := c.loadConfigForRules()
	if err != nil {
		return nil, fmt.Errorf("конфиг недоступен: %w", err)
	}
	var ccs []string
	seen := make(map[string]bool, len(cfg.Rules))
	for _, r := range cfg.Rules {
		cc := strings.ToLower(strings.TrimSpace(r.GeoIP))
		if cc == "" || seen[cc] {
			continue
		}
		seen[cc] = true
		ccs = append(ccs, cc)
	}
	if len(ccs) == 0 {
		return []string{"правил с geoip нет"}, nil
	}
	p := c.geoParams(cfg)
	report := make([]string, 0, len(ccs)+1)
	for _, cc := range ccs {
		prefixes, err := geoip.Refresh(p, cc)
		if err != nil {
			report = append(report, fmt.Sprintf("%s: ошибка %s", cc, firstLine(err)))
			continue
		}
		report = append(report, fmt.Sprintf("%s: %d префиксов", cc, len(prefixes)))
	}
	if err := c.ReloadConfig(); err != nil {
		report = append(report, "reload: "+firstLine(err))
	}
	return report, nil
}
