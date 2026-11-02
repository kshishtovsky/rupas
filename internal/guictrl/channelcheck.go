// channelcheck.go — the per-channel «Проверить» button (Android parity:
// mobile.TestProfile). One link in, one live verdict out: the endpoint's own
// carrier is brought up for the duration of the probe and closed again, so a
// broken channel is identified without touching the running tunnel.

package guictrl

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/kshishtovsky/rupas/internal/config"
	android "github.com/kshishtovsky/rupas/internal/transport/android"
	"github.com/kshishtovsky/rupas/internal/tunnel"
)

// channelProbeBudget caps the whole check; the probe itself splits it into
// dial/TLS stages.
const channelProbeBudget = 20 * time.Second

// CheckChannel probes exactly this share link. The error is a link-level
// refusal (unparseable or unsupported kind); a reachable-but-failing endpoint
// comes back as a ProbeResult with OK=false and a stage/err pair.
func (c *Controller) CheckChannel(link string) (tunnel.ProbeResult, error) {
	link = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(link), disabledMark))
	if link == "" {
		return tunnel.ProbeResult{}, errors.New("пустая ссылка")
	}
	ep, err := android.ParseShareLink(link)
	if err != nil {
		return tunnel.ProbeResult{}, err
	}
	mapped, role := endpointFor(ep)
	if role == "" {
		_, _, warning := classify(ep)
		if warning == "" {
			warning = "тип ссылки не поддерживается десктоп-ядром"
		}
		return tunnel.ProbeResult{}, errors.New(warning)
	}
	// Probe the credential that would actually be saved, not the one in a stale
	// links.json: same rule as SaveLinks, so «Проверить» and «Сохранить» agree.
	if cur, cerr := c.loadConfigForRules(); cerr == nil && cur.Tunnels != nil {
		for _, live := range []*config.Endpoint{cur.Tunnels.TCP, cur.Tunnels.UDP, cur.Tunnels.Fallback} {
			keepLiveSecret(&mapped, live) //nolint:errcheck // warning is advisory here
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), channelProbeBudget)
	defer cancel()
	r := tunnel.ProbeEndpoint(ctx, mapped, nil)
	// tmn держит пул долгих сессий: холодная — это подъём TLS+uTLS и AUTH, и на
	// живом канале замерено 12 с. Отдельно назвать самую частую причину отказа:
	// сервер ждёт authIdle (2 с), не узнаёт AUTH и отдаёт страницу прикрытия —
	// клиент видит «length > 1400». Это несовпадение ключа, а не мёртвый канал.
	if !r.OK && r.Stage == "dial" && mapped.Kind == config.KindTMN {
		if strings.Contains(r.Err, "length > 1400") {
			r.Err = "сервер не принял AUTH: PSK в ссылке не совпал с ключом сервера"
		} else {
			r.Err += " (новая сессия не поднялась; уже открытая живёт своей жизнью)"
		}
	}
	return r, nil
}
