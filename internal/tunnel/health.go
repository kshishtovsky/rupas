package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"time"
)

// healthLoop probes the marker URL through the tunnel every
// t.healthInterval. Health starts unknown (false); one success sets it,
// HealthFailThreshold consecutive failures clear it (§6).
func (t *tunnel) healthLoop() {
	t.probeOnce()
	ticker := time.NewTicker(t.healthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.probeOnce()
		}
	}
}

func (t *tunnel) probeOnce() {
	ctx, cancel := context.WithTimeout(t.ctx, markerTimeout)
	defer cancel()
	err := t.probe(ctx)
	if err == nil {
		if t.failStreak.Swap(0) > 0 || !t.healthy.Load() {
			t.logger.Info("tunnel marker ok", slog.String("marker", t.opts.MarkerURL))
		}
		t.healthy.Store(true)
		return
	}
	streak := t.failStreak.Add(1)
	down := streak >= HealthFailThreshold
	if down {
		was := t.healthy.Swap(false)
		if was {
			t.logger.Warn("tunnel marked UNHEALTHY",
				slog.Int("fail_streak", int(streak)), slog.Any("err", err))
		} else {
			t.logger.Warn("tunnel still unhealthy",
				slog.Int("fail_streak", int(streak)), slog.Any("err", err))
		}
		return
	}
	t.logger.Warn("tunnel marker failed",
		slog.Int("fail_streak", int(streak)), slog.Any("err", err))
}

// probe issues one GET to the marker URL through the sing-box mixed inbound
// (i.e. through VLESS+Reality). A 2xx answer counts as success.
func (t *tunnel) probe(ctx context.Context) error {
	if t.probeFunc != nil { // test seam
		return t.probeFunc(ctx)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.opts.MarkerURL, nil)
	if err != nil {
		return err
	}
	client := &http.Client{
		Transport: &http.Transport{
			DisableKeepAlives: true,
			// Dial through the tunnel: mixed inbound → vless outbound → exit.
			DialContext: func(ctx context.Context, network, addrS string) (net.Conn, error) {
				host, portS, err := net.SplitHostPort(addrS)
				if err != nil {
					return nil, err
				}
				port, err := strconv.ParseUint(portS, 10, 16)
				if err != nil {
					return nil, err
				}
				return t.tr.dialHost(ctx, host, uint16(port))
			},
		},
		Timeout: 0, // bounded by ctx
	}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("marker request: %w", err)
	}
	resp.Body.Close() //nolint:errcheck // marker has no body of interest
	if sc := resp.StatusCode; sc/100 == 2 {
		return nil
	}
	return fmt.Errorf("marker status %d", resp.StatusCode)
}

// tickNow advances the health state machine on demand (tests).
func (t *tunnel) tickNow() { t.probeOnce() }
