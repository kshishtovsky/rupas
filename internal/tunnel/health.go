package tunnel

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
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
			t.logger.Warn("tunnel marked UNHEALTHY; TG flows HELD (dropped) until recovery",
				slog.Int("fail_streak", int(streak)), slog.Any("err", err))
		} else if streak == HealthFailThreshold {
			t.logger.Warn("tunnel entering HOLD: new flows dropped with a counter",
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

// probe issues one GET to the marker URL through the TCP carrier chain
// (primary endpoint, then the fallback — any path answering counts). A 2xx
// answer counts as success.
func (t *tunnel) probe(ctx context.Context) error {
	if t.probeFunc != nil { // test seam
		return t.probeFunc(ctx)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, t.opts.MarkerURL, nil)
	if err != nil {
		return err
	}
	chain := t.tcpChain()
	var lastErr error
	for i, path := range chain {
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
					return path.c.dialHost(ctx, host, uint16(port))
				},
			},
			Timeout: 0, // bounded by ctx
		}
		resp, err := client.Do(req.Clone(ctx))
		if err != nil {
			pathErr := fmt.Errorf("marker via %s: %w", path.name, err)
			t.logger.Warn("tunnel marker path failed",
				slog.String("path", path.name), slog.Any("err", err))
			lastErr = errors.Join(lastErr, pathErr)
			continue
		}
		resp.Body.Close() //nolint:errcheck // marker has no body of interest
		if sc := resp.StatusCode; sc/100 == 2 {
			if i > 0 {
				t.logger.Warn("tunnel marker answered by the FALLBACK path",
					slog.String("path", path.name),
					slog.String("primary", chain[0].name))
			}
			return nil
		}
		lastErr = errors.Join(lastErr, fmt.Errorf("marker via %s: status %d", path.name, resp.StatusCode))
	}
	return lastErr
}

// udpHealthLoop probes the UDP path with a STUN binding request through
// the PRIMARY UDP carrier every t.udpHealthInterval (§6 wave 5): 3
// consecutive failures mark the UDP tunnel unhealthy and switch UDP
// pseudo-sessions to the xudp fallback over the TCP endpoint; the first
// success switches back. Skipped when no fallback carrier exists or the
// probe is disabled.
func (t *tunnel) udpHealthLoop() {
	if t.opts.STUNServer == "off" || len(t.udpChain()) < 2 {
		return
	}
	t.udpProbeOnce()
	ticker := time.NewTicker(t.udpHealthInterval)
	defer ticker.Stop()
	for {
		select {
		case <-t.ctx.Done():
			return
		case <-ticker.C:
			t.udpProbeOnce()
		}
	}
}

// udpSTUNAddr resolves the configured STUN server (cached).
func (t *tunnel) udpSTUNAddr(ctx context.Context) (netip.AddrPort, error) {
	t.stunAddrOnce.Do(func() {
		host, portS, err := net.SplitHostPort(t.opts.STUNServer)
		if err != nil {
			t.stunAddrErr = err
			return
		}
		port, err := strconv.ParseUint(portS, 10, 16)
		if err != nil {
			t.stunAddrErr = err
			return
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil || len(ips) == 0 {
			t.stunAddrErr = fmt.Errorf("resolve %s: %v", host, err)
			return
		}
		ip := ips[0].Unmap()
		t.stunAddr = netip.AddrPortFrom(ip, uint16(port))
	})
	return t.stunAddr, t.stunAddrErr
}

// resolveProbeAddr resolves a probe target "host:port" (IP literals skip
// resolution).
func (t *tunnel) resolveProbeAddr(ctx context.Context, hp string) (netip.AddrPort, error) {
	host, portS, err := net.SplitHostPort(hp)
	if err != nil {
		return netip.AddrPort{}, err
	}
	port, err := strconv.ParseUint(portS, 10, 16)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return netip.AddrPortFrom(ip.Unmap(), uint16(port)), nil
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return netip.AddrPort{}, fmt.Errorf("resolve %s: %v", host, err)
	}
	return netip.AddrPortFrom(ips[0].Unmap(), uint16(port)), nil
}

func (t *tunnel) udpProbeOnce() {
	chain := t.udpChain()
	primary := chain[0]
	ctx, cancel := context.WithTimeout(t.ctx, 2*stunTimeout) // stun + dns rounds
	defer cancel()
	method, err := t.udpProbePath(ctx, primary.c)
	if err == nil {
		t.udpFailStreak.Store(0)
		t.udpHealthy.Store(true)
		if t.activeUDP.Swap(0) != 0 {
			t.logger.Info("udp tunnel healthy again; UDP flows returned to the primary",
				slog.String("path", primary.name), slog.String("via", method))
		}
		return
	}
	t.udpHealthy.Store(false)
	streak := t.udpFailStreak.Add(1)
	if streak >= HealthFailThreshold && t.activeUDP.Load() == 0 {
		t.activeUDP.Store(1)
		t.logger.Warn("udp tunnel UNHEALTHY; UDP flows switched to the xudp fallback over the TCP endpoint",
			slog.Int("fail_streak", int(streak)),
			slog.String("primary", primary.name),
			slog.String("fallback", chain[len(chain)-1].name),
			slog.Any("err", err))
	} else {
		t.logger.Warn("udp health probe failed",
			slog.Int("fail_streak", int(streak)), slog.Any("err", err))
	}
}

// tickNow advances the health state machine on demand (tests).
func (t *tunnel) tickNow() { t.probeOnce() }
