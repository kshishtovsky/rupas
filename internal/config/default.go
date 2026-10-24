package config

// Default returns the default profile for the home RU ISP from the lab
// data (PRD §2, §5, appendix A; SYSTEM_DESIGN §4.3):
//   - YouTube/Discord are SNI-blackholed by the TSPU -> DESYNC (fake TTL=13);
//   - Telegram is IP-blackholed -> TUNNEL for its CIDRs;
//   - Discord voice UDP 50000-65535 is dead -> TUNNEL;
//   - everything else stays DIRECT.
//
// The tunnel endpoint is intentionally empty: the VPS is attached at
// runtime via QR/link import (PRD US-5).
func Default() *Config {
	return &Config{
		Profile: "isp-home-2025-10-25",
		Rules: []Rule{
			{SNI: "www.youtube.com", Action: ActionDesync},
			{SNI: "*.googlevideo.com", Action: ActionDesync},
			{SNI: "discord.com", Action: ActionDesync},
			{SNI: "gateway.discord.gg", Action: ActionDesync},
			{CIDR: "149.154.160.0/20", Action: ActionTunnel},
			{CIDR: "91.108.0.0/16", Action: ActionTunnel},
			{CIDR: "95.161.76.100/32", Action: ActionTunnel},
			{Ports: "50000-65535", Action: ActionTunnel},
			{Action: ActionDirect}, // default rule
		},
		Desync: DesyncParams{
			Strategy:     "fake",
			FakeTemplate: "chrome-124-pq.bin",
			TTL:          13,
			TTLMargin:    2,
			Repeats:      6,
		},
	}
}
