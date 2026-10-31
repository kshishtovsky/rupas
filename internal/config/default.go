package config

// Default returns the default profile for the home RU ISP from the lab
// data (PRD §2, §5, appendix A; SYSTEM_DESIGN §4.3):
//   - YouTube/Discord are SNI-blackholed by the TSPU -> DESYNC (fake TTL=13);
//   - Telegram is IP-blackholed -> TUNNEL for its CIDRs;
//   - Discord voice UDP 50000-65535 is dead -> TUNNEL;
//   - everything else stays DIRECT.
//
// Wave 7 default-vs-user asymmetry: Default() keeps the LAB-CALIBRATED
// desync profile for every SNI (fake TTL=13 measured stable in the lab).
// The USER config (configs/rupas.yaml) carries the tunnel OVERRIDES for
// the SNIs where the fake proved unstable in live probes — the defaults
// stay honest to the lab data and the operator tunes per ISP.
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
			// Wave 7: wider Discord/YouTube coverage. desync is the lab
			// default here too — users on an unstable fake ISP switch
			// these to `action: tunnel` (see configs/rupas.yaml).
			{SNI: "*.discordapp.com", Action: ActionDesync},
			{SNI: "media.discordapp.net", Action: ActionDesync},
			{SNI: "discord.gg", Action: ActionDesync},
			{SNI: "*.discord.gg", Action: ActionDesync},
			{SNI: "youtube.com", Action: ActionDesync},
			{CIDR: "149.154.160.0/20", Action: ActionTunnel},
			{CIDR: "91.108.0.0/16", Action: ActionTunnel},
			{CIDR: "95.161.76.100/32", Action: ActionTunnel},
			// Wave 7: Telegram web/DC5 ranges live-proven blackholed.
			{CIDR: "91.105.192.0/23", Action: ActionTunnel},
			{CIDR: "185.76.151.0/24", Action: ActionTunnel},
			{Ports: "50000-65535", Action: ActionTunnel},
			{Action: ActionDirect}, // default rule
		},
		Desync: DesyncParams{
			Strategy:     "fake",
			FakeTemplate: "fake-chrome.bin",
			TTL:          13,
			TTLMargin:    2,
			Repeats:      6,
		},
	}
}
