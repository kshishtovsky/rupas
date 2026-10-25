package android

import (
	"net/netip"
	"testing"
)

func TestW2PolicyVerdict(t *testing.T) {
	quic := FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:443")}
	tcp443 := FlowMeta{Network: "tcp", Destination: netip.MustParseAddrPort("142.250.0.1:443")}
	dns := FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("8.8.8.8:53")}
	udpOther := FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("149.154.167.51:443")} // TG DC UDP — не 443? это 443. замена:
	udpTG := FlowMeta{Network: "udp", Destination: netip.MustParseAddrPort("149.154.167.51:5228")}

	if W2PolicyVerdict(quic) != ActionBlock {
		t.Error("QUIC (udp/443) must be BLOCKed")
	}
	if W2PolicyVerdict(tcp443) != ActionDirect {
		t.Error("tcp/443 must stay DIRECT")
	}
	if W2PolicyVerdict(dns) != ActionDirect {
		t.Error("DNS must stay DIRECT")
	}
	if W2PolicyVerdict(udpOther) != ActionBlock {
		t.Error("udp/443 to any dst must be BLOCKed")
	}
	if W2PolicyVerdict(udpTG) != ActionDirect {
		t.Error("non-443 UDP must stay DIRECT")
	}
}
