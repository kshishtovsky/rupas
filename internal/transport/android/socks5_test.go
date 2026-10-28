package android

// SOCKS5 frame/reply tests: the ATYP=domain forms are legal per RFC 1928
// and used to abort a live UDP session (parseUDPFrame) or a CONNECT
// (socks5ReadReplyAddr) — the address is discarded, only offsets matter.

import (
	"net"
	"testing"
	"time"
)

// buildUDPFrame hand-builds RSV FRAG ATYP=domain LEN NAME PORT PAYLOAD.
func buildUDPFrame(name, payload string, port uint16) []byte {
	b := []byte{0, 0, 0, atypName, byte(len(name))}
	b = append(b, name...)
	b = append(b, byte(port>>8), byte(port))
	return append(b, payload...)
}

func TestParseUDPFrameDomainAddr(t *testing.T) {
	name, payload := "bnd.example.net", "hi"
	b := buildUDPFrame(name, payload, 53552)
	_, off, err := parseUDPFrame(b)
	if err != nil {
		t.Fatalf("domain frame rejected: %v", err)
	}
	want := 5 + len(name) + 2
	if off != want {
		t.Fatalf("payload offset = %d, want %d", off, want)
	}
	if got := string(b[off:]); got != payload {
		t.Fatalf("payload = %q, want %q", got, payload)
	}
	// Truncated name frame must still be refused.
	if _, _, err := parseUDPFrame(b[:5+len(name)+1]); err == nil {
		t.Fatal("short name frame accepted")
	}
}

func TestSocks5ReplyDomainBindAddr(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	go func() {
		name := "bnd.example.net"
		reply := []byte{socks5Version, 0x00, 0x00, atypName, byte(len(name))}
		reply = append(reply, name...)
		reply = append(reply, 0x1f, 0x90) // port 8080
		server.Write(reply)               //nolint:errcheck
		server.Close()
	}()
	client.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	if _, err := socks5ReadReplyAddr(client); err != nil {
		t.Fatalf("domain BND.ADDR reply rejected: %v", err)
	}
}
