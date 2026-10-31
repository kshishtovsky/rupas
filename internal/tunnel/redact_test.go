package tunnel

import "testing"

// Подробный лог копируется в чат: секреты канала не должны туда попадать.
func TestRedactSecrets(t *testing.T) {
	in := `{"outbounds":[{"type":"hysteria2","password":"7PRCfc5F8X"},` +
		`{"type":"vless","uuid":"d4550250-3222","tls":{"reality":{"public_key":"shVXc1ef","short_id":"999e2fd9"}}}],` +
		`"type":"hysteria2","server":"example.com"}`
	out := redactSecrets([]byte(in))
	for _, leaked := range []string{"7PRCfc5F8X", "d4550250-3222", "shVXc1ef", "999e2fd9"} {
		if contains(out, leaked) {
			t.Fatalf("secret %q leaked: %s", leaked, out)
		}
	}
	// Форма конфига должна остаться: по ней и читают лог.
	for _, kept := range []string{"hysteria2", "vless", "example.com", `"type"`} {
		if !contains(out, kept) {
			t.Fatalf("shape lost: %s", out)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
