package tunnel

import "regexp"

// secretRe matches `"<field>":"<value>"` for the credential fields of a
// sing-box outbound: hysteria2 password, vless uuid, reality public_key /
// short_id. The dumped config is copied into chat reports as-is, so the values
// are replaced while the shape stays readable.
var secretRe = regexp.MustCompile(
	`"(password|uuid|pbk|public_key|private_key|short_id|psk|auth)"\s*:\s*"[^"]*"`)

// redactSecrets replaces the value of every credential field with *** so a
// dumped config stays readable without leaking the channel.
func redactSecrets(cfg []byte) string {
	return secretRe.ReplaceAllString(string(cfg), `"$1":"***"`)
}
