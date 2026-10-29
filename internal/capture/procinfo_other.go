//go:build !windows

// procinfo_other.go — no PID attribution off Windows, so the `app:` rule
// stage never fires there (PLAN-0.8 §1.1: Android keeps its own
// package→action table). Fail-open by construction.
package capture

// procName always reports an unknown owner.
func procName(port uint16, udp bool) string { return "" }
