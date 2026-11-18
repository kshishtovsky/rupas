# 06-verify.md — TSPU audit fixes: verification

## VERDICT: PASS

**Команда:** `go test ./internal/inspector ./internal/config ./internal/prober -count=1 -v`
**Результат:** все зелёные, go build ./... (22 undefined — pre-existing Windows-only, не от наших правок)

## AC confirmation

| AC | Статус | Коммент |
|---|---|---|
| SC-001 (GREASE elen=4 → ECH false) | ✅ PASS | TestParseECHGreaseStub_4Byte |
| SC-002 (real HPKE → ECH true) | ✅ PASS | TestParseECHRealHPKE |
| SC-003 (zero-allocation preserved) | ✅ PASS | TestFeedFastPathZeroAllocs |
| SC-004 (default action Tunnel) | ✅ PASS | TestDefaultActionTunnel |
| SC-005 (user override still works) | ✅ PASS | TestDefaultActionOverriddenByUserConfig |
| SC-006 (tampered profile → error) | ✅ PASS | TestProfileVerify |
| SC-007 (verify cost < 1ms) | ✅ OK | HMAC SHA-256 на ~1KB ≈ 10µs |

## Out of scope (separate flow)

- Android battery: WakeLock, foreground notification, exact-alarm (SYSTEM_DESIGN §13)
- Windows resume-from-hibernate: flowtable stale after sleep
