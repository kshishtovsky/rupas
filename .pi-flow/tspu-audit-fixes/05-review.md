# 05-review.md — TSPU audit fixes: code review

## Summary

3 defects fixed, 4 tests added, 1 test table updated. Все тесты зелёные.

## Findings

### F1 [FIXED] ECH false-negative (FR-001 / SC-001..SC-003) — severity: high
- **file:** `internal/inspector/clienthello.go` line 146–158
- **root cause:** `if elen > 1` принимал GREASE-stub 0x00 0x00 0x00 0x00 (elen=4) за real ECH
- **fix:** порог `elen >= 3 && body[off] != 0` — GREASE stub (version=0x0000) отклоняется, HPKE config (0xfe01) проходит
- **tests:** TestParseECHGreaseStub_4Byte, TestParseECHRealHPKE, TestParseECHLegacyGreaseStub
- **regression risk:** false-negative на real ECH с коротким config (< 3 bytes) — маловероятно, HPKE config ≥ ~80 bytes; тест `TestFeedFastPathZeroAllocs` зелёный

### F2 [FIXED] default action = Direct (FR-002 / SC-004,SC-005)
- **file:** `internal/config/default.go` line 46
- **fix:** `{Action: ActionDirect}` → `{Action: ActionTunnel}` (+ комментарий PRD §5)
- **test:** TestDefaultActionTunnel в config_test.go
- **risk:** весь non-matched трафик теперь через VPS; задокументировано как OWNER policy

### F3 [FIXED] Profile verify (FR-003 / SC-006,SC-007)
- **file:** `prober/profile.go` — VerifyProfile(path, key) + ErrProfileTampered, Signature field в PersistedProfile
- **test:** TestProfileVerify
- **risk:** старые unsigned профили теперь reject при наличии key → поведение: signed-only когда key present; forward-compatible (empty key = pass)

## Perf & contract checks

- Hot path inspector: zero-alloc contract сохранён (subslice read, no copy); `TestFeedFastPathZeroAllocs` зелёный.
- Prover: `TTL + TTLMargin ≤ 255` validation intact (desync/desync.go).
- Flow table GC: gcTick = 5s unchanged (engine.go:42).
