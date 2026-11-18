# 04-tasks.md — TSPU audit fixes: task list

## Task order (dependencies)

T001 → T002, T003 parallel (независимые); все после `go build ./...`.

## Tasks

- [x] T001 [P1] [US1] ECH false-negative: internal/inspector/clienthello.go — порог elen≥3 + HPKE magic check; тесты: TestParseECHGreaseStub_4Byte, TestParseECHRealHPKE, TestParseECHLegacyGreaseStub.
- [x] T002 [P2] [US2] default action Tunnel: internal/config/default.go → ActionTunnel; тест TestDefaultActionTunnel.
- [x] T003 [P2] [US3] Profile verify: prober/profile.go — VerifyProfile (HMAC SHA-256), TestProfileVerify.

## Acceptance (shared)

- `go build ./... && go test ./internal/inspector ./internal/config ./internal/prober -count=1 -v -race` — всё зелёное.
- Существующие zero-alloc тесты не регрессировали: `TestFeedFastPathZeroAllocs`, `TestActionsZeroAllocs`.
