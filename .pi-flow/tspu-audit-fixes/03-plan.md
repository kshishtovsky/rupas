# 03-plan.md — TSPU audit fixes: implementation plan

## Constitution Check

- **Горячий путь без аллокаций:** inspector не меняет буферы, читает subslice; test `TestFeedFastPathZeroAllocs` зелёный.
- **Порядок правил CIDR→SNI→port→default:** default action = Tunnel — не ломает порядок (попадает в last rule).
- **Доктрина фейков / ECH ≠ GREASE:** FR-1 реализует именно эту доктрину, а не «ECH всегда true».
- **Секреты не в git:** minisign/HMAC key хранится отдельно от profile.json.
- **FR-003 (verify) cost < 1ms:** HMAC с SHA-256 на ~1KB profile ≈ 10µs.

## Technical Context

- **Язык/платформа:** Go; `internal/inspector` — чистая логика, no platform deps; `prober/profile.go` — os.ReadFile/writeFile (Windows/Android/Linux одинаково).
- **Зависимости:** ноль новых — HMAC в stdlib (`crypto/hmac`, `crypto/sha256`), minisign отложен.
- **Тесты:** go test ./internal/inspector ./internal/config ./internal/prober; `go test -race`; existing zero-alloc tests must stay green.
- **Go build:** go build ./... — все пакеты компилируются на Linux (Windows-only targets не трогаем).

## Tasks

**T001 [P1] [FR-001] ECH payload validation.** File: `internal/inspector/clienthello.go` (функция parseClientHello, case extECH). Добавить порог ≥ 3 bytes + HPKE magic check. +test: `TestParseClientHelloGREASE`, `TestParseClientHelloRealECH`.
**T002 [P2] [FR-002] default action Tunnel.** File: `internal/config/default.go`, last rule `{Action: ActionTunnel}`. +test: `TestDefaultActionTunnel` в config_test.go.
**T003 [P2] [FR-003] Profile verify.** File: `prober/profile.go` — `VerifyProfile(path, key []byte) error` (HMAC SHA-256), integrate into LoadProfile. +test: `TestProfileVerify`.

## File change list

1. `internal/inspector/clienthello.go` — FR-001
2. `internal/config/default.go` — FR-002
3. `prober/profile.go` — FR-003
4. Тесты: 3 файла test, по одному на задачу.

## Verification

```bash
go build ./... && go test ./internal/inspector ./internal/config ./internal/prober -count=1 -v -race
```
Все существующие тесты зелёные + 3 новых.
