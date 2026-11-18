# 02-spec.md — TSPU audit fixes: specification

### User Story 1 — ECH false-negative (Priority: P1)

**Контекст:** ТСПУ дропает ClientHello с реальным ECH, но GREASE-пустышка
0xfe0d (elen=4, нулевой HPKE payload) проходит десинк и умирает на handshake.
Пользователь видит «YouTube работает, но со сбоями раз в N минут».

**Given** ClientHello содержит расширение extECH (0xfe0d или 0xff0d) с elen=4
и нулевым payload (GREASE-пустышка); **When** inspector парсит пакет;
**Then** `Result.ECH == false`, поток идёт в DESYNC.

**Given** CH содержит real ECH, elen=96, HPKE ciphertext 80 bytes;
**When** inspector парсит; **Then** `Result.ECH == true`, поток идёт в TUNNEL.

**FR-001:** `inspector/clienthello.go:parseClientHello` различает GREASE и real ECH по порогу payload ≥ 3 bytes + HPKE magic check (тип 0x40). Zero-allocation: чтение subslice, без copy.
**SC-001:** `TestParseClientHelloGREASE` — elen=4, payload 0x00 0x40 0x03 0x50 → ECH=false.
**SC-002:** `TestParseClientHelloRealECH` — elen=96, HPKE payload → ECH=true.
**SC-003:** `TestFeedFastPathZeroAllocs` остаётся зелёным (hot path untouched).

### User Story 2 — Default action Tunnel (Priority: P2)

**Given** пользователь устанавливает rupas впервые; **When** запускает без конфига;
**Then** все non-matched потоки идут в туннель (PRD §5: «всё остальное → TUNNEL»).

**FR-002:** `config.Default().Rules[last]` = `{Action: ActionTunnel}`.
**SC-004:** `TestDefaultActionTunnel` — default config отдаёт Tunnel.
**SC-005:** user config override (rulе «direct» в YAML) всё ещё побеждает default.

### User Story 3 — Profile integrity (Priority: P2)

**Given** persisted profile на диске; **When** load; **Then** tampered profile → error → fallback full PROBING.
Порог: HMAC SHA-256 с ключом из конфига (minisign отложен — проще, без внешней зависимости).

**FR-003:** `prober/profile.go`: новая функция `VerifyProfile(path, key []byte) error`; LoadProfile вызывает verify, rejected → fallback PROBING.
**SC-006:** valid profile → loaded; tampered → error + PROBING.
**SC-007:** verify cost < 1ms, skipped на fresh probe (zero overhead).

## Assumptions

- Порог ECH ≥ 3 bytes + magic: достаточно для GREASE/real distinction; corpus lab-дампов при необходимости.
- HMAC вместо minisign: ключ локальный, tampering vs forgery — достаточно.
- Windows resume-from-hibernate: не в scope, отложено (flowtable stale — отдельный fix).
