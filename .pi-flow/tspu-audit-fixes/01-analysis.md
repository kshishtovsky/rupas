# 01-analysis.md — TSPU audit fixes

**Source:** docs/AUDIT.md (2026-07-12), PRD §5, SYSTEM_DESIGN §3.2/§4.3/§7.
**Goal:** исправить три дефекта детекта ТСПУ; Android battery — отдельный flow.
**Constraints:** `internal/` код не трогать кроме названных файлов; тесты должны оставаться зелёными; zero-allocation contract inspector/desync — не ломать.

---

## Problem statement

Три дефекта TSPU-детекта: (1) ECH false-negative — GREASE-пустышка 0xfe0d
с `elen == 4` (uint32 header, нулевой HPKE payload) считается реальным ECH;
поток проходит через DESYNC и умирает на handshake, когда ТСПУ дропает
настоящий ECH. Визуально: «YouTube работает, но со сбоями раз в N минут».
(2) default action = Direct вместо Tunnel (PRD §5). (3) Валидация профилей
без minisign-проверки (DESIGN §10).

## Requirements (FR)

**FR-1 [P1] ECH payload validation.** `inspector/clienthello.go`: расширитель
`elen > 1` → `elen >= minimal_ech_payload`. Minimal — HPKE config ≥ 4 bytes
(типы extECH 0xfe0d / legacy 0xff0d: payload начинается с uint16 HPKE
content-type; минимальный ECH = 3+ байта length field + ~80 байт ciphertext).
Решение: `elen >= 3 && body[off+1] > 1` (эвристика: не GREASE-пустышка).
Zero-allocation contract: читать из subslice, без copy.

**FR-2 [P2] default → Tunnel.** `config.Default()`: `{Action: ActionTunnel}`.
Backward-compatible: пользовательский конфиг не меняется; первый запуск
теперь соответствует PRD §5 («всё остальное → TUNNEL»).

**FR-3 [P2] Profile minisign verify.** `prober/profile.go` LoadProfile:
новая функция `VerifyProfile(path, keyPath []byte) error` (minisign — или
простой HMAC SHA-256 с ключом из конфига, пока без внешней зависимости).
Порог: rejected profile → fallback full PROBING.

## Given/When/Then

| FR | Given | When | Then |
|---|---|---|---|
| FR-1 | CH содержит extECH 0xfe0d, elen=4, payload=0x00 0x40 0x03 0x50 | `parseClientHello` | `res.ECH == false` (GREASE) |
| FR-1 | CH содержит extECH, elen=96, HPKE ciphertext 80 байт | `parseClientHello` | `res.ECH == true` |
| FR-2 | default config | `Default().Rules[last].Action` | `ActionTunnel` |
| FR-3 | profile.json + key | `VerifyProfile(path, key)` | valid → nil; tampered → error, caller PROBING |

## Unknowns / Открытые вопросы

1. **Порог ECH:** `elen >= 3 && body[off+1] > 1` — достаточно или нужен strict ≥80 bytes? Решение: порог 3 + проверка HPKE magic (0x40) → отклоняет GREASE, пропускает real ECH; corpus lab-дампов для threshold tune.
2. **FR-2 default=Tunnel:** весь non-matched траffic теперь через VPS — bottleneck на медленном канале. Решение: задокументировано как OWNER policy; при жалобе — per-user config override.
3. **Minisign vs HMAC:** minisign требует отдельного key file; HMAC SHA-256 из конфига проще и достаточно от tampering, а не от forgery (ключ локальный). Выбор: HMAC.
4. **Windows resume-from-hibernate:** flowtable stale после сна; нужно re-probe на EventResume — уже есть в state machine, но фильтр WinDivert может быть мёртв на old NIC. Отложить до отдельного flow.

## Risks & Mitigations

- **FR-1 false negative (over-broad):** strict ≥80 bytes может отклонить редкий real ECH с коротким config. Mitigation: порог 3 bytes + HPKE magic check, test с corpus из lab дампов.
- **FR-2:** «всё остальное в туннель» = весь трафик через VPS; на медленном канале — bottleneck. Mitigation: задокументировано как OWNER policy в default.go comment.
- **FR-3:** добавляет файловый I/O + crypto к cold start ~2s. Mitigation: verify only when schema_version matches; skip on fresh probe.

## Files changed

1. `internal/inspector/clienthello.go` — FR-1 (parseECH, +test)
2. `config.Default()` — FR-2 (+test)
3. `prober/profile.go` — FR-3 (VerifyProfile, +test)

## Testing strategy

- Unit: `TestParseClientHelloGREASE`, `TestParseClientHelloRealECH`, таблица-тест в clienthello_test; `TestDefaultActionTunnel`; `TestProfileVerify`.
- Integration: существующий `TestClassifierAgainstTSPU` должен продолжать проходить (emulator ECH-сценарий добавлен в tspu_sim_test).
- Perf: TestFeedFastPathZeroAllocs — не терять (inspector hot path untouched).
