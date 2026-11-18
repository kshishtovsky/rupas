# 02-spec.md — Android battery: WakeLock, notification, alarm

### User Story 1 — WakeLock на probe (Priority: P1)

**Контекст:** probe Classify+CalibrateTTL длится ~3 мин; без WakeLock Android засыпает в deep sleep и probe зависает.

**Given** Go запускает Classify + TTL calibration (~3 мин); **When** телефон в screen-off;
**Then** PARTIAL_WAKE_LOCK держит CPU, probe завершается за ~3 мин, release после SaveProfile.

**FR-001:** `RupasVpnService.java` — методы acquireWakeLock()/releaseWakeLock() (re-entrant, refcount), PARTIAL_WAKE_LOCK.
**SC-001:** acquire/release balanced, last release = real wake; re-entrant (nested probe call не выкинет lock).
**SC-002:** cost ≤ 5m/day (3 probes × 3мин), negligible.

### User Story 2 — Foreground notification status (Priority: P1)

**Given** RupasVpnService уже имеет startForeground; **When** статус туннеля меняется;
**Then** notification обновляется (ACTIVE = "защитано", DEGRADED = "проблема", OFF = "отключён").

**FR-002:** buildNotification/refeshTunnelNotification уже есть; улучшить: DEGRADED-канал, icon state-aware.
**SC-003:** notification обновляется ≤ 500ms после события (handler post).
**SC-004:** channel IMPORTANCE_LOW, ongoing=true (не будит).

### User Story 3 — AlarmManager exact-alarm (Priority: P2)

**Given** телефон в Doze; **When** сеть меняется (Wi-Fi/роуминг);
**Then** AlarmManager.setExactAndAllowWhileIdle будит, probe классифицирует.

**FR-003:** VpnActionReceiver получает NETWORK_CHANGE → schedules exact alarm; SCHEDULE_EXACT_ALARM runtime permission (API 31+, fallback inexact).
**SC-005:** в Doze probe запускается ≤ 1 мин после события сети.
**SC-006:** SCHEDULE_EXACT_ALARM request при первом запуске, без краха на API < 31.

## Assumptions

- WakeLock: PARTIAL (CPU), не SCREEN — probe 3 мин, экран не нужен.
- AlarmManager: exact-only on network change; periodic probe остаётся по таймеру (existing).
- Notification: Go → Java push через существующий refreshTunnelNotification (triggered by Core status).
