# 01-analysis.md — Android battery (WakeLock, notification, alarm)

**Source:** SYSTEM_DESIGN §13 ("foreground service + wakeup-политика probe только по событиям сети"), AUDIT.md §6.
**Goal:** реализовать WakeLock на probe, foreground notification, exact-alarm; затем merge master и проверить APK-сборку CI.

## Исходное состояние

| Компонент | Статус | Где |
|---|---|---|
| VpnService + startForeground | ✅ есть | RupasVpnService.java:87, `startForegroundWithStatus()` |
| NotificationCompat.Builder | ✅ базовый (ID=1) | RupasVpnService.java:441 |
| WakeLock на probe | ❌ нет | — |
| AlarmManager probe (Doze) | ❌ нет | — |
| adapter.Notification (Go→Java status) | stub `errNotSupported` | platform_stub.go:65–67 |
| RUPAS_PROBE_IFACE | ✅ есть, но Java-стороны нет | prober/bind.go, не вызывается из Android |

## Requirements

**FR-1 [P1] WakeLock на probe.** `RupasVpnService`: acquire `PowerManager.PARTIAL_WAKE_LOCK` перед Classify/CalibrateTTL (~3 мин), release после SaveProfile. `acquire()` + `release()`, thread-safe, re-entrant (count).

**FR-2 [P1] Foreground notification с статусом туннеля.** Улучшить `startForeground`: content = статус (ACTIVE/DEGRADED/OFF), channel description; Go → `adapter.Notification` (уже интерфейс в platform_stub.go), Java read status from Core event.

**FR-3 [P2] AlarmManager exact-alarm для probe.** `setExactAndAllowWhileIdle`, trigger по `NetworkCallback` (смена Wi-Fi/Doze) — probe "только по событиям сети", DESIGN §13.

## Given/When/Then

| FR | Given | When | Then |
|---|---|---|---|
| FR-1 | Go запускает Classify | `acquireWakeLock()` | CPU не уходит в deep sleep, probe завершается за ~3 мин |
| FR-2 | Supervisor ACTIVE | Go отправляет status | notification "Rupas: защищено" (ACTIVE), статус обновляется |
| FR-3 | Телефон в Doze | Смена сети | AlarmManager будит, probe классифицирует; не глушит радио |

## Unknowns

1. `WakeLock` cost: PARTIAL_WAKE_LOCK держит CPU, но не экран — ~5m × 3мин probe = 15m/day, negligible.
2. `setExactAndAllowWhileIdle` требует permission `SCHEDULE_EXACT_ALARM` (API 31+). Mitigation: request at runtime, fallback to inexact.
3. Go-сторона уже имеет supervisor (EventResume, DEGRADED) — notification push from Go к Java через VpnService.notification field.

## Files changed

1. `RupasVpnService.java` — acquireWakeLock/release, improved startForeground with status channel
2. `platform_stub.go` — реализовать SendNotification (Go→Java), UsePlatformNotification = true
3. `VpnActionReceiver.java` — AlarmManager exact-alarm trigger on network change
