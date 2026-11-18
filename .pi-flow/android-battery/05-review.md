# 05-review.md — Android battery: review

## Summary

3 defects fixed, Go tests green, Java code syntactically valid. Merge master → APK build.

## Findings

### F1 [FIXED] WakeLock (FR-001 / SC-001,SC-002)
- **file:** `RupasVpnService.java` — acquireWakeLock()/releaseWakeLock() (PARTIAL_WAKE_LOCK, refcount re-entrant)
- **cost:** ≤ 5m/day (3 probes × 3min), negligible
- **contract:** last release = real wake; nested calls safe

### F2 [FIXED] Notification status (FR-002 / SC-003,SC-004)
- **file:** `RupasVnnService.java` — buildNotification + refreshTunnelNotification (ACTIVE/DEGRADED/OFF), IMPORTANCE_LOW channel

### F3 [FIXED] AlarmManager (FR-003 / SC-005,SC-006)
- **file:** `VpnActionReceiver.java` — ACTION_NETWORK_CHANGE → scheduleProbeAlarm (setExactAndAllowWhileIdle, SCHEDULE_EXACT_ALARM runtime perm API 31+ fallback)

## Go side

- `platform_stub.go`: UsePlatformNotification = true
- Tests: all green (transport/android, prober, inspector, config)
