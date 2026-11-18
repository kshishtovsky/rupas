# 04-tasks.md — Android battery: tasks

## Tasks

- [x] T001 [P1] [US1] WakeLock: RupasVpnService.java — acquireWakeLock()/releaseWakeLock() (PARTIAL_WAKE_LOCK, re-entrant refcount).
- [x] T002 [P1] [US2] Notification status: RupasVpnService.java — buildNotification DEGRADED/OFF; channel IMPORTANCE_LOW.
- [x] T003 [P2] [US3] AlarmManager: VpnActionReceiver.java — setExactAndAllowWhileIdle + SCHEDULE_EXACT_ALARM permission.

## Acceptance

- `go build ./... && go test ./internal/transport/android -count=1` зелёные
- `cd android && ./gradlew assembleDebug` — APK build OK
- Manual: probe в screen-off держит CPU; Doze → alarm будит
