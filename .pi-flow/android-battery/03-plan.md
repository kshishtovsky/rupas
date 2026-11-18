# 03-plan.md — Android battery: implementation plan

## Constitution Check

- **Горячий путь без аллокаций:** WakeLock — Java-side, не пересекает Go hot path; notification push асинхронный (handler postDelayed).
- **Zero-allocation contract:**不改 internal/inspector/desync/rules/prober — только Android VpnService.java + platform_stub.go.
- **Android compatibility:** PARTIAL_WAKE_LOCK API 1+, SCHEDULE_EXACT_ALARM runtime permission API 31+ fallback.

## Technical Context

- **Платформа:** Android Java (Kotlin not used); go build для mobile/aar; VpnService extends android.net.VpnService.
- **Зависимости:** ноль новых; SCHEDULE_EXACT_ALARM — AndroidX runtime permission (already in manifest).
- **Тесты:** UI: RupasVpnService acquire/release idempotent; Go: platform_stub.go SendNotification test.
- **Build:** `cd android && ./gradlew assembleDebug` / CI `assembleRelease`; проверка APK после merge.

## Tasks

**T1 [P1] WakeLock (RupasVpnService.java):** acquireWakeLock()/releaseWakeLock(), re-entrant refcount. Call from Go-side probe entry (VpnActionReceiver triggers via Binder → acquire; SaveProfile → release).

**T2 [P1] Notification status:** improve buildNotification for DEGRADED state; channel IMPORTANCE_LOW, ongoing=true.

**T3 [P2] AlarmManager (VpnActionReceiver.java):** setExactAndAllowWhileIdle on network change; SCHEDULE_EXACT_ALARM request at first launch.

## Files changed

1. `android/app/src/main/java/ru/rupas/android/RupasVpnService.java` — WakeLock + improved notification
2. `android/app/src/main/java/ru/rupas/android/VpnActionReceiver.java` — AlarmManager trigger
3. `internal/transport/android/platform_stub.go` — SendNotification real impl

## Verification

- Go: `go build ./...`, `go test ./internal/transport/android -count=1`
- Android: `cd android && ./gradlew assembleDebug` — APK builds, no lint errors.
- Manual: probe during screen-off → CPU stays up; Doze → alarm wakes probe.
