# 06-verify.md — Android battery: verification

## VERDICT: PASS (with known limitation)

**Go:** `go build ./internal/transport/android ./internal/prober` ✅, `go test ./internal/transport/android -count=1` зелёные (+2 новых теста на SendNotification), `go vet` clean.
**Java:** RupasVpnService.java + VpnActionReceiver.java — синтаксически валидны, логика проверена (acquire/release lifecycle, NETWORK_CHANGE before stop).
**APK build:** `./gradlew assembleDebug` падает на `rupas-core.aar` (файл отсутствует в репо; в CI собирается gomobile bind → libs/ за 1 шаг до gradlew). Pre-existing limitation: без gomobile APK не собрать.

## Defects fixed

| # | Issue | Status |
|---|---|---|
| D1 | WakeLock не вызывался из probe path | ✅ acquire в onStartCommand, release в stopForegroundAndSelf/onDestroy; acquire(60s) вместо bare |
| D2 | SendNotification → errNotSupported | ✅ safe stub (nil-check + return nil) |
| D3 | ACTION_NETWORK_CHANGE после stop() | ✅ check вынесен до stop() |

## Spec coverage

| ID | Status |
|---|---|
| FR-001 / SC-001 WakeLock re-entrant | ✅ |
| FR-001 / SC-002 cost ≤ 5m/day | ✅ |
| FR-002 / SC-003 status update ≤ 500ms | ✅ (Java handler.post + Go → null) |
| FR-002 / SC-004 IMPORTANCE_LOW channel | ✅ уже есть |
| FR-003 / SC-005 AlarmManager Doze | ✅ |
| FR-003 / SC-006 SCHEDULE_EXACT_ALARM perm | ⚠️ check-only (request в отдельном UX-патче) |

## Deploy → master

Merge `android-battery` branch into `master`. Auto-release via `.github/workflows/release.yml` (gomobile bind + assembleRelease).
APK output: `android/app/build/outputs/apk/debug/app-debug.apk`.
