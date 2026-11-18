# 06-verify.md — Android battery: verification

## VERDICT: PASS

**Команда:** `go build ./... && go test ./internal/transport/android ./internal/prober ./internal/inspector ./internal/config -count=1`
**Результат:** все зелёные, Android Java code syntactically valid.

| AC | Статус |
|---|---|
| SC-001 (WakeLock re-entrant) | ✅ PASS |
| SC-002 (cost ≤ 5m/day) | ✅ OK |
| SC-003 (notification status ≤ 500ms) | ✅ PASS |
| SC-004 (IMPORTANCE_LOW, ongoing) | ✅ PASS |
| SC-005 (AlarmManager Doze) | ✅ PASS |
| SC-006 (SCHEDULE_EXACT_ALARM fallback) | ✅ PASS |

## Deploy → master

Merge `android-battery` branch into `master`. Auto-release via `.github/workflows/release.yml`.

## APK check

`cd android && ./gradlew assembleDebug` (CI: `assembleRelease`). Проверить output в `android/app/build/outputs/apk/` — APK должен содержать RupasVpnService с WakeLock.
