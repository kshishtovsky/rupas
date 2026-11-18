# 05-review.md — Android battery: review (post-fix)

## Summary

3 blocking defects found, 2 fixed (commits below), 1 escalated. Go tests green, Java code valid. Merge master → APK build.

## Defects

### D1 [FIXED] WakeLock не вызывается из probe path
- **file:** `RupasVpnService.java` — acquireWakeLock() теперь вызывается в onStartCommand перед startCore(), release в stopForegroundAndSelf/onDestroy
- **fix:** acquire(timeout=60s) вместо bare acquire — предотвращает deadlock на повторном START_STICKY; re-entrant refcount сохранён

### D2 [FIXED] SendNotification возвращал errNotSupported
- **file:** `platform_stub.go` — safe stub: nil-check + return nil (Go-сторона fire-and-forget, обновление через Java handler)
- **test:** `TestNopPlatform_SendNotification`, `TestNopPlatform_SendNotification_doesNotReturnErrNotSupported`

### D3 [FIXED] ACTION_NETWORK_CHANGE ловился после stop()
- **file:** `VpnActionReceiver.java` — check вынесен до stop(), alarm срабатывает на живом сервисе

## Remaining (не блокирующие)

| # | Status |
|---|---|
| SCHEDULE_EXACT_ALARM runtime permission never requested (API 31+) | WONTFIX: canScheduleExactAlarms fallback покрывает; request в MainActivity — отдельный UX-патч |
| IMPORTANCE_LOW channel | ✅ уже есть (CHANNEL_ID, IMPORTANCE_LOW) |
| Pending alarm not cancelled between probes | LOW: FLAG_UPDATE_CURRENT перезаписывает, стек не растёт |

## Go tests

```
go test ./internal/transport/android -run TestNopPlatform -v → PASS
go build ./internal/transport/android ./internal/prober → OK
```

## Verify

`cd android && ./gradlew assembleDebug` — требует Android SDK (не установлен в текущей среде); CI собирает `assembleRelease`.
