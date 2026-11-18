# 07-deploy.md — Android battery: deploy plan

## Что
T001 WakeLock (RupasVpnService.java), T002 notification status, T003 AlarmManager (VpnActionReceiver.java), platform_stub.go UsePlatformNotification=true. Merge в master.

## Куда
master → auto-release release.yml. Merge-коммит "feat: Android battery — WakeLock + exact-alarm + notification status".

## Выкат
merge master, CI: `./gradlew assembleRelease`, проверить APK.

## Проверка
```bash
go build ./... && go test ./internal/transport/android -count=1
cd android && ./gradlew assembleDebug; ls app/build/outputs/apk/debug/*.apk
```
APK ≥ 10MB, содержит RupasVpnService с WakeLock.
