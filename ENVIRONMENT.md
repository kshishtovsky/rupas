# Окружение разработки rupas-android
## Настроено 2026-10-26

| Компонент | Путь / значение |
|---|---|
| Android SDK | `C:\android-sdk` (перенесён с E: — на E: не хватило места) |
| NDK | `C:\android-sdk\ndk\27.2.12479018` (r27c) |
| Build-tools / Platform | 36.0.0 / android-36 |
| JDK (для Gradle) | `C:\android-sdk\jdk-17.0.20.1+1` (Temurin 17; системный JDK 26 для AGP слишком новый) |
| Go | 1.26.5 |
| gomobile / gobind | `%GOPATH%\bin` (`go install golang.org/x/mobile/cmd/gomobile@latest`) |
| adb | `E:\platform-tools-latest-windows\platform-tools\adb.exe` |
| ANDROID_HOME / ANDROID_SDK_ROOT / JAVA_HOME | setx → `C:\android-sdk`, `C:\android-sdk\jdk-17.0.20.1+1` |

## Телефон
- Samsung SM-S938B (Galaxy S25 Ultra), Android 16 / API 36, **arm64-v8a**, 154 ГБ свободно.
- USB-serial: `R5CY41VRP9R`; Wi-Fi adb: `192.168.1.209:5555` (живёт до перезагрузки телефона;
  восстановление: USB → `adb tcpip 5555` → `adb connect 192.168.1.209:5555`).

## Проверено
- `gomobile bind -target=android -androidapi 26` собирает AAR (скелет `core/`,
  артефакт `core/rupas-core-test.aar`: classes.jar + libgojni.so × 4 ABI).
- Ядро `E:\rupas` собирается под `GOOS=android GOARCH=arm64 -tags "with_utls with_quic with_gvisor"`
  без правок: internal/{inspector,rules,tunnel,prober,supervisor,desync,config,flowtable,core}.
  Не собирается (ожидаемо, W2): `cmd/rupasctl`, `cmd/testmutex`, `internal/app` (pipeline_other — заглушка).

## Команды
```bash
# окружение в каждом новом shell
export ANDROID_HOME='C:/android-sdk' ANDROID_NDK_HOME='C:/android-sdk/ndk/27.2.12479018' \
       JAVA_HOME='C:/android-sdk/jdk-17.0.20.1+1'
export PATH="$PATH:$(go env GOPATH)/bin"

# сборка AAR ядра (реальная обвязка — пакет ./mobile в модуле E:\rupas)
cd /e/rupas && gomobile bind -target=android -androidapi 26 \
    -tags "with_utls with_quic with_gvisor" -o out/rupas-core.aar ./mobile
cp /e/rupas/out/rupas-core.aar /e/rupas-android/app/libs/rupas-core.aar
```

## Примечание
Теги `with_utls with_quic with_gvisor` ОБЯЗАТЕЛЬНЫ и в gomobile-сборке (см.
AGENTS.md десктопного репозитория — требование то же для обоих):
- без `with_utls` — sing-box падает в рантайме «uTLS is not included»;
- без `with_quic` — hysteria2-носитель недоступен;
- без `with_gvisor` — sing-tun отказывает («gvisor is not included»):
  `tun.NewStack("gvisor")` в internal/transport/android/tun.go не создаётся,
  VPN поднимается, но трафик в Go-ядро не попадает вовсе.
