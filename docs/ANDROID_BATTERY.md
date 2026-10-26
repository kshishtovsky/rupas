# Android: расход батареи и скорость

Документ фиксирует узкие места мобильного клиента (Java/`RupasVpnService` +
Go-ядро `internal/transport/android`) и изменения, которые уже внесены.
Порядок — по ожидаемому вкладу в расход, а не по сложности.

## 1. Что жгло батарею сильнее всего

| # | Место | Проблема | Что сделано |
|---|-------|----------|-------------|
| 1 | `MainActivity.updateEndpointInfo()` | Вызывался **раз в секунду** из телеметрии. Каждый вызов создавал `MasterKey` (Android Keystore) и заново открывал `EncryptedSharedPreferences` — расшифровка всех записей + криптооперации в самом дорогом месте. | `SettingsStore` кеширует `SharedPreferences` на процесс; `updateEndpointInfo()` вызывается только при смене состояния VPN, `onResume` и сохранении настроек. |
| 2 | `MainActivity.logListener` | На **каждую** строку лога (а Go пишет строку на каждый TCP-флоу и ClientHello) в main thread ставился `renderLogs()`: полный `dump()` до 1000 строк + `SimpleDateFormat` на каждую + `setText` + автоскролл. При загрузке сети main thread не успевал. | Журнал перерисовывается не чаще 4 раз/с, только когда вкладка логов видима и Activity в foreground. События не копятся в очереди (coalescing через `AtomicBoolean`). |
| 3 | `RupasVpnService.notifyTicker` | Каждые 1.5 с: `Core.status()` через JNI → JSON-парсинг → `NotificationCompat.build()` → `NotificationManager.notify()` → IPC в SystemUI, даже в фоне/с выключенным экраном. | Тикер удалён. Foreground-уведомление статично; живая статистика — только на открытом экране (1 раз/с). |
| 4 | `MainActivity.telemetryPoller` | Опрос `Core.status()` раз в секунду независимо от вкладки: на «Настройках»/«Логах» и при погашенном экране данные всё равно собирались и UI перерисовывался. | Опрос идёт только при `resumed` **и** видимой вкладке «Главная»; при уходе с вкладки/в фон `removeCallbacks`. |
| 5 | `LogBuffer.add()` + `PlatformImpl.log()` | Каждая строка дважды писалась в logcat (`Log.d` в `PlatformImpl` и в `LogBuffer`), включая рутинные `tcp flow`/`udp session`. Синхронный logcat на каждый флоу — заметная цена. | Дублирование убрано; в logcat попадают только INFO+ (сетевой трейсинг остаётся в кольцевом буфере для экрана «Логи»). |
| 6 | `MainActivity.refreshUI()` | Полная перерисовка цветов/текстов/`ColorStateList` каждую секунду, даже когда состояние VPN не менялось. | Есть guard по последнему отрисованному состоянию; тяжёлые сеттеры выполняются только при переключении ON/OFF. |
| 7 | `MainActivity.onCreate()` | `setTurnScreenOn(true)` + `setShowWhenLocked(true)`: запуск Activity из шторки будил и включал экран. | Убрано: Activity не должна зажигать дисплей ради показа статуса. |

## 2. Go-ядро (`internal/transport/android`)

| Место | Проблема | Что сделано |
|-------|----------|-------------|
| `copyConn` (`engine.go`) | На каждый TCP-флоу — два буфера по 16 КиБ (по одному на направление). Браузер открывает сотни флоу за сессию → мегабайты мусора и лишний GC. | `sync.Pool` на буферы релея. |
| `peekClientHello` (`peek.go`) | 4 КиБ буфер чтения + растущий `seen` на каждый TLS-флоу. | Буфер из `sync.Pool`, `seen` сразу с ёмкостью `sniPeekLimit` (2 КиБ) — без промежуточных реаллокаций. |
| `engineLogger` (`tun.go`) | `Trace`/`Debug` gVisor/sing-tun уходят через JNI в Java на error-путях пакетного уровня. | `Trace`/`Debug` отбрасываются; `Info`+ сохраняются. Это снимает риск шторма JNI-вызовов. |
| `serveProtect` (`protect_unix.go`) | На каждый защищённый сокет писались 2–3 строки в Java. | Оставлены только ошибки/отказы. (Сейчас `protect_path` отключён — см. §4.) |
| `ProtectedDialer.KeepAlive` (`egress.go`) | 30 с — агрессивнее дефолта Linux (`tcp_keepalive_time` ~2 ч). Каждый idle-сокет будил радиомодуль. | 2 минуты: NAT-сессии живут, число проб меньше в 4 раза. |

## 3. Что осталось осознанно «дорогим»

1. **gVisor netstack.** Весь трафик проходит через userspace-стек. Это цена
   маршрутизации по SNI/правилам; system-stack (TUN без netstack) на Android
   потребовал бы root/тоннельного демона. Не меняем.
2. **Лог на каждый флоу.** `tcp flow`, `CH sni=...` идут в Java даже когда
   экран закрыт. Строки дешёвые по отдельности, но на тысячах флоу это JNI.
   Следующий шаг — флаг `Core.setFlowLogging(false)` из Java (release-сборка),
   чтобы горячий путь вообще не пересекал JNI. Требует пересборки AAR.
3. **UDP-сессии живут 5 минут** (`UDPTimeout`) даже для одного DNS-запроса.
   Это компромисс: меньше 5 минут — риск порвать QUIC/звонки. Трогать только
   с замерами.
4. **DNS = 8.8.8.8 через TUN.** Каждый резолв — UDP-сессия через netstack.
   Локальный DNS-прокси/кеш в ядре сократит число сессий и RTT (энергия —
   через меньшее время работы радиомодуля).
5. **`QUERY_ALL_PACKAGES`** в манифесте не нужен, пока нет выбора приложений:
   политика Play и лишний скан пакетов на старте.

## 4. Связанные изменения в рабочем дереве (не про батарею)

В `internal/transport/android/relay.go` сейчас отключены `uTLS` и
`protect_path` (обход зависаний сокетов на современных ядрах Android), а
исходящие сокеты sing-box bypass-ят VPN через
`addDisallowedApplication(getPackageName())`. Это влияет на совместимость и
скорость установления TLS, но не является источником фонового расхода.

## 5. Как проверять (без догадок)

```bash
adb shell dumpsys batterystats --reset
# ...20–30 минут обычного сценария: браузер, мессенджер, экран погашен...
adb shell dumpsys batterystats | grep -A20 rupas.android
adb shell dumpsys cpuinfo | grep rupas
```

Perfetto/`record_android_trace` для main thread: ищем `renderLogs`,
`SettingsStore`, `Core.status`, `NotificationManager.notify`. До изменений
`SettingsStore` и `renderLogs` должны были доминировать; после — основной
остаток должен приходиться на Go-потоки netstack (это ожидаемо).

Быстрый smoke-чек, что оптимизации не сломали функциональность:

```bash
cd E:/rupas
go build ./...
GOOS=android GOARCH=arm64 go build -tags "with_utls with_quic" ./internal/transport/android ./mobile
go test ./internal/transport/android ./mobile -count=1

cd E:/rupas-android
./gradlew :app:compileDebugJavaWithJavac
```
