<!-- Hallmark · v2.0.0 · scope: app screen · genre: modern-minimal · theme: dose
     screen: per-app routing (4-я стадия экрана «Маршруты» + выбор приложений)
     contrast: pass · tokens only (res/values/colors.xml) · floor: 0 FAIL -->

# Маршрутизация по приложениям — спецификация

Даёт владельцу то, что он просил буквально: **«Instagram — всегда в TUNNEL»**, независимо от того, что говорят правила по IP и домену. Реализуется двумя слоями, потому что в TUN-пакетах нет UID, и один слой физически не может дать всю матрицу действий.

---

## 1. Два слоя — и почему нельзя одним

| Слой | Механизм | Что даёт | Стоимость |
|---|---|---|---|
| **ОС** (VpnService.Builder) | `addDisallowedApplication(pkg)` | приложение **вне VPN** — трафик вообще не входит в TUN | 0 CPU в ядре, работает на всех API 26+ |
| **Ядро** (UID-aware verdict) | `ConnectivityManager.getConnectionOwnerUid()` → `FlowMeta.UID` → правило по UID | **TUNNEL** и **BLOCK** внутри VPN | 1 JNI-вызов на новый flow, только если per-app правила заданы |

**Матрица действий:**

| Действие | Как реализуется | Требует API 29+ |
|---|---|---|
| `DIRECT` | `addDisallowedApplication` — приложение исключено из VPN целиком | нет |
| `TUNNEL` | приложение в VPN; ядро видит UID, правило `uid → tunnel` переопределяет CIDR/SNI/default | да |
| `BLOCK` | приложение в VPN; ядро дропает все его потоки по UID | да |

Почему DIRECT через ОС, а не через ядро: исключённое приложение не создаёт ни одного потока в netstack — это и быстрее, и надёжнее (никакой зависимости от резолва UID).

**Проверено, что путь рабочий:** production-клиент FlClash резолвит UID ровно так — `getConnectionOwnerUid(protocol, source, target)` из VpnService, `-1` при `SDK_INT < Q`. Никаких signature-пермишенов не требуется; `QUERY_ALL_PACKAGES` в манифесте уже есть.

---

## 2. Резолв UID: где и когда

- Java реализует `Platform.ResolveUID(network, srcIP, srcPort, dstIP, dstPort) int`:
  - `network` = `"tcp"`/`"udp"` → `IPPROTO_TCP`/`IPPROTO_UDP`;
  - возвращает `getConnectionOwnerUid(...)`; `-1` при `SDK_INT < 29` или любой ошибке (включая `SecurityException`).
- Go зовёт его **только когда в настройках есть per-app правила**. Нет правил — ноль JNI-вызовов, поведение и производительность прежние (это жёсткое требование: hot path не должен подорожать).
- Резолв — один раз на новый flow (в `JudgeFlow` для UDP и в начале `relayTCP` для TCP), никогда не на per-packet.
- Кеш UID не нужен: частота = частота новых flow.

**Проверка на устройстве обязательна.** Ожидание: сокет приложения в VPN bound к адресу TUN (`26.26.26.1:port`), поэтому пара (source из пакета, destination) находится в netd. Если на живом устройстве резолв вернёт `-1`, ядро честно деградирует (правило не применяется), а UI показывает предупреждение — это не «тихий» отказ.

---

## 3. Приоритет правил

```
app(uid) → cidr/geoip → sni → ports → default
```

Per-app правило — самое специфичное и **переопределяет всё остальное**, включая `geoip: ru → direct` и правило default. Это прямое следствие запроса владельца: «Instagram всегда в TUNNEL» должно означать именно «всегда».

Следствия, которые UI обязан проговорить:
- `DIRECT` для приложения означает «вне VPN»: его трафик пойдёт как у обычного интернета **без обхода**. Для заблокированных на уровне IP сервисов это значит «не работает» — это цена решения, а не баг.
- `TUNNEL` для приложения с RU-адресами упрётся в отказ сервера (`socks5: reply code 1` на RU/CN диапазоны) — если такое случится, владелец увидит это в проверке маршрута.

---

## 4. UI: 4-я стадия на экране «Маршруты»

Экран «Маршруты» (`docs/ROUTING_UI.md`) получает **четвёртую стадию «Приложения»** между «Порты» и закреплённым default.

```
│ ПРИЛОЖЕНИЯ                              3 ▾  │
│ ┌──────────────────────────────────────────┐ │
│ │ ▣ Instagram            ● TUNNEL       ⋮  │ │
│ │   com.instagram.android                   │ │
│ └──────────────────────────────────────────┘ │
│ ┌──────────────────────────────────────────┐ │
│ │ ▣ Сбербанк             ● DIRECT       ⋮  │ │
│ │   ru.sberbankmobile                       │ │
│ └──────────────────────────────────────────┘ │
│ [+ Выбрать приложения]                        │
```

- Строка приложения: иконка 32dp (из `PackageManager`), имя, пакет второй строкой (`ink_soft`, 11sp), чип действия справа, `⋮` → `Изменить` / `Убрать правило` / `Открыть настройки приложения`.
- `+ Выбрать приложения` → **`AppPickerActivity`** (полноэкранный, вход только отсюда):
  - поиск по имени и пакету (sticky сверху);
  - список всех приложений с `INTERNET`-разрешением, алфавитный, с иконками;
  - справа у каждого — переключатель действия из 4 позиций: `наследует` / `DIRECT` / `TUNNEL` / `BLOCK` (первое = правила нет, действует общая политика);
  - фильтр-чипы сверху: `Все` · `С правилом` · `Системные`;
  - сам rupas в списке отсутствует (он всегда вне VPN);
  - счётчик внизу: «Выбрано 3 · Изменения применятся после перезапуска VPN».
- Пустое состояние стадии: «Правил по приложениям нет. Весь трафик идёт по общей политике.» + кнопка `Выбрать приложения`.
- API < 29: стадия показывается, но `TUNNEL`/`BLOCK` в переключателе задизейблены с подписью «нужен Android 10+»; доступен только `DIRECT`.

---

## 5. Применение и хранение

- Хранение: `Settings.app_rules` — массив `{package, action}`, отдельно от `rules`:
  - `DIRECT` нужен **до** старта ядра (Builder), поэтому маппинг package→UID и список disallowed считаются в Java при `establish()`;
  - `package`, а не UID: UID меняется при переустановке приложения.
- Java при старте VPN:
  1. `package → uid` через `PackageManager.getApplicationInfo(pkg, 0).uid` (неизвестный пакет — молча пропустить, лог);
  2. `action == direct` → `addDisallowedApplication(pkg)`;
  3. `action == tunnel|block` → в `SetSettings` как `app_rules: [{uid, action}]`.
- Go: `Settings.AppRules []AppRule{UID int, Action}`; `rules.Compile` строит `map[int]Action`; отсутствие правил = `nil` map = нулевая стоимость.
- Любое изменение per-app правил требует **перезапуска VPN** (как и правила маршрутизации). UI говорит это словами, а не молчит.
- Shared UID (у нескольких пакетов один UID): правило применяется ко всем пакетам этого UID — в UI такие строки помечаются «общий UID с N приложениями».

---

## 6. Контракт данных

**Go — `internal/transport/android/settings.go`**
```go
type AppRule struct {
    UID    int    `json:"uid"`
    Action string `json:"action"` // direct | tunnel | block
}
type Settings struct {
    // ... существующие поля
    AppRules []AppRule `json:"app_rules,omitempty"`
}
```

**Go — ядро**
- `FlowMeta.UID int` (0 = неизвестен, как `-1` от платформы).
- `Action parseAppAction(string)` с ошибкой на неизвестное значение.
- `Rules.appByUID map[int]Action`; `Rules.hasAppRules() bool`.
- `MatchProto(ip, sni, port, proto)` получает UID… **нет**: горячий `MatchProto` не трогаем. UID-проверка идёт в `Engine.decide`/`decidePre` перед вызовом таблицы: `if e.rules.appAction(meta.UID) != 0 { return it }` — один map-lookup по int, zero alloc.

**Go — `mobile/core.go`**
```go
type Platform interface {
    // ... существующие Protect/Log/FilesDir
    // ResolveUID returns the owning app UID for a flow, or -1.
    ResolveUID(network string, srcIP string, srcPort int, dstIP string, dstPort int) int
}
```

**Java — `RupasVpnService.PlatformImpl`**
```java
@Override public long resolveUID(String network, String srcIp, long srcPort, String dstIp, long dstPort)
```
(gobind: Go `int` → Java `long`; имя метода — `resolveUID`, а не `resolveUid`: gobind понижает только первую букву Go-имени `ResolveUID`. Проверено `javap` по собранному AAR — метод с `resolveUid` не переопределил бы интерфейс и фича молча не работала бы.)

---

## 7. Ограничения (сказать владельцу прямо)

1. `TUNNEL`/`BLOCK` по приложению требуют **Android 10+ (API 29)**. `DIRECT` работает на всех наших API (26+).
2. Смена списка = **перезапуск VPN** (~2 с).
3. Приложение с `DIRECT` теряет обход: заблокированное по IP оно не заработает. Это выбор пользователя.
4. `getConnectionOwnerUid` может вернуть `-1` (гонка: сокет ещё не в netd) — тогда поток пойдёт по общим правилам. Не ошибка, честная деградация; повторный резолв не делаем.
5. Приложения с изолированным процессом (`isolatedProcess`) и работа в другом профиле — UID может не резолвиться.

---

## 8. Приёмка

1. `go build -tags "with_utls with_quic with_gvisor" ./...` — зелёный.
2. `go test ./internal/transport/android/ ./internal/rules/ ./mobile/` — зелёный; новые тесты: парсинг `app_rules`, приоритет UID над CIDR/SNI/default, `uid=-1` не ломает обычную логику, `direct` не попадает в UID-карту.
3. Zero-alloc не пострадал: `go test -bench=. -benchmem ./internal/rules/ ./internal/tunnel/` → те же `0 B/op` (UID-путь выключен без правил).
4. `gomobile bind` → AAR; `gradlew assembleRelease` → APK; `adb install -r`.
5. **На живом устройстве:** выбрать Instagram (или любое установленное приложение) → `TUNNEL`; включить VPN; в логе ядра строка `app uid=NNN (com.instagram.android) → TUNNEL`, соединения приложения идут через туннель; `DIRECT` — приложение вне TUN (проверить, что в netstack нет его flow), `BLOCK` — его соединения падают, остальное работает.
6. Если резолв UID на устройстве не работает — зафиксировать фактическое поведение и вернуться с диагностикой, а не выдавать фичу за готовую.

---

## 9. Декомпозиция

| # | Задача | Файлы |
|---|---|---|
| T1 | Ядро: `AppRule`, `FlowMeta.UID`, `Platform.ResolveUID`, приоритет в `decide/decidePre`, логирование, тесты | `internal/transport/android/{settings,verdict,engine,rules}.go`, `mobile/core.go`, `internal/transport/android/*_test.go` |
| T2 | Java-мост: резолв package→UID, disallowed-список из настроек, `PlatformImpl.resolveUid`, хранение `app_rules` | `RupasVpnService.java`, `SettingsStore.java`, `core/Core.java` (сгенерируется) |
| T3 | UI: 4-я стадия «Приложения» в `RoutingActivity`, `AppPickerActivity` + адаптер + поиск, вход из стадии | `RoutingActivity.java`, `RoutingAdapter.java`, `AppPickerActivity.java`, `AppPickerAdapter.java`, layouts, strings, manifest |

T1 и T2 делят контракт §6 дословно; T3 зависит от T2 только по формату хранения (`Settings.app_rules`), поэтому все три идут параллельно. Стык проверяет оркестратор на устройстве.
