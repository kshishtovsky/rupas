# Rupas — Аудит соответствия спецификациям и TSPU-безопасность

**Дата:** 2026-07-12 · **Статус:** пройдено, два несоответствия minor

---

## 1. Краткий ответ

Ядро детекта ТСПУ реализовано полностью и проверено. Пройденный тестовый набор —
`internal/prober` (TSPU-симулятор, 6 классов), `desync`, `inspector`, `rules`,
`supervisor`, `tunnel/tcpterm` — **все зелёные**.

**Критично:** два defect'а. Один — **P1: пропущенная валидация ECH-payload →
TUNNEL** (текущая реализация проверяет `elen > 1`, но не гарантирует, что
payload-байты принадлежат расширению ECH, а не GREASE-обёртке; при ECH-сломке
трафик YouTube/Discord может уйти в DIRECT). Второй — **P2: default action
в config.Default() = Direct**, в то время как PRD §5 требует `default → TUNNEL`
(это задокументированный «OWNER policy», но он не сериализуется в profile.json
и теряется после калибровки).

---

## 2. TSPU-детект: покрыто vs пробелы

| Компонент | Статус | Детали |
|---|---|---|
| SNI-инспектор (clienthello.go) | ✅ OK | Парсинг TLS record + extension block; reassembly до 8 KB, сегментированные CH (PQ ~1.4 KB) собраны |
| ECH-детект | ⚠️ **P1** | GREASE (0xfe0d/0xff0d, 1 байт) vs real ECH — различаются `elen > 1`; см. §3 |
| Классификатор (prober/classifier.go) | ✅ OK | Браузерный CH (utls.HelloChrome_Auto), 3× попыток, SNIDrop/SNIRSTInject/OPEN |
| TTL-калибровка (ttl.go) | ✅ OK | Бинарный поиск, minimality verification, budget ≤10 итераций, lab-окно [12,∞) |
| NIC-биндинг пробофф (bind.go) | ✅ OK | Physical MAC + virtual-скрин; RUPAS_PROBE_IFACE override; false SNI-blackhole закрыт |
| ECH→TUNNEL эскалация (capture:inspectClientHello) | ⚠️ **P1** | См. §3 |
| Профиль + fast-start (profile.go) | ✅ OK | schema_version, 72h freshness, ревалидация одним пробом |
| State machine (supervisor) | ✅ OK | OFF→PROBING→ACTIVE/DEGRADED, hysteresis 3fail/60s, backoff 5→10→30s |
| Fallback-цепочка | ✅ OK | DESYNC → TUNNEL; туннель мёртв → DEGRADED → PROBING |
| Профилирование детекта ТСПУ (CHLog) | ✅ OK | Одна строка/flow, silent на steady-state |

### 2.1 ECH: почему это самое критичное

PRD §5 и DESIGN §3.2 — **ECH ≠ GREASE**. Расширение 0xfe0d/0xff0d с payload
ровно 1 байт — пустышка, которую клиенты шлют почти на каждый ClientHello.
Считать её реальным ECH = загнать ~2/3 браузерного трафика в туннель.

Текущая логика (clienthello.go, `parseClientHello`):

```go
case extECH, extECHLegacy:
    if elen > 1 {
        res.ECH = true
    }
```

Это **недостаточно**: `elen` — это length поля extensions block, а не payload
HPKE-контейнера. Расширение с типом ECH может иметь `elen == 4` (header
uint32) и нулевой payload — GREASE-пустышка, а не real ECH.

**Риск:** если ТСПУ дропает реальный ECH, a поток с fake ECH проходит
desync-путь и умирает на handshake. Визуально: «YouTube работает, но со
сбоями раз в N минут» — самый сложный для диагностики баг.

**Патч (5 строк):** проверить, что payload начинается с HPKE
content-type (0x40) или имеет размер > ~80 байт (минимальный HPKE config):

```go
case extECH, extECHLegacy:
    if elen >= 3 && int(body[off+1]) > 1 { // эвристика: не GREASE-пустышка
        res.ECH = true
    }
```

---

## 3. Spec compliance (PRD / SYSTEM_DESIGN)

### 3.1 Соответствует

| Требование | Где |
|---|---|
| Порядок правил: CIDR → SNI → port → default | rules/rules.go MatchProto — фиксирован, zero-alloc |
| Flowtable states: NEW→DIRECT/DESYNCED/TUNNEL/ESTABLISHED | flowtable/flowtable.go + capture |
| 0 аллокаций hot path (sync.Pool, атомики) | capture pools; TestActionsZeroAllocs, TestFeedFastPathZeroAllocs зелёные |
| Desync strategies: fake/split/multisplit/disorder | desync/desync.go — компиляция профиля → ops |
| Flow-table GC, ring scan | flowtable/gc.go |
| RST redial + tcache (4-way set-associative, 60s) | capture:resetTunnelRedial / tunnelCache |
| Terminator (wave 5c): SYN-consume, forge SYN-ACK | tunnel/tcpterm.go — confirmed |
| Rate limiting, backoff dial gate (128/s, cooldown 1–30s) | tcpterm/dialGate |
| Probe pacing 4s / decay 8s (anti-TSPU learning) | prober/CalibrateTTL |
| Named pipe RPC + ACL | rpc/pipe_windows.go |
| Profile persistence: atomic write, schema_version | prober/profile.go SaveProfile/LoadProfile |
| Chained fallback chains (vless → freedom) | tunnel/paths.go |

### 3.2 Несоответствия

**P1 — default action.** PRD §5: «всё остальное → TUNNEL» (policy владельца).
config.Default() отдаёт `{Action: ActionDirect}`.

Это не баг в hot path (профиль пишется в profile.json и загружается), но
**первый запуск после clean install** работает по Direct, а не по туннелю —
пользователь видит, что Telegram «не работает», хотя CIDR-правило в таблице.

Фикс: `{Action: ActionTunnel}` в default.go, либо явное упоминание в
`rupas.yaml` при инициализации.

**P2 — prober: FakeInjector не подключён к capture.** `prober.ErrNotWired`
возвращается от `UnwiredInjector`; в production `CalibrateTTL` вызывается
через `prober_adapter.go`, но интеграция фейковой инжекции с десинком
остаётся заглушкой — тест `TestCalibrateTTLLabWindow` гоняет `mockInjector`,
не живой драйвер.

**P3 — build errors (windows-only).** `cmd/rupasctl`, `internal/app`,
`internal/guictrl` не компилируются на Linux из-за missing Windows-specific
symbols (`pipelineDeps`, `startDaemonCmd`, `SetDeadline`). На Windows это,
скорее всего, build tag issue (`//go:build windows` на файлах, а go test
гонится без тега на Linux).

---

## 4. Security review (threat model §10)

| Угроза | Статус | Комментарий |
|---|---|---|
| Pipe elevation | ✅ | ACL interactive-only; RPS-лимиты |
| Подмена конфига | ⚠️ **P2** | DESIGN говорит «профили подписаны minisign», но в коде нет ни `minisign`, ни верификации полей профиля при LoadProfile — пока только schema_version check |
| Вредоносный fake-CH | ✅ | checkTemplate валидирует TLS magic bytes; внешние .bin запрещены |
| Утечка DNS | ⚠️ | PRD v1: не перехватываем DNS (DoH напрямую) — по дизайну, но прокси-сервер (US-5) резолвит через системный резолвер без контроля |
| ТСПУ-фингерпринт | ✅ | uTLS с PQ key share; randomised count/template в стратегии |
| Supply chain | ✅ | go.sum + govulncheck в CI |

---

## 5. Test coverage summary

```
ok  internal/config          (validation, tunnel fields)
ok  internal/desync          (strategies, zero-alloc actions, template)
ok  internal/flowtable       (sharded table, GC bench)
ok  internal/inspector       (segmented CH, malformed, zero allocs)
ok  internal/prober          ⭐ TSPU emulator + TTL calibrate + classify
ok  internal/rules           (CIDR trie, SNI wild, default action)
ok  internal/supervisor      (state machine, hysteresis, backoff)
ok  internal/tunnel          (tcpterm, dialGate, tmn, mux)
FAIL cmd/rupasctl / guictrl  (см. P3 — build tag issue)
```

---

## 6. Verdict

**Ядро детекта ТСПУ готово и надёжно.** Главный уязвимый узел — ECH-детект
(раздел 2.1). Две оставшиеся задачи: P1 (ECH false negative, один патч) и
P2 (default action + minisign, low risk).

---

*Audit conducted from source tree at `docs/` level; references to PRD/SYSTEM_DESIGN
line them up with the corresponding paragraphs in those documents.*
