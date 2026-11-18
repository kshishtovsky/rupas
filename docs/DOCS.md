# Rupas — полная документация

**Версия:** v0.20.5 · **Обновлено:** 2026-11-18
`PRD.md` — vision, `SYSTEM_DESIGN.md` — architecture, этот файл — code map.

---

## 1. Что это

Rupas — локальный обход DPI (TCP desync) + туннель VLESS-Reality.
Один процесс перехватывает каждый TCP-поток, читает ClientHello и решает:
**DESYNC** (фейк-пакет с калиброванным TTL, без сервера, полная скорость),
**TUNNEL** (VPS, VLESS-Reality) или **DIRECT**.
Цели v1 — Telegram (CIDR), YouTube, Discord на домашнем ISP; пользователь не настраивает ни одно приложение.

## 2. Архитектура (C4)

```
[браузер / TG / Discord] → WinDivert.sys / VpnService(TUN)
        ┌──────────────── RUPAS CORE (Go, SYSTEM-сервис) ──────────────┐
        │ capture → inspector → rules → desync | tunnel | direct      │
        │ prober · supervisor · flowtable · rpc pipe                  │
        └──────────────────────────────────────────────────────────────┘
                              ↑ VPS: sing-box, VLESS-Reality
```

Trust boundaries: юзерленд↔SYSTEM, хост↔ТСПУ (враждебный канал), хост↔VPS.
Зависимости направлены строго вниз; кольцевых нет (§ADR-1).

## 3. Компоненты (internal/…)

| Пакет | Что делает | Ключевые константы / контракты |
|---|---|---|
| **capture** | WinDivert: recv/send, batch ≤64, три handle (NETWORK/REDIRECT/TERM). P50 <100µs, 0 аллокаций steady-state. | `defaultBatchSize=64`, `gcTick=5s`, `tunnelCacheTTL=60s` |
| **flowtable** | Conntrack-подобная таблица; шардинг по CPU (RWMutex per shard). States: NEW → DIRECT/DESYNCED/TUNNEL/ESTABLISHED. | 64B/flow, ring GC |
| **inspector** | Incremental TLS parser: TCP segments → reassemble ClientHello до 8 KB; SNI, ALPN, ECH (GREASE vs real). Zero-alloc: subslice, no copy. | `maxAccumulate=8KB`, `ErrNeedMore`/`ErrNotTLS`/`ErrMalformed` |
| **desync** | Компилирует профиль → ops: InjectFake / SplitAt. Actions zero-alloc (pre-allocated `[]Op`). | TTL ∈ [1,32], Repeats 1–16; strategy: fake/fake,split/multisplit/disorder |
| **rules** | CIDR trie (patricia), SNI map + wildcards, sorted port spans. Order fixed: CIDR→SNI→port→default. | MatchProto — zero alloc |
| **prober** | Классификатор (IP/SNI/UDP probes), TTL binary search (CalibrateTTL), profile persist (atomic write+rename). | 3× attempts, pacing 4s; TSPU emulator в tspu_sim_test.go |
| **supervisor** | State machine: OFF→PROBING→ACTIVE/DEGRADED; hysteresis 3fail/60s, backoff 5→10→30s; FastStart from persisted profile. | DeescalateStable=300s |
| **tunnel** | sing-box lib: VLESS-Reality, XUDP, health marker GET/204; terminator (tcpterm): SYN-consume → forge SYN-ACK, relay; dialGate 128/s. | gate cooldown 1s→30s exponential backoff |
| **rpc** | Named pipe `\\.\pipe\rupasctl`, JSON-line; ACL interactive-only; commands: status/on/off/probe/reload/logs/tui. | |
| **config** | YAML config + rules compilation, profile persistence (%ProgramData%\rupas\profile.json). | `schema_version=1`, MaxAge 72h |
| **transport/android** | VpnService adapter, protect (VpnService.protect), per-app routing, adblock DNS-choke, verdicts. | UsePlatformNotification=true |

## 4. Горячий путь пакета (Windows)

```
WinDivertRecv → classify SYN/data/fin → flowtable.get(4-tuple)
  SYN → Flow{NEW}
  first data: inspector.parse_client_hello()
    SNI found → rules.Match(sni, dstIP, port) → DIRECT / DESYNC / TUNNEL
    ECH (elen≥3 + HPKE magic) → TUNNEL (desync banned for real ECH)
  DESYNC: inject fake×N (TTL=t_calib), split real CH → hold+release after fakes
  TUNNEL: forged RST from dst → tcache add → next SYN fast-path to terminator
```

## 5. Команды и файлы

| Команда | Описание |
|---|---|
| `rupasd -config configs/rupas.yaml` | демон (OFF→ON) |
| `rupasctl on|off|status|probe|reload|logs|tui` | RPC-клиент |
| `rupasctl tui` | bubbletea TUI (Status/Desync/Rules) |
| `configs/rupas.yaml` | конфиг (uuid/password в gitignore) |
| `%ProgramData%\rupas\profile.json` | кэлиброванный профиль, schema_version=1 |
| `build/WinDivert.dll`, `WinDivert64.sys` | драйвер (tracked!) |

## 6. Сборка и тесты

```bash
# ОБЯЗАТЕЛЬНО: теги, иначе sing-box падает рантаймом
go build -tags "with_utls with_quic" -trimpath -ldflags "-s -w" ./cmd/...
go test ./internal/... ./cmd/... -count=1 && go vet ./...

# Android: нужен JDK, ANDROID_HOME (C:/android-sdk), JAVA_HOME
make aar; make apk
```

## 7. Безопасность

- Pipe ACL: interactive-only (kernel32 CreateMutexW single-instance)
- Secrets в gitignore: `configs/*.yaml`, keystore/
- Profile verify: HMAC SHA-256, rejected → PROBING fallback
- Threat model §10: elevation, config tampering, DNS leak, supply chain

## 8. Known limits

- Desync только TCP/TLS; QUIC — BLOCK (UDP:443)
- UDP Discord voice через туннель (NAT→tproxy); direct не работает
- Без туннеля non-TLS к незнакомым адресам → DIRECT (ограничение v1)

## 9. Android battery (v2)

- WakeLock: PARTIAL, acquire/release вокруг probe (~3 мин); re-entrant refcount
- AlarmManager: setExactAndAllowWhileIdle, ACTION_NETWORK_CHANGE trigger
- Notification: IMPORTANCE_LOW, ongoing, status-aware (ACTIVE/DEGRADED/OFF)
- Foreground service: startForeground (уже было), улучшен content

## 10. Тесты (пройденные)

- TSPU emulator: tspu_sim_test.go — SNIDrop/SNIRSTInject/IP/UDP, CalibrateTTL lab window
- Inspector: zero-allocation, segmented CH reassembly, ECH GREASE vs real
- Supervisor: state machine, hysteresis 3fail/60s, backoff 5→10→30s
- All green: inspector · config · prober · desync · flowtable · tunnel · rules
