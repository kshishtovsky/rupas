# AGENTS.md — правила работы с этим репозиторием

Короткая памятка для людей и агентов, которые правят код Rupas. Полный обзор —
`README.md`, требования — `docs/PRD.md`, устройство — `docs/SYSTEM_DESIGN.md`.

## Сборка и проверка

```bash
go build -tags "with_utls with_quic" -trimpath -ldflags "-s -w" ./cmd/rupasd ./cmd/rupasctl
go build ./...                  # быстрая проверка компиляции (без тегов достаточно)
go test ./internal/... ./cmd/... -count=1
go vet ./...
```

**Теги `with_utls with_quic` обязательны для рабочего бинарника.** Без них
сборка проходит, но sing-box падает в рантайме (`uTLS is not included in this
build`), туннель не стартует, и все TUNNEL-правила эскалируются в direct —
Telegram-CIDR уходит в чёрную дыру. Симптом выглядит как баг кода, а не сборки.

`go test -race` требует cgo/gcc; на хосте без gcc используйте обычный прогон.

Известный давний красный тест: `TestPipelineTunnelEscalationNoEndpoint`
(`internal/app`). Он не связан с текущими правками — не «чините» его попутно,
если задача не про него.

## Инварианты, которые нельзя ломать

1. **Горячий путь без аллокаций.** В steady-state — ноль аллокаций на пакет:
   `sync.Pool` для буферов, атомики вместо мьютексов, неизменяемые таблицы
   правил. В пакетах `capture`, `rules`, `inspector`, `flowtable` есть
   zero-alloc тесты — они обязаны оставаться зелёными.

2. **Порядок разрешения правил фиксирован: CIDR → SNI → ports → default.**
   Менять порядок нельзя: на нём держится приоритет Telegram-CIDR над
   port-правилами и QUIC-блоком.

3. **Доктрина фейков.** Реальный ClientHello держится целиком (включая
   многосегментный), фейки уходят строго до него, seq/ack фейка = seq/ack
   первого сегмента CH, TTL = t* + margin.

4. **Терминатор терминирует только SYN-ведённые соединения.** Любой вердикт
   TUNNEL, пришедший на данных (после SYN), обязан идти через RST + кеш dst +
   передial. Попытка отдать данные в терминатор напрямую = поток висит до
   таймаута без единого carrier dial.

5. **GREASE ≠ ECH.** Расширение 0xfe0d/0xff0d с payload ровно 1 байт — пустышка,
   которую клиенты шлют почти на каждый ClientHello. Считать её настоящим ECH =
   загнать ~2/3 браузерного трафика в туннель.

6. **Секреты не попадают в git.** `configs/rupas.yaml` и `configs/*.bak`
   содержат uuid/password и обязаны оставаться в `.gitignore`. В git лежит
   только `configs/rupas.example.yaml`.

7. **`build/` игнорируется не полностью.** `build/WinDivert.dll`,
   `build/WinDivert64.sys`, `build/windivert/**` и `build/desync/*.bin` —
   рантайм-ассеты, они отслеживаются. Игнорируются только `*.exe` и логи.

## Перезапуск демона на Windows

`rupasctl off` останавливает пайплайн, но не гарантирует завершение процесса.
После подмены бинарника проверяйте `StartTime` процесса: старый образ продолжает
жить на переименованном файле, а новый экземпляр молча выходит по
single-instance мьютексу (`another rupasd instance is already running`).

```powershell
build\rupasctl.exe off
taskkill /IM rupasd.exe /F
# подменить бинарник, затем:
build\rupasctl.exe start      # или build\rupasd.exe -config configs\rupas.yaml
build\rupasctl.exe on
```

Логи демона — stderr; при запуске из TUI/CLI они пишутся в
`build/rupasd-tui.log`.

## Диагностика

- `rupasctl tui` — вкладка Статус (живой опрос) и редактор конфига.
- `-chlog=true` (по умолчанию) печатает строку на каждый ClientHello:
  `CH sni=... ech=... dst=... verdict=...` — основной инструмент разбора
  маршрутизации.
- Если пробы классификатора классифицируют всё как заблокированное, проверьте
  строку `prober: probes bound to Ethernet (…)`: при запущенном VPN-клиенте с TUN
  пробы без биндинга уходят в туннель и врут.
- Живые замеры: `go test -tags "live with_utls" -run TestLive... -v`.
