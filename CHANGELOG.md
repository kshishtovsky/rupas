## v0.20.6 (unreleased)

- feat(TSPU): ECH false-negative fix — GREASE stub elen=4 больше не классифицируется как real ECH (inspector/clienthello.go, HPKE magic check)
- feat(TSPU): default action = Tunnel (PRD §5: «всё остальное → TUNNEL»)
- feat(TSPU): profile integrity — HMAC SHA-256 VerifyProfile + ErrProfileTampered fallback PROBING
- feat(battery): WakeLock PARTIAL на probe (RupasVpnService.acquire/release, re-entrant refcount)
- feat(battery): AlarmManager exact-alarm ACTION_NETWORK_CHANGE, SCHEDULE_EXACT_ALARM runtime permission
- feat(battery): foreground notification status-aware (ACTIVE/DEGRADED/OFF), IMPORTANCE_LOW channel
- fix(rules): UsePlatformNotification = true в platform_stub.go

## v0.20.5

- chore(release): v0.20.5 (1d02d2c)
- fix(guictrl): канал к 3x-ui не поднимался — flow терялся, свой сервер не исключался (7bbc860)
- fix(guictrl): тестовый бинарь физически не может писать в живой state-каталог (b4e0f52)

## v0.20.4

- chore(release): v0.20.4 (4f89366)
- fix(guictrl): тесты больше не затирают links.json живой установки (ce3b10d)
- docs(changelog): v0.20.3 (78752ea)

## v0.20.3

- chore(release): v0.20.3 (7c700d0)
- fix(guictrl): конфиг без правила по умолчанию больше не отправляет трафик с реальным IP (7c6e8fd)
- docs(changelog): v0.20.2 (2c3052b)

## v0.20.2

- chore(release): v0.20.2 (6809454)
- fix(capture): IPv6 CIDR-правило и утёкший tproxy-порт больше не убивают туннель (6d8bda6)

## v0.20.1

- chore(release): v0.20.1 (d95d8fb)
- fix(android): кнопки QR на живой вкладке настроек, а не в мёртвом экране (3591c52)
- docs(changelog): v0.20.0 (224dc7a)

## v0.20.0

- chore(release): v0.20.0 (cf9480f)
- Merge branch 'master' of github.com:kshishtovsky/rupas (0253380)
- feat(qr): перенос конфига через QR на Android, общий payload с десктопом (34af5c0)
- docs(changelog): v0.19.0 (a6fff01)

## v0.19.0

- chore(release): v0.19.0 (1f93eac)
- Merge branch 'master' of github.com:kshishtovsky/rupas (5b87336)
- Merge branch 'fix/audit-throughput': окно терминатора, GUI и QR-перенос конфига (6731711)
- feat(qr): экспорт и импорт всей конфигурации через QR (30836be)
- fix(reload): сохранение без изменений больше не рвёт живой туннель (6c9c962)
- fix(gui): лаги — подпись трея, поток снимков, опрос логов, двойной Status (a382a80)
- perf(guictrl): DetailedLogs читает лог инкрементально, а не 512 КиБ каждые 2 с (03b8003)
- fix(tunnel): приёмное окно терминатора масштабируется — 64 КиБ запирали upload (5dae8ec)
- docs(changelog): v0.18.2 (60154bf)

## v0.18.2

- chore(release): v0.18.2 (0764c1e)
- fix(tcpterm): SYN-ACK без опции WS запирал окно клиента в 64 КиБ (6e79bee)
- docs(changelog): v0.18.1 (da1dcdc)

## v0.18.1

- chore(release): v0.18.1 (0a906a5)
- test(tcpterm): регресс на потолок окна — синтетический RTT (0a906a5)
