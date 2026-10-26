# Rupas Android — PRD
## v1.0 · 2026-10-26 · основан на PRD/SYSTEM_DESIGN E:\rupas и решениях владельца от 2026-10-26

Системный дизайн: `docs/SYSTEM_DESIGN.md` (ADR, граница Java↔Go, горячий путь,
desync-механика rootless, жизненный цикл, бюджет батареи, тестирование).

---

## 1. Решения владельца (зафиксированы 2026-10-26)

| # | Вопрос | Решение |
|---|---|---|
| D1 | Ядро | Go-ядро rupas (inspector / rules / desync / tunnel / prober / supervisor) компилируется в AAR через **gomobile**; **Java — только GUI и VpnService** |
| D2 | Обхват трафика | **v1.1, пересмотрено** после анализа антифрод-детекта (2026-10-26): TUN на всё, **кроме UID-исключений** — российские чувствительные приложения (банки, Госуслуги, маркетплейсы) выводятся из VPN через `addDisallowedApplication`; авто-скан `ru.*`/`su.*` + зашитый список. Whitelist-режим (`addAllowedApplication`) — опция |
| D3 | Desync в v1 | **Fake+TTL и split с калибровкой пробером**, как на Windows; перебор стратегий, если мобильный ТСПУ режет иначе |
| D4 | Дистрибуция | **Внутренний APK для себя**, без публикации (ни Play, ни GitHub Releases) |
| D5 | Минимальная версия | **API 26+** (Android 8.0); foreground service всё равно обязателен |

## 2. Видение

Одна кнопка на телефоне: клиент сам решает судьбу каждого потока — desync локально
(полная скорость канала, без сервера), туннель на VPS (VLESS-Reality) или direct.
Пользователь не настраивает прокси ни в Telegram, ни в браузере. Root не требуется.

**Не-цели v1:** iOS, монетизация, сторы, мультипользовательский режим,
per-app маршрутизация (зафиксировано как расширение v2), TV/Android Auto профили.

## 3. Лабораторный фундамент

Домашний ISP измерен (см. PRD E:\rupas §2): SNI-блэкхолы YT/Discord, IP-блэкхол TG,
UDP-медиа порты мертвы, окно TTL фейков [12..20], ECH дропается.

**Мобильный ТСПУ не измерен.** PRD E:\rupas прямо называет это риском v1.
Следствие: **первый спринт — замер мобильного оператора на реальном телефоне**
(матрица из dpi-bypass-lab: TCP connect → TLS с SNI / чужим SNI / без SNI,
UDP :53/:123/:3478/:19302, свип TTL). До замера все desync-параметры — допущение.

Допущения, которые проверяет спайк S0 (см. SYSTEM_DESIGN §12):
- `setsockopt(IP_TTL)` доступен из приложения с обычным APK (не root) — подтверждено
  практикой byedpi/ByeByeDPI/SlipNet, но на целевом устройстве не проверен;
- `splice(SPLICE_F_GIFT)`-трюк fake-then-swap работает на ядре Android целевого
  устройства (тот же механизм, что в byedpi на Linux; SlipNet повторил его в JNI
  на Android);
- gVisor netstack в Android-процессе держит нагрузку всех приложений (прецедент:
  sing-box for Android).

## 4. User Stories

- **US-A1** Пользователь жмёт одну кнопку «Включить». Система показывает стандартный
  диалог VPN-разрешения, после — YouTube 4K играет (desync-ветка, полная скорость).
- **US-A2** Telegram работает без ввода прокси в клиенте (CIDR → туннель VLESS-Reality).
- **US-A3** Discord: текст, медиа и голос одновременно; голос (UDP) через туннель.
- **US-A4** Смена сети Wi-Fi ↔ мобильный: клиент за ≤30 c перекалибровывается под
  новый ТСПУ молча; профили провайдеров раздельные (Wi-Fi и мобильный — разные ТСПУ).
- **US-A5** VPS-эндпоинт подхватывается вставкой ссылки/QR (vless:// как в Happ),
  секреты хранятся в EncryptedSharedPreferences.
- **US-A6** «Почему не работает» → шеринг текстового отчёта (профиль, последние
  вердикты, состояние туннеля) в один тап.
- **US-A7** Экран выключен, приложение в фоне: туннель живёт (foreground service),
  батарея не сажается (probes только по событиям сети).
- **US-A8** Always-on VPN в системе: после перезагрузки туннель поднимается сам.
- **US-A9** Банки, Госуслуги, маркетплейсы работают без заглушки «отключите VPN»
  и видят реальный RU-IP при включённом rupas (UID-исключения, см. ADR-9 / SD §7.1).

## 5. Таблица маршрутизации (паритет с десктопом, 2026-10-26)

Порядок разрешения: **CIDR → SNI → ports → default**; правило имеет `proto`.

| Трафик | Действие |
|---|---|
| LAN (RFC1918, link-local, multicast) | DIRECT |
| DNS :53 | DIRECT (защищённый сокет) |
| Telegram CIDR (149.154.160.0/20, 91.108.0.0/16, 91.105.192.0/23, 185.76.151.0/24, 95.161.76.100/32) | TUNNEL → VLESS-Reality |
| YouTube (*.youtube.com, *.googlevideo.com) TCP:443 | DESYNC fake+TTL / split (калибровка) |
| Discord (все зоны) TCP:443 | TUNNEL (настоящий ECH; GREASE ≠ ECH) |
| Discord voice UDP (50000–65535), STUN :3478 | TUNNEL → XUDP/Hysteria2 |
| RU-зоны (.ru/.su/.рф/…), RU-сервисы на .com (vk.com, ok.ru, userapi.com) | DIRECT |
| UDP:443 (QUIC) | BLOCK (дроп в netstack; браузер уйдёт на TCP) |
| всё остальное | TUNNEL |

Отличие от десктопа: **вердикт «всё остальное → tunnel» не требует RST+передиал** —
на Android SNI виден в netstack до установления исходящего соединения (см.
SYSTEM_DESIGN §5), значит терминатор терминирует все соединения, а не только
SYN-ведённые. Убирается единственная цена desktop-политики (+1 RTT на новый dst).

## 6. Скоуп MVP (Android v1)

1. Go-ядро в AAR (gomobile): inspector, rules, desync, tunnel (sing-box lib),
   prober, supervisor — с платформенным слоем `internal/transport/android`.
2. Java: GUI (одна кнопка, статус, лог, редактор правил v0 — YAML import/export),
   VpnService (TUN fd, protect-проброс), foreground-нотификация со статусом.
3. Desync: split (несколько стратегий), fake+TTL через JNI-примитивы
   (setTtl / sendFakeThenSwap), автокалибровка TTL пробером.
4. Туннель: тот же VPS-эндпоинт, что на десктопе (VLESS-Reality + XHTTP-fallback).
5. Диагностика: экспорт отчёта; живые вердикты CH в лог-экране.

**Вне MVP v1:** полноценный per-app движок маршрутизации (правила per-app в ядре —
UID-исключения уже в v1, per-app правила — v2), автоматические обновления,
community-списки правил, IPv6 TUN (v1 — IPv4-only TUN, IPv6 внутрь TUN не
маршрутизируем; см. SYSTEM_DESIGN §11).

## 7. Риски

| Риск | Вер. | Митигация |
|---|---|---|
| Мобильный ТСПУ режет иначе (L4 не измерен) | высокая | спайк S0/S1 — замер до кода desync; probe-engine портабелен; per-network профили |
| splice/vmsplice недоступен/запрещён на ядре устройства | средняя | fallback: fake через обычный write (тогда fake доходит до сервера → нужен fake-swap) → если и это не ок: v1 без fake, только split/multisplit (проверено rootless на DPITunnel/ByeDPI) |
| Kill системы: сервис убит в фоне | средняя | foreground service + START_STICKY + always-on VPN + `onRevoke`-обработка |
| Один VPN слот: конфликт с Happ/другим VPN | высокая | детект чужого VpnService до establish, явное сообщение; только один активный |
| gomobile-биндинг тормозит на горячем пути | низкая | горячий путь целиком в Go; граница Java↔Go — только управление, 0 вызовов на пакет |
| Батарея: пробы/калибровка в фоне | средняя | пробы только на NetworkCallback-события; анти-эскалационный pacing как на десктопе |
| Антифрод-детект: getAllNetworks()/NetworkCallback всё ещё видит TRANSPORT_VPN даже для исключённых UID (полевого подтверждения «полной невидимости» нет) | средняя | спайк S4 — зонд с детект-кодом; честно документировать: гарантия только для activeNetwork-проверок (основной метод SDK) |
| Always-on lockdown («блокировать без VPN»): трафик UID-исключённых приложений **блокируется** (поведение addDisallowedApplication в lockdown, issuetracker 238109298) — банки умирают | средняя | детект lockdown-режима в Java + предупреждение в GUI; либо не advertised supports always-on lockdown |
| AV/Play Protect ругается на sideload APK | средняя | свой APK без публикации: игнор предупреждения, задокументировать |

## 8. Roadmap

- **W1:** спайк S0 — замер мобильного ТСПУ на телефоне (матрица dpi-bypass-lab,
  USB-tether не нужен: зонд прямо на устройстве); ADR-фиксация профиля.
- **W2:** gomobile-каркас: ядро собирается в AAR, Java-сервис поднимает TUN,
  direct-трафик ходит (без desync/tunnel) — базовый поток пакетов жив.
- **W3:** туннель (sing-box lib) + правила + routing-политика; TG/Discord работают.
- **W4:** desync: split-стратегии; fake+TTL через JNI-примитивы; калибровка пробером.
- **W5:** профили per-network, автовосстановление, always-on, диагностика.
- **W6:** полевые испытания на мобильном операторе, стабилизация, GUI-полировка.

## Приложение. Ссылки на прецеденты

- byedpi (`hufrea/byedpi`, desync.c): setttl через `setsockopt(IP_TTL)`,
  fake через `vmsplice(SPLICE_F_GIFT)+splice`, restore-механизм страниц.
- SlipNet (anonvector/SlipNet): JNI `sendFakeThenSwap` на Android — подтверждение
  механики fake-then-swap на мобильном ядре; `TCP_MAXSEG` clamp для форсированного
  фрагментации по сегментам.
- ByeByeDPI / ByeDPIAndroid: rootless VPN-режим = VpnService + hev-socks5-tunnel
  → локальный прокси с desync; per-app белый/чёрный список.
- sing-box for Android (libbox): паттерн «Go-ядро AAR + VpnService + gVisor»,
  передача TUN fd в Go,PlatformInterface-колбэки.
- DPITunnel-android: Java+VpnService+desync, автоопределение настроек ISP.
