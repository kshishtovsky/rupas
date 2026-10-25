# rupas-android

Порт клиента обхода DPI **rupas** (Windows, Go) на Android: Go-ядро через gomobile
(AAR) + нативный Java GUI с VpnService. Одна кнопка: Telegram, YouTube, Discord
без настройки прокси, root не нужен.

Документация:

| Файл | Содержание |
|---|---|
| `docs/PRD.md` | продуктовые требования, user stories, скоуп, риски, roadmap |
| `docs/SYSTEM_DESIGN.md` | ADR, архитектура Java↔Go, горячий путь, desync-механика на Android, жизненный цикл, тестирование |

Исходный проект: `E:\rupas` (см. `docs/PRD.md` и `docs/SYSTEM_DESIGN.md` там —
здесь портируются только решения, ядро переиспользуется кодом).

Статус: **дизайн** (реализация не начата).
