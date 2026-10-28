## v0.7.0

- chore(release): v0.7.0 (ea3fd0f)
- chore: релиз 0.7.0 — автообновление Android и GUI (2bc6828)
- fix(android): диалог обновления не уезжает под системный (32ca4c1)
- docs(agents): gomobile требует Windows-пути в ANDROID_HOME (fd8e5f6)
- docs: статистика репозитория в README и решения по PRD (f802c55)
- feat(gui): проверка и установка обновлений в интерфейсе (122d5c6)
- feat(update): клиент GitHub Releases и проверка версии (20aaf69)
- fix(scripts): make-dist берёт версию из VERSION в имени архива (7dc7b3f)

# Changelog

Формат: [Keep a Changelog](https://keepachangelog.com/ru/1.1.0/),
версионирование — [SemVer](https://semver.org/lang/ru/).
Записи генерируются CI из Conventional Commits при выпуске релиза
(`docs/VERSIONING.md`); вручную править не нужно.

## [0.6.0] — 2026-10-28

Первый публичный релиз: репозиторий, CI/CD, автообновление.

### Added

- Единый источник версии `VERSION`, флаг `-version` у `rupasd`, `rupasctl`,
  `rupas-gui`; `internal/version` с semver-сравнением.
- Релизный конвейер GitHub Actions: сборка Windows-архива и APK по тегу,
  Release с контрольными суммами и авто-changelog.
- `docs/PRD_RELEASE_PIPELINE.md` — требования к релизам и автообновлению.

### Changed

- Go-модуль переименован в `github.com/kshishtovsky/rupas`.
- Android: `versionName`/`versionCode` берутся из `VERSION`, подпись — из
  локального `keystore.properties` (ключ вне git).

### Security

- Release-keystore и пароли вычищены из истории git; ключ хранится только
  локально и в GitHub Secrets, пароль ключа сменён.
