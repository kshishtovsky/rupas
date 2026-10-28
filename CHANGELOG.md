## v0.7.4

- chore(release): v0.7.4 (106042d)
- fix(xhttp): поток переживает свой dial — отправка не обрывается на старте (f5ec57a)
- docs(changelog): v0.7.3 (0e1c608)

## v0.7.3

- chore(release): v0.7.3 (3e6eb0a)
- fix(xhttp): отправка медиа больше не висит на середине (e590b8a)
- docs(perf): замер после правок на 0.7.2 (35ba493)
- docs(perf): замер после правок на 0.7.2 (f399470)
- docs(changelog): v0.7.2 (5ff7b7b)

## v0.7.2

- chore(release): v0.7.2 (98d7546)
- fix(update): диалог обновления — без префикса v и без всей истории (ac66a03)
- fix(update): диалог обновления — без префикса v и без всей истории (76fd3e2)
- docs(changelog): v0.7.1 (b38f7e4)

## v0.7.1

- chore(release): v0.7.1 (f49824c)
- perf(android): 0.7.1 — меньше фонового шума и CPU (d124119)
- perf(android): убрать фоновый шум — уровни логов, gcTick, поллинг (6b2521b)
- docs: перформанс-аудит Android (0c62862)
- docs: перформанс-аудит Android на живом устройстве (176dbce)
- docs(releasing): переиздание по тегу и грабли CI (784eb9d)
- docs(changelog): v0.7.0 (1594d0a)
- ci(release): полный путь к sdkmanager (нет в PATH без setup-android) (80ed9c8)
- ci(release): снимать префикс v с переиздаваемого тега (055a786)
- ci(release): переиздание тега через input workflow_dispatch (665cc4e)
- ci: починка android-джобы релиза и переиздание по тегу (9ec972d)
- ci: android-джоба без setup-android, переиздание по тегу (8c34743)

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
