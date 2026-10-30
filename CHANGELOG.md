## v0.8.6

- chore(release): v0.8.6 (eae8d45)
- fix(gui): скачивание обновления повторяется после сброса соединения (6b4720b)
- docs(changelog): v0.8.5 (1c853c5)

## v0.8.5

- chore(release): v0.8.5 (0eb89b4)
- fix(gui): проверка обновлений и GeoIP переживают сброс соединения (6be3ad9)
- docs(changelog): v0.8.4 (c1646e1)

## v0.8.4

- chore(release): v0.8.4 (f7c6437)
- fix(socks5): ответ CONNECT ограничен дедлайном вызывающего (1755a6a)
- docs(changelog): v0.8.3 (4bbdc0d)

## v0.8.3

- chore(release): v0.8.3 (5b3e220)
- fix(android): direct больше не выходит вперёд живого канала из-за бана (e057090)
- docs(changelog): v0.8.2 (dada44f)

## v0.8.2

- chore(release): v0.8.2 (acf9376)
- Merge remote-tracking branch 'origin/master' (12b42ab)
- fix(android): дайл в канал ограничен 6 с, смерть после commit видна в логе (962d87b)
- docs(changelog): v0.8.1 (4a49e97)

## v0.8.1

- chore(release): v0.8.1 (3635b45)
- merge: android — рабочая цепочка не уходит в непроверенные каналы на 10 с (6d29e82)
- fix(android): доказанный канал больше не теряет первое место из-за bench (bd57c6b)
- docs(changelog): v0.8.0 (f018d50)

## v0.8.0

- chore(release): v0.8.0 (dfbe035)
- Merge remote-tracking branch 'origin/master' (75dd3b1)
- merge: 0.8 — маршрутизация по процессу, тёмная тема, проверка конфига и GeoIP в GUI (212e27e)
- fix(gui): сохранение каналов больше не стирает правила и исключения (f348a43)
- feat(gui): стадия «Приложения», + в шапке маршрутов, GeoIP, удаление канала (0f6ef1d)
- docs: план 0.8 — контракт и четыре потока работ (45d1db8)
- feat(gui): CheckLinks, RefreshGeoIP, ListProcesses (cbcb10e)
- feat(gui): тёмная тема — системная / светлая / тёмная (81f9c83)
- feat(routing): app-правило — маршрутизация по процессу на Windows (9af945c)
- docs(changelog): v0.7.6 (9939432)

## v0.7.6

- chore(release): v0.7.6 (b23a30a)
- merge: GUI-автозапуск демона и фикс FQN биндингов в релизную ветку (ac30997)
- fix(gui): демон стартует при входе в Windows, перехват восстанавливается после ребута (a4006c0)
- docs(changelog): v0.7.5 (45beefd)

## v0.7.5

- chore(release): v0.7.5 (95bb379)
- fix(android): профили не включаются сами при смене темы (87bca6e)
- docs(changelog): v0.7.4 (1bdef02)
- docs: убрать скриншоты из README (4aa5b27)

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
