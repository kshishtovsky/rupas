# Версионирование

Одна версия на весь проект — SemVer `MAJOR.MINOR.PATCH`, источник истины —
файл [`VERSION`](../VERSION) в корне репозитория.

## Правило (жёсткое)

**Любое изменение кода, попавшее в `master`, увеличивает версию.** Версию
поднимает CI по типам коммитов, поэтому «забыть» её невозможно; ручной bump
существует только для случая, когда версию нужно задать явно.

| Тип коммита (Conventional Commits) | Инкремент |
|---|---|
| `BREAKING CHANGE:` в теле или `feat!:` / `fix!:` в заголовке | MAJOR |
| `feat: ...` | MINOR |
| `fix: ...`, `perf: ...` | PATCH |
| `docs:`, `chore:`, `ci:`, `test:`, `refactor:`, `style:` | без релиза |

Итог: `master` без `feat`/`fix`/`perf` с прошлого тега новых версий не
выпускает — это нормально (правки документации не создают релиз).

## Куда попадает версия

| Место | Как |
|---|---|
| `rupasd -version`, `rupasctl -version`, `rupas-gui -version` | `-ldflags -X .../internal/version.Version` |
| Android `versionName` | gradle читает `../VERSION` |
| Android `versionCode` | `MAJOR*10000 + MINOR*100 + PATCH` (монотонен) |
| имя артефактов | `Rupas-win64-<ver>.zip`, `Rupas-android-<ver>-arm64.apk` |
| git-тег и Release | `v<ver>` |
| `CHANGELOG.md` | CI дописывает секцию при публикации |

## Ручной bump

```bash
bash scripts/bump.sh patch   # 0.6.0 -> 0.6.1
bash scripts/bump.sh minor   # 0.6.0 -> 0.7.0
bash scripts/bump.sh major   # 0.6.0 -> 1.0.0
```

Скрипт только меняет `VERSION` и коммитит его: тег и релиз всё равно создаст CI
при пуше в `master`. Приоритет у ручного значения — CI берёт текущий `VERSION`
и инкрементирует уже от него.

## Что считается breaking

- ломается формат `configs/rupas.yaml` (старый конфиг не читается);
- ломается JSON-протокол named pipe (старый `rupasctl`/GUI не работает с новым
  `rupasd`);
- меняется `applicationId` или ключ подписи APK (пользователь обязан
  переустановить приложение);
- удаляется или переименовывается флаг/команда CLI.
