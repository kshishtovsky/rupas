# Релизы

Релиз полностью автоматический: **пуш в `master` = релиз**. Руками ничего
собирать и загружать не нужно.

## Как это работает

```
dev ──PR──► master ──► CI: тип коммитов → bump VERSION → тег vX.Y.Z
                              ├── windows-latest: rupasd/rupasctl/rupas-gui → zip
                              ├── ubuntu-latest: gomobile AAR → gradle assembleRelease → APK
                              └── publish: SHA256SUMS + CHANGELOG → GitHub Release
```

`.github/workflows/release.yml`:

| job | что делает |
|---|---|
| `version` | читает `VERSION`, смотрит коммиты с прошлого тега, поднимает версию, коммитит `chore(release): vX.Y.Z`, ставит и пушит тег |
| `windows` | `go build` с тегами `with_utls with_quic`, `-H=windowsgui` для GUI, сборка портативного zip |
| `android` | `gomobile bind` → AAR, `./gradlew assembleRelease` с ключом из секретов |
| `publish` | `SHA256SUMS.txt`, секция в `CHANGELOG.md`, GitHub Release с артефактами |

Если с прошлого тега нет `feat`/`fix`/`perf`, job `version` завершается без
релиза — пайплайн зелёный, тег не создаётся.

## Что нужно один раз настроить

Секреты репозитория (Settings → Secrets and variables → Actions):

| Секрет | Значение |
|---|---|
| `KEYSTORE_BASE64` | `base64 -w0 android/keystore/rupas-release.jks` |
| `KEYSTORE_PASSWORD` | пароль ключа (тот же, что в локальном `android/keystore.properties`) |

Ключ и пароль **никогда не коммитятся**: `android/keystore/` и
`android/keystore.properties` в `.gitignore`. Потеря ключа = невозможность
выпустить обновление, которое Android примет как обновление (придётся менять
`applicationId` или просить всех переустановить) — храни копию вне репозитория.

## Ручной запуск и переиздание

- Пересобрать артефакты для текущего `VERSION`: Actions → Release → Run
  workflow (job `version` ничего не выпустит без новых `feat`/`fix`, сборки
  останутся пропущенными).
- Выпустить релиз принудительно: сначала `bash scripts/bump.sh patch` (меняет
  `VERSION`), затем пуш в `master` с коммитом `fix: ...` — либо вручную поставить
  тег:

```bash
git tag v0.6.1 && git push origin v0.6.1
```

Тег без коммита `VERSION` разойдётся с приложениями: сначала правь `VERSION`.

## Откат

Релиз не удаляем — выпускаем следующий с исправлением (пользователи уже
получили APK, отозвать его нельзя).

1. Найти рабочий коммит: `git log --oneline v0.6.0` .
2. `git revert <bad-commit>` в `dev`, прогнать CI, смержить в `master` —
   выйдет `v0.6.1` (или `v0.7.0`, если в откате есть `feat`).
3. Если сломан сам пайплайн (APK не собирается) — править workflow в `dev`,
   проверять прогоном Release вручную, затем мерж.

Крайний случай — ключ подписи скомпрометирован: новый ключ, новый
`applicationId` или одноразовая переустановка у всех, MAJOR-бамп.

## Локальная проверка перед пушем

```bash
mingw32-make build gui      # десктоп с обязательными тегами
mingw32-make android-smoke  # портабельность ядра под android/arm64
mingw32-make test           # go test -count=1 ./...
```

APK локально: `mingw32-make aar apk` (нужны JDK17, ANDROID_HOME, gomobile).
