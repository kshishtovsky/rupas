# rupas monorepo — единая точка сборки.
# Теги обязательны: без utls/quic sing-box мёртв в рантайме («uTLS is not included in this build»).

GO_TAGS_DESKTOP := with_utls with_quic
GO_TAGS_MOBILE  := with_utls with_quic with_gvisor
LDFLAGS         := -s -w
AAR_OUT         := android/app/libs/rupas-core.aar

.PHONY: build gui aar apk dist test bench lint android-smoke

## Десктоп: демон + CLI (обязательные теги!)
build:
	go build -tags "$(GO_TAGS_DESKTOP)" -trimpath -ldflags "$(LDFLAGS)" -o build/ ./cmd/rupasd ./cmd/rupasctl

## Десктопный GUI (Wails v3): -H=windowsgui обязателен (иначе консоль из Explorer)
gui:
	go build -trimpath -ldflags "$(LDFLAGS) -H=windowsgui" -o build/rupas-gui.exe ./cmd/rupas-gui

## Смок-тест портабельности ядра под android/arm64 (быстрее bind, гонять ДО aar)
android-smoke:
	GOOS=android GOARCH=arm64 go build -tags "$(GO_TAGS_MOBILE)" ./internal/inspector ./internal/rules ./internal/tunnel ./internal/prober ./internal/supervisor ./internal/desync ./internal/config ./internal/flowtable ./internal/core ./mobile

## AAR для Android: из gobind-пакета ./mobile этого же модуля (без replace).
## Первая сборка компилирует тулчейн x/mobile под 4 ABI — минуты, не убивать.
aar: android-smoke
	gomobile bind -tags "$(GO_TAGS_MOBILE)" -target=android -androidapi 26 -o $(AAR_OUT) ./mobile

## APK (JDK17/ANDROID_HOME в env; maven — через зеркала Tencent, уже в settings.gradle)
apk:
	cd android && ./gradlew.bat assembleDebug

## Портативный дистрибутив (боевой configs/rupas.yaml НЕ попадает — секреты)
dist: build gui
	powershell -NoProfile -ExecutionPolicy Bypass -File scripts/make-dist.ps1

test:
	go test -race -count=1 ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

lint:
	go vet ./...
	staticcheck ./internal/tunnel/ ./internal/inspector/ ./internal/rules/ ./internal/flowtable/ ./internal/desync/
