# 07-deploy.md — TSPU audit fixes: deploy plan

## Что

3 дефекта TSPU-детекта: ECH false-negative, default action, profile verify.

## Куда

`master`, merge → автоматический релиз (`.github/workflows/release.yml`).

## Выкат

Rollout: **сразу** — non-breaking, forward-compatible (unsigned profiles accept при empty key). Backout: revert одного PR.

## Проверка после

```bash
go build -tags "with_utls with_quic" -trimpath -ldflags "-s -w" ./cmd/rupasd ./cmd/rupasctl && go test ./internal/inspector ./internal/config ./internal/prober -count=1
```
