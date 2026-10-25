.PHONY: test bench build lint lab

build:
	go build -tags "with_utls with_quic" -trimpath -ldflags "-s -w" ./cmd/rupasd ./cmd/rupasctl

test:
	go test -race -count=1 ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

lint:
	go vet ./...
