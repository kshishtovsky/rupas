.PHONY: test bench build lint lab

build:
	go build -trimpath -ldflags "-s -w" ./cmd/rupasd ./cmd/rupasctl

test:
	go test -race -count=1 ./...

bench:
	go test -bench=. -benchmem -run=^$$ ./...

lint:
	go vet ./...
