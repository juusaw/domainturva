VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)
PKG := ./cmd/domainturva

.PHONY: all build build-freebsd test lint run clean tidy

all: build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/domainturva $(PKG)

build-freebsd:
	GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/domainturva-freebsd-amd64 $(PKG)

test:
	go test -race ./...

lint:
	go vet ./...
	@command -v staticcheck >/dev/null 2>&1 && staticcheck ./... || echo "staticcheck not installed, skipping"

run: build
	./bin/domainturva run --config ./config.yaml

tidy:
	go mod tidy

clean:
	rm -rf bin/
