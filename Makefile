BINARY_NAME=vpsguard
VERSION=$(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.version=$(VERSION) -X main.buildTime=$(BUILD_TIME)"

.PHONY: all build test clean install uninstall fmt vet lint

all: fmt vet test build

build:
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) ./cmd/vpsguard

test:
	go test -v -race -count=1 ./...

test-cover:
	go test -v -race -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

fmt:
	go fmt ./...

vet:
	go vet ./...

clean:
	rm -rf bin/ coverage.out coverage.html

install: build
	install -m 755 bin/$(BINARY_NAME) /usr/local/bin/$(BINARY_NAME)
	mkdir -p /etc/vpsguard
	mkdir -p /var/lib/vpsguard/geoip
	mkdir -p /var/log/vpsguard
	@if [ ! -f /etc/vpsguard/config.yaml ]; then \
		install -m 600 configs/config.example.yaml /etc/vpsguard/config.yaml; \
	fi
	install -m 644 init/vpsguard.service /etc/systemd/system/vpsguard.service
	systemctl daemon-reload
	@echo "VPSGuard installed. Edit /etc/vpsguard/config.yaml then: systemctl enable --now vpsguard"

uninstall:
	systemctl stop vpsguard 2>/dev/null || true
	systemctl disable vpsguard 2>/dev/null || true
	rm -f /usr/local/bin/$(BINARY_NAME)
	rm -f /etc/systemd/system/vpsguard.service
	systemctl daemon-reload
	@echo "VPSGuard uninstalled. Config in /etc/vpsguard/ preserved."
