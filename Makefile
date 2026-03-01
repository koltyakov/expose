APP := expose
PKG := github.com/koltyakov/expose
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
BIN_DIR := bin

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: help tidy deps fmt lint vet test test-race test-coverage bench build build-all release-check release-local ci run-server run-server-wizard run-client client-login apikey-create apikey-list apikey-revoke clean

help:
	@echo "Targets:"
	@echo "  make tidy           - Run go mod tidy"
	@echo "  make deps           - Download + tidy dependencies"
	@echo "  make fmt            - Format Go code"
	@echo "  make lint           - Run golangci-lint"
	@echo "  make vet            - Run go vet"
	@echo "  make test           - Run tests"
	@echo "  make test-race      - Run tests with race detector"
	@echo "  make test-coverage  - Run tests with coverage output"
	@echo "  make bench          - Run focused performance benchmarks"
	@echo "  make build          - Build binary to ./$(BIN_DIR)/$(APP)"
	@echo "  make build-all      - Cross-build common release binaries"
	@echo "  make release-check  - Validate GoReleaser config"
	@echo "  make release-local  - Build snapshot artifacts via GoReleaser"
	@echo "  make ci             - Run local CI checks"
	@echo "  make run-server     - Run server (env-driven)"
	@echo "  make run-server-wizard - Guided server setup (.env + optional API key)"
	@echo "  make run-client     - Run tunnel client (env-driven)"
	@echo "  make client-login   - Save client server URL + API key"
	@echo "  make apikey-create  - Create API key"
	@echo "  make apikey-list    - List API keys"
	@echo "  make apikey-revoke  - Revoke API key (requires KEY_ID=...)"
	@echo "  make clean          - Remove ./$(BIN_DIR)"

tidy:
	go mod tidy

deps:
	go mod download
	go mod tidy

fmt:
	gofmt -w -s .

lint:
	@if ! command -v golangci-lint >/dev/null 2>&1; then \
		echo "golangci-lint is required: https://golangci-lint.run/welcome/install/"; \
		exit 1; \
	fi
	golangci-lint run

vet:
	go vet ./...

test:
	go test ./...

test-race:
	go test -race -v ./...

test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -func=coverage.out

bench:
	go test ./internal/client ./internal/server ./internal/store/sqlite ./internal/tunnelproto -bench . -run ^$

build:
	@mkdir -p $(BIN_DIR)
	go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP) ./cmd/expose

build-linux:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP) ./cmd/expose

build-all:
	@mkdir -p $(BIN_DIR)
	GOOS=linux GOARCH=amd64 go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP)-linux-amd64 ./cmd/expose
	GOOS=linux GOARCH=arm64 go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP)-linux-arm64 ./cmd/expose
	GOOS=darwin GOARCH=amd64 go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP)-darwin-amd64 ./cmd/expose
	GOOS=darwin GOARCH=arm64 go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP)-darwin-arm64 ./cmd/expose
	GOOS=windows GOARCH=amd64 go build -ldflags "-X $(PKG)/internal/cli.Version=$(VERSION)" -o $(BIN_DIR)/$(APP)-windows-amd64.exe ./cmd/expose

release-check:
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "goreleaser is required: https://goreleaser.com/install/"; \
		exit 1; \
	fi
	goreleaser check

release-local:
	@if ! command -v goreleaser >/dev/null 2>&1; then \
		echo "goreleaser is required: https://goreleaser.com/install/"; \
		exit 1; \
	fi
	goreleaser build --snapshot --clean

ci: deps fmt vet test test-race build release-check
	@echo "All CI checks passed."

run-server:
	go run ./cmd/expose server

run-server-init:
	go run ./cmd/expose server init

client-login:
	@if [ -n "$$EXPOSE_API_KEY" ]; then \
		go run ./cmd/expose login --server "$${EXPOSE_DOMAIN:-example.com}" --api-key "$$EXPOSE_API_KEY"; \
	else \
		go run ./cmd/expose login --server "$${EXPOSE_DOMAIN:-example.com}"; \
	fi

run-client:
	@if [ -z "$$EXPOSE_PORT" ]; then echo "EXPOSE_PORT is required"; exit 1; fi
	@if [ -n "$$EXPOSE_SUBDOMAIN" ]; then \
		go run ./cmd/expose http --domain "$$EXPOSE_SUBDOMAIN" $${EXPOSE_PORT}; \
	else \
		go run ./cmd/expose http $${EXPOSE_PORT}; \
	fi

apikey-create:
	go run ./cmd/expose server apikey create --name "default"

apikey-list:
	go run ./cmd/expose server apikey list

apikey-revoke:
	@if [ -z "$$KEY_ID" ]; then echo "KEY_ID is required"; exit 1; fi
	go run ./cmd/expose server apikey revoke --id $$KEY_ID

clean:
	rm -rf $(BIN_DIR)
