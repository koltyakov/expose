APP := expose
PKG := github.com/koltyakov/expose

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: help tidy fmt test build run-server run-client client-login apikey-create apikey-list apikey-revoke clean

help:
	@echo "Targets:"
	@echo "  make tidy           - Run go mod tidy"
	@echo "  make fmt            - Format Go code"
	@echo "  make test           - Run tests"
	@echo "  make build          - Build binary to ./bin/$(APP)"
	@echo "  make run-server     - Run server (env-driven)"
	@echo "  make run-client     - Run tunnel client (env-driven)"
	@echo "  make client-login   - Save client server URL + API key"
	@echo "  make apikey-create  - Create API key"
	@echo "  make apikey-list    - List API keys"
	@echo "  make apikey-revoke  - Revoke API key (requires KEY_ID=...)"
	@echo "  make clean          - Remove ./bin"

tidy:
	go mod tidy

fmt:
	gofmt -w -s .

test:
	go test ./...

build:
	go build -o bin/$(APP) ./cmd/expose

run-server:
	go run ./cmd/expose server

client-login:
	go run ./cmd/expose login \
		--server $${EXPOSE_DOMAIN:-example.com} \
		--api-key $${EXPOSE_API_KEY:-}

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
	rm -rf bin
