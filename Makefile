APP := expose
PKG := github.com/koltyakov/expose

ifneq (,$(wildcard .env))
include .env
export
endif

.PHONY: help tidy fmt test build run-server run-client apikey-create apikey-list apikey-revoke clean

help:
	@echo "Targets:"
	@echo "  make tidy           - Run go mod tidy"
	@echo "  make fmt            - Format Go code"
	@echo "  make test           - Run tests"
	@echo "  make build          - Build binary to ./bin/$(APP)"
	@echo "  make run-server     - Run server (configure env/flags)"
	@echo "  make run-client     - Run client (configure env/flags)"
	@echo "  make apikey-create  - Create API key"
	@echo "  make apikey-list    - List API keys"
	@echo "  make apikey-revoke  - Revoke API key (requires KEY_ID=...)"
	@echo "  make clean          - Remove ./bin"

tidy:
	go mod tidy

fmt:
	gofmt -w cmd internal

test:
	go test ./...

build:
	go build -o bin/$(APP) ./cmd/expose

run-server:
	go run ./cmd/expose server \
		--base-domain $${EXPOSE_BASE_DOMAIN:-example.com} \
		--db $${EXPOSE_DB_PATH:-./expose.db} \
		--api-key-pepper $${EXPOSE_API_KEY_PEPPER:-change-me} \
		--tls-mode $${EXPOSE_TLS_MODE:-auto}

run-client:
	go run ./cmd/expose client \
		--server $${EXPOSE_SERVER_URL:-https://tunnel.example.com} \
		--api-key $${EXPOSE_API_KEY:-} \
		--local $${EXPOSE_LOCAL_URL:-http://127.0.0.1:3000}

apikey-create:
	go run ./cmd/expose server apikey create \
		--db $${EXPOSE_DB_PATH:-./expose.db} \
		--api-key-pepper $${EXPOSE_API_KEY_PEPPER:-change-me} \
		--name $${KEY_NAME:-default}

apikey-list:
	go run ./cmd/expose server apikey list \
		--db $${EXPOSE_DB_PATH:-./expose.db}

apikey-revoke:
	@if [ -z "$$KEY_ID" ]; then echo "KEY_ID is required"; exit 1; fi
	go run ./cmd/expose server apikey revoke \
		--db $${EXPOSE_DB_PATH:-./expose.db} \
		--id $$KEY_ID

clean:
	rm -rf bin
