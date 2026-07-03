.PHONY: build run api dashboard agent test check clean setup start

# ── Build ───────────────────────────────────────────────────────────

build:
	cargo build --release

check:
	cargo check

test:
	cargo test --lib

clean:
	cargo clean

# ── Run ─────────────────────────────────────────────────────────────

## Start the API server, print token
api:
	@echo "=== Starting API server ==="
	@cargo run --release --bin arcticfox-api &
	@sleep 2
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	echo ""; \
	echo "  API Server: http://localhost:7443"; \
	echo "  Admin token: $${ADMIN:0:16}..."; \
	echo "  Dashboard:   make dashboard"; \
	echo "  Setup:       make setup"; \
	echo "  Quick Ops:   curl http://localhost:7443/api/admin/stats -H 'Authorization: Bearer $${ADMIN}'"; \
	echo ""; \
	echo "  Press Ctrl+C to stop"; \
	wait

## Start the dashboard (requires API server running)
dashboard:
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	cargo run --release --bin c3 -- --token $$ADMIN

## Run guided setup wizard (walks through first-time configuration)
setup:
	@echo "=== C3 Guided Setup ==="
	@echo ""
	@echo "  Starting API server in background..."
	@cargo run --release --bin arcticfox-api > /tmp/c3-api.log 2>&1 &
	@sleep 3
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	cargo run --release --bin c3 -- --token $$ADMIN --setup; \
	kill $$(lsof -ti:7443) 2>/dev/null; \
	true

## Start the agent (requires config with repos)
agent:
	cargo run --release --bin arcticfox-agent -- --config pb_config.json

# ── Quick Start ──────────────────────────────────────────────────────

## First time: build everything, print launch commands
start: build
	@echo ""
	@echo "=== Ready ==="
	@echo ""
	@echo "  Quick:   make setup    (guided setup wizard + API server)"
	@echo "  Manual:  make api      (API server in one terminal)"
	@echo "           make dashboard (TUI in another terminal)"
	@echo ""
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	echo "  Token:   $${ADMIN:0:16}..." 2>/dev/null; \
	echo ""

## Full end-to-end: start API + launch dashboard
all: build api
