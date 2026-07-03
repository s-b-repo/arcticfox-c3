.PHONY: build run api dashboard agent test check clean

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

## Start the API server (background), print token, monitor logs
api:
	@echo "=== Starting API server ==="
	@cargo run --release --bin arcticfox-api &
	@sleep 2
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	echo ""; \
	echo "  API Server: http://localhost:7443"; \
	echo "  Admin token: $${ADMIN:0:16}..."; \
	echo "  Dashboard:   cargo run --release --bin c3 -- --token $${ADMIN:0:16}..."; \
	echo "  Quick Ops:   curl http://localhost:7443/api/admin/stats -H 'Authorization: Bearer $${ADMIN}'"; \
	echo ""; \
	echo "  Press Ctrl+C to stop"; \
	wait

## Start the dashboard (requires API server running)
dashboard:
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	cargo run --release --bin c3 -- --token $$ADMIN

## Start the agent (requires config with repos)
agent:
	cargo run --release --bin arcticfox-agent -- --config pb_config.json

# ── Quick Start ──────────────────────────────────────────────────────

## First time: build everything, print dashboard launch command
start: build
	@echo ""
	@echo "=== Ready ==="
	@echo ""
	@echo "  Step 1: Start API server in one terminal:"
	@echo "    make api"
	@echo ""
	@echo "  Step 2: Launch dashboard in another terminal:"
	@ADMIN=$$(grep admin_token api_config.json | cut -d'"' -f4); \
	echo "    cargo run --release --bin c3 -- --token $${ADMIN}" 2>/dev/null || \
	echo "    cargo run --release --bin c3 -- --token <paste-admin-token-from-api_config.json>"
	@echo ""
	@echo "  Step 3: Configure repos in the dashboard's F2 tab,"
	@echo "          then queue commands in F3, push with 'p'"
	@echo ""

## Full end-to-end: start API + launch dashboard
all: build api
