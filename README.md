# C3 — Async Networking & Codec Framework

A modular Rust framework for asynchronous content synchronization and
text encoding across GitHub, GitLab, and paste services.

## Architecture

```
c3 (dashboard) ──HTTP──► arcticfox-api ──JSON──► control_config.json
                             │                        │
                             ├─ /api/admin/*          ├─ repos, commands
                             ├─ /api/lints/*          ├─ heartbeat config
                             └─ /api/heartbeat/*      └─ tokens

arcticfox-agent ──poll──► GitHub/GitLab READMEs ◄──push── arcticfox-control
      │                                                        │
      ├─ fetcher (ZW extract)                                  ├─ push/pull
      ├─ heartbeat (open redirect)                             ├─ command queue
      └─ executor (shell, download, upload, popmsg)            └─ attack studio
```

## Crates

| Crate | Description |
|-------|-------------|
| `arcticfox-core` | ZW codec, config types, crypto (ChaCha20-Poly1305 + HKDF), repo operations |
| `arcticfox-agent` | Async polling client with self-healing backoff, stealth, anti-analysis |
| `arcticfox-api` | REST API server (Axum) for admin and monitoring |
| `arcticfox-control` | Operator CLI for managing dead-drop repos and commands |
| `arcticfox-dashboard` | Unified TUI console (`c3` binary) with 8 tabs |
| `arcticfox-scan` | Async network scanner with honeypot detection |
| `arcticfox-mcp` | Model Context Protocol server for AI integration |
| `arcticfox-zwtransport` | Encrypt-then-ZW-encode framing layer |
| `arcticfox-bindshell` | Multi-protocol ZW-encrypted listener (TCP/UDP/ICMP) |
| `arcticfox-uring` | Linux io_uring kernel-bypass async I/O transport |
| `arcticfox-lol` | System utility command template library |

## Quick Start

### 1. Build

```bash
cargo build --release
```

### 2. Start the API Server

```bash
./target/release/arcticfox-api
```

This auto-generates admin and lints tokens, saved to `api_config.json`.

### 3. Launch the Dashboard

```bash
./target/release/c3 --connect http://localhost:7443 --token <admin_token>
```

Or with environment variable:
```bash
C3_TOKEN=<admin_token> ./target/release/c3
```

### 4. Configure Dead-Drops

From the dashboard's **Repos** tab (`F2`), add your repos:
```
gh:your-org/your-repo
gitlab:your-group/your-repo
```

Set GitHub/GitLab tokens in the **Config** tab (`F7`).

### 5. Queue and Push Commands

From the **Commands** tab (`F3`), add commands and push to repos. From the **Attack** tab (`F4`), generate attack scripts using the built-in templates.

### 6. Deploy the Agent

```bash
./target/release/arcticfox-agent --config agent_config.json
```

The agent polls configured repos for commands, executes them, and sends heartbeats.

## Configuration Files

| File | Purpose |
|------|---------|
| `api_config.json` | API server tokens, host, port, padding settings |
| `control_config.json` | Repos, commands, heartbeat URLs, platform tokens |
| `pb_config.json` | Agent poll config (repos, interval, jitter) |
| `bots.json` | Bot heartbeat tracking (auto-generated) |

**All config files are excluded from version control.** They contain credentials.

## Documentation

- [Architecture](docs/Architecture.md)
- [Getting Started](docs/Getting-Started.md)
- [API Reference](docs/API-Reference.md)
- [Stealth Guide](docs/Stealth-Guide.md)
- [Detection Bypasses](docs/Detection-Bypasses.md)
- [MITRE Mapping](docs/MITRE-Mapping.md)
- [Novel Techniques](docs/Novel-Techniques.md)

## Requirements

- Rust 1.85+ (edition 2024)
- Linux recommended (io_uring, ICMP, anti-forensics)
- macOS and Windows supported with graceful platform degradation

## License

GPL-3.0-only
