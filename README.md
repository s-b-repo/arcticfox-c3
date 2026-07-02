# C3 — Async Networking & Codec Framework

A modular Rust framework for asynchronous content synchronization and
text encoding across GitHub, GitLab, and paste services.

## Architecture

```
c3 (dashboard) ──HTTP──► arcticfox-api ──JSON──► control_config.json
     │                        │                        │
     │ 8-tab TUI              ├─ /api/admin/*  (full)  ├─ repos, commands
     │ Bots/Repos/Cmds        ├─ /api/lints/* (read)   ├─ heartbeat config
     │ Attack/Scan/Implants   └─ /api/heartbeat/*      └─ tokens, session key
     │ Config/Stats
     │
arcticfox-agent ──poll──► GitHub/GitLab READMEs ◄──push── arcticfox-control
     │                                                        │
     ├─ fetcher (ZW extract+headers)                          ├─ push/pull/paste
     ├─ heartbeat (ZW UA + response commands)                 ├─ command queue
     ├─ executor (shell, download, upload, permakill, sk)     └─ attack studio
     ├─ icmp_heartbeat (type 13/14 covert)                   
     ├─ log_covert (inter-agent via auth.log)
     ├─ anti_analysis (debugger/VM/sandbox detection)
     ├─ anti_forensics (exe spoof, FD camo, timestamps)
     ├─ uncovered (fanotify, eBPF, LD_AUDIT, CRIU)
     ├─ evasion (systemd dropin, ICMP timestamp, busybox)
     └─ systemd_gen (generator injection persistence)
```

## Crates

| Crate | Description |
|-------|-------------|
| `arcticfox-core` | ZW codec, config types, crypto (ChaCha20-Poly1305 + HKDF), repo ops, FBI-NET |
| `arcticfox-agent` | Async polling client with self-healing, stealth, anti-analysis, ICMP/log covert |
| `arcticfox-api` | REST API server (Axum) for admin, monitoring, and heartbeat |
| `arcticfox-control` | Operator CLI for managing dead-drop repos and commands |
| `arcticfox-dashboard` | Unified TUI console (`c3` binary) with 8 tabs |
| `arcticfox-scan` | Async network scanner with honeypot detection, zmap sharding |
| `arcticfox-mcp` | Model Context Protocol server for AI integration (15 tools, 4 tiers) |
| `arcticfox-zwtransport` | Encrypt-then-ZW-encode framing layer for all protocols |
| `arcticfox-bindshell` | Multi-protocol ZW-encrypted listener (TCP/UDP/ICMP) |
| `arcticfox-uring` | Linux io_uring kernel-bypass async I/O + memfd_exec |
| `arcticfox-lol` | System utility command template library (GTFOBins/LOLBAS catalog) |

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

The agent polls configured repos for commands, executes them, and sends heartbeats via HTTP, ICMP, and log covert channels.

## Configuration Files

| File | Purpose |
|------|---------|
| `api_config.json` | API server tokens, host, port, padding settings |
| `control_config.json` | Repos, commands, heartbeat URLs, platform tokens, session key |
| `pb_config.json` | Agent poll config (repos, interval, jitter, ICMP/log_covert settings) |
| `bots.json` | Bot heartbeat tracking (auto-generated) |

**All config files are excluded from version control.** They contain credentials.

## Documentation

| Document | Topic |
|----------|-------|
| [Architecture](docs/Architecture.md) | Data flow, crate dependency graph, ZW codec spec, AEAD pipeline |
| [Getting Started](docs/Getting-Started.md) | Install, build, configure |
| [API Reference](docs/API-Reference.md) | REST endpoints, auth, heartbeat, MCP tools |
| [Dashboard Guide](docs/Dashboard.md) | `c3` TUI usage, 8-tab reference, keyboard shortcuts |
| [Command Reference](docs/Commands.md) | FBI agent commands and operator CLI reference |
| [Configuration Reference](docs/Configuration.md) | All config files, every field documented |
| [Stealth Guide](docs/Stealth-Guide.md) | Process camouflage, domain fronting, TLS fingerprinting |
| [Detection Bypasses](docs/Detection-Bypasses.md) | Per-technique detection + bypass for 12 methods |
| [MITRE Mapping](docs/MITRE-Mapping.md) | 45+ techniques across 10 tactics |
| [Novel Techniques](docs/Novel-Techniques.md) | 4 zero-MITRE techniques (LD_AUDIT, fanotify, eBPF, CRIU) |
| [FBI-NET Compat](docs/FBI-NET-Compat.md) | `### run` format, permakill, serialkiller |
| [Rustsploit Interop](docs/Rustsploit-Interop.md) | API spec, bridge, credential sharing |

## Requirements

- Rust 1.85+ (edition 2024)
- Linux recommended (io_uring, ICMP, anti-forensics, fanotify, eBPF)
- macOS and Windows supported with graceful platform degradation

## License

GPL-3.0-only
