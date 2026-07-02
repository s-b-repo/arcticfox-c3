# C3 — Wiki Index

A Rust framework for async content synchronization and invisible
Unicode text encoding across GitHub, GitLab, and paste services.

## Quick Links

| Document | Topic |
|----------|-------|
| [Getting Started](Getting-Started.md) | Install, build, configure first deployment |
| [Architecture](Architecture.md) | Crate map, data flow, ZW protocol, framing, AEAD pipeline |
| [API Reference](API-Reference.md) | REST endpoints, auth, heartbeat, MCP tools |
| [Dashboard Guide](Dashboard.md) | `c3` TUI usage, 8-tab reference, keyboard shortcuts |
| [Configuration Reference](Configuration.md) | All config files, every field documented |
| [Command Reference](Commands.md) | FBI agent commands, operator CLI reference |
| [Stealth Guide](Stealth-Guide.md) | Process camouflage, domain fronting, TLS fingerprinting |
| [Detection Bypasses](Detection-Bypasses.md) | Per-technique detection + bypass for 12 methods |
| [MITRE Mapping](MITRE-Mapping.md) | 45+ techniques across 10 tactics, verified |
| [Novel Techniques](Novel-Techniques.md) | 4 zero-MITRE techniques (LD_AUDIT, fanotify, eBPF, CRIU) |
| [FBI-NET Compat](FBI-NET-Compat.md) | `### run` format, permakill, serialkiller |
| [ZW Transport](ZW-Transport.md) | Encrypt→ZW pipeline, io_uring, framing spec |
| [Bind Shell](Bind-Shell.md) | TCP/UDP/53/ICMP multi-protocol ZW shell |
| [LOL Catalog](LOL-Catalog.md) | GTFOBins/LOLBAS living-off-the-land techniques |
| [Rustsploit Interop](Rustsploit-Interop.md) | API spec, bridge, credential sharing |
| [Rustsploit Checklist](RUSTSPLOIT-CHECKLIST.md) | 10 prioritized interop requirements |
| [Medium Article](MEDIUM-ARTICLE.md) | Human-readable narrative |
| [Social Release](SOCIAL-RELEASE.txt) | Reddit/LinkedIn post (no markdown) |

## Crate Overview (11 crates)

| Crate | Type | Purpose |
|-------|------|---------|
| `arcticfox-core` | lib | ZW codec, ring crypto, config, repo ops, FBI-NET |
| `arcticfox-agent` | bin+lib | Polling implant: stealth, anti-analysis, heartbeat, watchdog |
| `arcticfox-api` | bin | REST dashboard: Axum, auth, admin/lints/heatbeat |
| `arcticfox-control` | bin | Operator CLI: interactive shell, push/pull |
| `arcticfox-dashboard` | bin | `c3` TUI: 8-tab unified console |
| `arcticfox-scan` | bin | Async telnet scanner + brute-forcer |
| `arcticfox-lol` | lib | GTFOBins/LOLBAS command catalog |
| `arcticfox-mcp` | bin | MCP server: 15 AI tools, 4-tier safety |
| `arcticfox-zwtransport` | lib | Encrypt→ZW framing transport layer |
| `arcticfox-bindshell` | bin | TCP/UDP/ICMP multi-protocol ZW shell |
| `arcticfox-uring` | lib | io_uring kernel-bypass + memfd exec |

## Key Numbers

- **97 unit tests** across all crates
- **11 crates**, Rust 2024 edition
- **29 stealth process names**, 25 bot hostname IDs
- **45+ GTFOBins/LOLBAS techniques**
- **35 IoT credentials** in scanner
- **55 malware targets** in SerialKiller
- **15 AI tools** (MCP) with 4-tier safety
- **Session-derived ZW markers** via HKDF
- **4 novel techniques** with zero MITRE coverage
