# ArcticFox C3 — Wiki Index

ArcticFox C3 is an async zero-width dead-drop C2 framework in Rust (edition 2024).  
Commands are hidden in invisible Unicode inside GitHub/GitLab README files.  
No listening ports, no custom protocols, no network signatures.

## Quick Links

| Document | Topic |
|---|---|
| [Architecture](Architecture.md) | Crate map, data flow, ZW protocol, framing |
| [Getting Started](Getting-Started.md) | Install, build, configure first C2 |
| [API Reference](API-Reference.md) | REST endpoints, auth, heartbeat, MCP tools |
| [Implant Guide](Implant-Guide.md) | Agent deployment, stealth, persistence, watchdog |
| [ZW Transport](ZW-Transport.md) | Encrypt→ZW pipeline, io_uring, framing spec |
| [Bind Shell](Bind-Shell.md) | TCP/UDP/53/ICMP multi-protocol ZW shell |
| [LOL Catalog](LOL-Catalog.md) | GTFOBins/LOLBAS living-off-the-land techniques |
| [FBI-NET Compat](FBI-NET-Compat.md) | `### run` format, permakill, serialkiller |
| [Stealth Guide](Stealth-Guide.md) | Process camouflage, domain fronting, TLS fingerprinting |
| [Rustsploit Interop](Rustsploit-Interop.md) | API spec, bridge, credential sharing, exploit pipeline |
| [MITRE Mapping](MITRE-Mapping.md) | 45+ techniques across 10 tactics, verified against v19 |
| [Detection Bypasses](Detection-Bypasses.md) | Per-technique detection + bypass for 12 methods |
| [Novel Techniques](Novel-Techniques.md) | 4 zero-MITRE techniques (LD_AUDIT, fanotify, eBPF, CRIU) |
| [Rustsploit Checklist](RUSTSPLOIT-CHECKLIST.md) | 10 prioritized interop requirements |
| [Medium Article](MEDIUM-ARTICLE.md) | Human-readable story of the build |
| [Social Release](SOCIAL-RELEASE.txt) | Reddit/LinkedIn post (no markdown) |

## Crate Overview (10 crates)

| Crate | Purpose | Bin/Lib |
|---|---|---|
| `arcticfox-core` | Foundation: ZW codec, ring crypto, config, repo ops, FBI-NET | lib |
| `arcticfox-agent` | C2 implant: polling loop, heartbeat, stealth, watchdog | bin + lib |
| `arcticfox-api` | REST dashboard: Axum, auth, admin/lints endpoints | bin |
| `arcticfox-control` | Operator CLI: interactive shell, push/pull | bin |
| `arcticfox-scan` | Async telnet scanner + brute-forcer | bin |
| `arcticfox-lol` | GTFOBins/LOLBAS command catalog | lib |
| `arcticfox-mcp` | MCP server: 15 AI tools, 4-tier safety | bin |
| `arcticfox-zwtransport` | Encrypt→ZW framing transport (16-char delimiters) | lib |
| `arcticfox-bindshell` | TCP/UDP/53/ICMP multi-protocol ZW shell | bin |
| `arcticfox-uring` | io_uring kernel-bypass + memfd exec | lib |

## Key Numbers

- **57 unit tests** (37 core + 9 lol + 7 zwtransport + 12 agent)
- **10 crates**, all Rust 2024 edition
- **29 stealth process names**, 25 bot hostname IDs
- **45+ GTFOBins/LOLBAS techniques**
- **35 IoT credentials** in scanner
- **55 malware targets** in SerialKiller
- **15 AI tools** (MCP) with 4-tier safety
- **16-char ZW frame delimiters** (collision probability < 10⁻⁹)
