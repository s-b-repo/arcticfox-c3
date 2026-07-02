# Changelog

## v4.1.0 (July 2026) — Bug Fixes & Integration Hardening

### Bug Fixes (34 total)
- **Runtime panics**: `i64::MIN.abs()` fixed with `wrapping_abs()` in anti-forensics. Nested `tokio::Runtime::new()` in MCP replaced with `Handle::current().block_on()` (3 sites). `CString::new().unwrap_or_default()` null-byte UB fixed.
- **Dashboard integration**: All 4 HTTP methods now check `resp.status().is_success()` before parsing JSON. Errors (401/403/404/409/429/500) are now surfaced instead of silently returning empty data.
- **MCP bugs**: `push_payload` now properly destructures `Result<bool>` instead of using `.is_ok()`. `build_payload` no longer silently returns empty vec on serialization failure.
- **Rustsploit bridge**: `r#gen_range` syntax error fixed.
- **Uncovered module**: `ob Sole` typo in C source generator fixed to `object`.
- **Serial killer**: Uses `tokio::process::Command` (non-blocking) with proper exit code reporting (`[ok]`/`[err]`).
- **Shell executor**: Added 60s `tokio::time::timeout` wrapper. Previously had no execution time limit.
- **`unlink_self()`**: Now resolves `/proc/self/exe` symlink before unlinking the real path.
- **Bot ID path**: Uses `std::env::temp_dir()` instead of hardcoded `/tmp/.sd-id` for cross-platform support.
- **Scanner**: Division-by-zero guard on `ZmapIpIterator::new()`.
- **Crypto**: `SystemRandom::fill` expects replaced with time-based fallback entropy. HKDF expects replaced with graceful `and_then` degradation.

### Error Handling Improvements (15+)
- Agent process dispatch: `let _ =` replaced with `warn!()` logging for command failures.
- Persistence operations: `.ok()` replaced with proper Result propagation.
- Heartbeat command channel: `len =` on send failures replaced with warn logging.
- Crypto token generation: `expect()` replaced with fallback entropy paths.

### Removed Dead Code
- `arcticfox-scan`: `AsyncBufReadExt` import, `ScanTarget` enum, dead `scan_ip`/`read_banner`/`brute_force` methods.
- `arcticfox-agent`: `GENERATOR_OUTPUT_EARLY/LATE` constants, `ModuleRunRequest` struct, `client` field from Heartbeat.
- `arcticfox-dashboard`: Unused `preview()` method, `BORDER_NONE` constant, 8 color constants, `block_panel()`, unused struct fields.
- `arcticfox-uring`: Unused `SocketAddr`/`AsRawFd` imports, `BUF_COUNT` constant.
- `arcticfox-core`: Doc comment on macro converted to regular comment.

### Config Additions
- `AgentConfig`: `icmp_heartbeat_dest`, `icmp_heartbeat_interval`, `log_covert_path`, `log_covert_interval`.
- `ControlConfig`: `session_key` field for encrypt-then-ZW payload protection.

### Documentation
- New: `docs/FBI-NET-Compat.md` — `### run` format, permakill, serialkiller reference.
- New: `docs/Dashboard.md` — Full `c3` TUI usage guide.
- New: `docs/Configuration.md` — All config files with field tables.
- New: `docs/Commands.md` — FBI agent commands and operator CLI reference.
- Updated: `README.md` — Full architecture diagram with new modules.
- Updated: `docs/Home.md` — Dashboard and new doc links.

## v4.0.0 (July 2026) — Rust Rewrite & Unified Dashboard

### Breaking Changes
- **Pure Rust**: All Python code removed. `control.py`, `api.py`, `pastebomb.py`, `oogascan.py`, `zwenc.py` replaced by Rust equivalents.
- **New binary**: `c3` unified TUI dashboard replaces the old Python control tool.
- **Config format**: `pb_config.json` and `oogascan.json` retired. Use `agent_config.json` for agent config.

### New Features
- **`c3` Dashboard**: 8-tab terminal UI (Bots, Repos, Commands, Attack Studio, Scanner, Implants, Config, Stats). Ratatui-based with color-coded status, keyboard navigation, and live auto-refresh.
- **Session-derived ZW markers**: Zero-width payload delimiters now randomized per session via HKDF from the session key. Prevents static fingerprinting of payload markers.
- **HKDF key derivation**: Replaced custom iterative HMAC with standard `ring::hkdf::HKDF_SHA256`.
- **Encrypt-then-ZW everywhere**: `seal_oneshot()`/`open_oneshot()` now wired into heartbeat, exfiltration, commit messages, and HTTP headers. Dead code from `arcticfox-zwtransport` now in production use.
- **Anti-analysis module**: Debugger (ptrace/TracerPid), VM (DMI/CPUID/systemd-detect-virt, configurable via `ALLOW_VM`), sandbox (RAM/home/uptime), timing anomaly. Env-var override: `NO_ANTI_ANALYSIS=1`.
- **Anti-forensics**: `/proc/pid/exe` spoofing, FD camouflage, timestamp tampering, systemd child lineage spoofing. All wired into agent startup.
- **Uncovered stack**: 4 novel techniques — LD_AUDIT interception, fanotify self-hiding, eBPF audit filtering, CRIU checkpoint/restore persistence. All wired into agent startup (best-effort).
- **Systemd generator persistence**: Stealthiest Linux persistence via `/etc/systemd/system-generators/` — units exist only in tmpfs, never on disk.
- **Systemd drop-in override**: Inject `ExecStartPost` into existing services (e.g., sshd.service) without creating new units.
- **Bot ID persistence**: Agent stores bot_id in temp directory across restarts.
- **Heartbeat ZW commands**: Agents receive encrypted commands via heartbeat response body (`ts` field). Session key delivered through dead-drop payloads (`hb.key`).
- **Upload/exfil commands**: New `upload` and `exfil` agent commands with ZW-encrypted data transfer.
- **ICMP heartbeat**: Alternative covert channel using ICMP timestamp (type 13/14) with ZW-encrypted payloads. Wired into agent main loop.
- **Log covert channel**: Inter-agent communication via shared system log files with ZW-encoded messages. Wired into agent main loop.
- **ZW in HTTP headers**: User-Agent and X-Cache-Breaker headers carry ZW-encoded bot ID and timing data invisibly.
- **ZW in commit messages**: Git commit messages can carry ZW-encoded data via `zw_commit_msg()`.
- **ZW in process arguments**: Watchdog passes config path as ZW-encoded suffix in `--name` argument. Hidden from `/proc/pid/cmdline`.
- **Per-session key rotation**: `set_key` command updates session key and marker sets atomically (keeps last 3).
- **Permakill/SerialKiller execution**: Wired into executor — `permakill <user> <pass>` and `serialkiller [RUN]` commands.
- **B64 command parser**: Legacy Python `pastebomb.py` command format (`<!-- B64:... -->`) compatibility in Rust agent.
- **Scanner enhancements**: Bogon/martian IP filtering, zmap stateless scanning, sharding, rate limiting.
- **Config at-rest protection**: All token fields ZW-encoded before writing to disk. Auto-decoded on load.
- **Daemon mode**: Double-fork + setsid + fd redirect for proper background execution.
- **Argnames shortened**: `--stealth-name` → `--name`, `--parent-pid` → `--ppid`. Repos removed from CLI args (config-only).
- **Crate descriptions de-branded**: All `Cargo.toml` descriptions replaced with innocuous text.
- **Dashboard API client**: All 21 endpoints wrapped with status code checking and error surfacing.
- **MCP server**: JSON-RPC validation (`jsonrpc == "2.0"`), `RustsploitMcpBridge` Drop impl for child process cleanup.

### Bug Fixes
- **Broken exponential backoff**: Agent backoff calculation mixed `Instant` (monotonic) with epoch timestamps. Fixed to use chrono timestamps consistently.
- **Fisher-Yates shuffle**: Range `(1..n).rev()` skipped index 0. Fixed to `(0..n).rev()`.
- **ZW inject last-line duplication**: `inject()` duplicated the last line when no heading found. Fixed.
- **io_uring mmap check**: Failure check only triggered if ALL three mmaps failed. Now validates each independently with proper cleanup + munmap on Drop.
- **save_bots path**: API server saved bots to hardcoded `bots.json` ignoring `--bots-file` CLI arg. Fixed.
- **GitHub auth prefix**: Deprecated `token` scheme → `Bearer`.
- **Bindshell key panic**: Added length validation before `copy_from_slice`.
- **Zero-nonce vulnerability**: Heartbeat response decryption used all-zero nonce. Fixed to derive from response SHA-256 hash.
- **Accept header overwrite**: Browser-mimic headers overwrote GitHub's required Accept header. Fixed by skipping Accept in mimic loop.
- **TOCTOU in save_bots**: Concurrent saves could corrupt bots.json. Fixed with atomic timestamp check.
- **Python padding bug**: `zwenc.py` used `// 3` instead of `* 4`, producing 1/12th intended ZW padding.
- **Crypto KDF**: Replaced non-standard iterative HMAC construction with ring HKDF.
- **Hex decode silent fail**: `secure_hash_eq` returned true for invalid hex. Fixed to reject malformed input.
- **Dashboard Accept header**: GitHub API Accept destroyed by browser-mimic loop — fixed with `continue`.
- **Anti-analysis false positives**: VM detection now skippable via `ALLOW_VM=1`. Sandbox thresholds reduced. Uptime 5min → 60s. Timing 5x → 20x.
- **`i64::MIN.abs()`**: Fixed with `wrapping_abs()`.
- **Nested tokio Runtime**: MCP server creating new Runtime inside async context — replaced with `Handle::current().block_on()`.

### Removed
- All Python scripts (`control.py`, `api.py`, `pastebomb.py`, `oogascan.py`, `zwenc.py`)
- `requirements.txt`, `pb_config.json`, `oogascan.json`
- `--repo` CLI argument (repos now config-file-only)
- Static ZW markers (replaced by session-derived markers)
- Hardcoded `ArcticFox-C3/4.0` user-agent (replaced by randomized pool)
- Duplicate `BLAND_COMMITS`, `random_commit_msg`, `random_user_agent()` from control and fetcher
- Dead code: `ScanTarget` enum, dead scanner methods, `ModuleRunRequest`, `BORDER_NONE`, color constants

## v3.1.0 (May 2026)

### Previous Changelog

*(Earlier versions retained from original project. See git history for details.)*
