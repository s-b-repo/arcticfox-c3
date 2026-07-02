# Changelog

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
- **Anti-analysis module**: Debugger detection (ptrace/TracerPid), VM detection (DMI/CPUID/systemd-detect-virt), sandbox detection (RAM/home/uptime), timing anomaly detection. Configurable via env vars.
- **Anti-forensics**: `/proc/pid/exe` spoofing, FD camouflage, timestamp tampering, systemd child lineage spoofing. Wired into agent startup.
- **Bot ID persistence**: Agent stores bot_id in `/tmp/.sd-id` across restarts.
- **Heartbeat ZW commands**: Agents can now receive encrypted commands via heartbeat response body. Session key delivered through dead-drop payloads.
- **Upload/exfil commands**: New `upload` and `exfil` agent commands with ZW-encrypted data transfer.
- **ICMP heartbeat**: Alternative covert channel using ICMP timestamp (type 13/14) with ZW-encrypted payloads.
- **Log covert channel**: Inter-agent communication via shared system log files with ZW-encoded messages.
- **ZW in HTTP headers**: User-Agent and X-Cache-Breaker headers carry ZW-encoded data invisibly.
- **ZW in commit messages**: Git commit messages can carry ZW-encoded data via `zw_commit_msg()`.
- **ZW in process arguments**: Watchdog passes config path as ZW-encoded suffix in `--name` argument.
- **Per-session key rotation**: `set_key` command updates session key and marker sets atomically.
- **B64 command parser**: Legacy Python `pastebomb.py` command format compatibility in Rust agent.
- **Scanner enhancements**: Bogon/martian IP filtering, zmap stateless scanning, sharding, rate limiting.
- **Config at-rest protection**: All token fields ZW-encoded before writing to disk.
- **Daemon mode**: Double-fork + setsid + fd redirect for proper background execution.
- **Argnames shortened**: `--stealth-name` → `--name`, `--parent-pid` → `--ppid`. Repos removed from CLI args (config-only).
- **Crate descriptions de-branded**: All `Cargo.toml` descriptions replaced with innocuous text.

### Bug Fixes
- **Broken exponential backoff**: Agent backoff calculation mixed `Instant` (monotonic) with epoch timestamps, causing repos to never be rate-limited. Fixed to use chrono timestamps consistently.
- **Fisher-Yates shuffle**: Range `(1..n).rev()` skipped index 0. Fixed to `(0..n).rev()`.
- **ZW inject last-line duplication**: `inject()` duplicated the last line when no heading found. Fixed.
- **io_uring mmap check**: Failure check only triggered if ALL three mmaps failed. Now validates each independently with proper cleanup.
- **save_bots path**: API server saved bots to hardcoded `bots.json` ignoring `--bots-file` CLI arg. Fixed.
- **GitHub auth prefix**: Deprecated `token` scheme → `Bearer`.
- **Bindshell key panic**: Added length validation before `copy_from_slice`.
- **Zero-nonce vulnerability**: Heartbeat response decryption used all-zero nonce. Fixed to derive from response hash.
- **Accept header overwrite**: Browser-mimic headers overwrote GitHub's required Accept header. Fixed.
- **TOCTOU in save_bots**: Concurrent saves could corrupt bots.json. Fixed with atomic timestamp check.
- **Python padding bug**: `zwenc.py` used `// 3` instead of `* 4`, producing 1/12th intended ZW padding.
- **Crypto KDF**: Replaced non-standard iterative HMAC construction with ring HKDF.
- **Hex decode silent fail**: `secure_hash_eq` returned true for invalid hex. Fixed to reject malformed input.

### Removed
- All Python scripts (`control.py`, `api.py`, `pastebomb.py`, `oogascan.py`, `zwenc.py`)
- `requirements.txt`, `pb_config.json`, `oogascan.json`
- `--repo` CLI argument (repos now config-file-only)
- Static ZW markers (replaced by session-derived markers)
- Hardcoded `ArcticFox-C3/4.0` user-agent (replaced by randomized pool)
- Duplicate `BLAND_COMMITS` and `random_commit_msg` in control tool
- Duplicate `random_user_agent()` between fetcher and repo (consolidated)

## v3.1.0 (May 2026)

### Previous Changelog

*(Earlier versions retained from original project. See git history for details.)*
