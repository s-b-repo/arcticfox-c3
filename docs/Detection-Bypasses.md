# Detection Bypasses — Per MITRE Technique

Every technique ArcticFox uses is detectable. Here's HOW each is detected
and HOW we bypass that specific detection. Implemented bypasses are marked ✓.
Planned bypasses marked ○.

---

## T1102.002 — GitHub README Dead-Drop C2

**How detected:**
- GitHub API audit logs show repeated GETs to `/repos/{owner}/{repo}/contents/README.md`
- Raw.githubusercontent.com CDN logs show unusual fetch patterns
- Repository has zero stars/forks but frequent README commits
- User-Agent string fingerprinting across requests
- Timing analysis: fixed-interval polling creates detectable periodicity

**Bypass:**
- ✓ Randomized polling interval with jitter (±15s default)
- ✓ Cache-busting query params on every fetch (`?nocache=XXXXX&t=TTTTTT`)
- ✓ Rotating User-Agent strings (Chrome/Firefox/Safari/Edge profiles)
- ✓ Using `api.github.com` instead of `raw.githubusercontent.com` (blends with CI/CD traffic)
- ✓ Multiple fallback repos (if one is flagged, others still work)
- ○ GitHub App installation auth (OAuth token = looks like legit integration)
- ○ Rate-limit-aware polling (respect X-RateLimit-Remaining headers)

---

## T1090.004 — Domain Fronting

**How detected:**
- TLS SNI mismatch with HTTP Host header (advanced TLS inspection)
- CDN edge logs show unusual backend routing
- ESNI/ECH adoption (Encrypted Client Hello hides SNI, but also makes fronting harder)
- Certificate transparency logs reveal both front and backend domains

**Bypass:**
- ✓ Domain front list uses major CDNs (Cloudflare, Fastly, Akamai) — millions of legit users share these
- ✓ HTTP Host matches expected backend pattern (e.g., `api.example.com` looks normal)
- ✓ Traffic volume kept low (heartbeats only, not bulk exfil)
- ○ Use domains with valid TLS certs for BOTH front and backend (no SNI mismatch)
- ○ WebSocket-over-HTTPS so all traffic looks like a single long-lived connection

---

## T1036.005 — Process Name Camouflage

**How detected:**
- `ps aux | grep sshd` shows duplicate sshd processes
- Parent-child relationship: `bash → sshd` (real sshd is spawned by systemd, not bash)
- `/proc/<pid>/exe` symlink points to unexpected binary path
- `lsof -p <pid>` shows unusual file handles (not `/etc/ssh/sshd_config`)
- Systemd service monitoring: unexpected child of `sshd.service`

**Bypass:**
- ✓ Random service name rotation (29 names)
- ✓ Watchdog respawn under DIFFERENT name (breaks PID correlation)
- ✓ `/proc/self/exe` unlink (symlink target disappears)
- ✓ `prctl(PR_SET_NAME, "sshd")` — kernel-level process name change
- ○ Spoof `/proc/<pid>/exe` via `mount --bind` to point at real sshd binary
- ○ Fork from actual systemd process via `sd_pid_notify()` to appear as legitimate child
- ○ Match real sshd's open file descriptors (open `/etc/ssh/sshd_config` readonly)

---

## T1620 — Reflective Code Loading (memfd_create)

**How detected:**
- `memfd_create` syscall audit (auditd rule `-a always,exit -S memfd_create`)
- `/proc/<pid>/fd/N` pointing to anonymous inode (no backing file)
- `lsof` shows `memfd:` type file descriptors
- EDR hooks on `execveat()` with AT_EMPTY_PATH flag
- Memory region with RWX permissions (writable + executable = suspicious)

**Bypass:**
- ✓ Use empty/space name for memfd (name field appears blank in `ls -la /proc/pid/fd`)
- ✓ Execute via `/proc/self/fd/N` instead of `fexecve` (uses standard exec path)
- ○ Chaining: memfd_create → write → seal (F_SEAL_SEAL) → exec (immutable before exec)
- ○ Map as RX only (not RWX) by using separate writable+executable mappings
- ○ Write via `process_vm_writev` from a different process to avoid EDR inline hooks

---

## T1574.006 — LD_PRELOAD Shim

**How detected:**
- `/etc/ld.so.preload` file existence (integrity monitoring trips on new file)
- `LD_PRELOAD` environment variable in process tree
- Dynamic linker audit (`LD_AUDIT`) can log every library load
- `readelf -d /proc/<pid>/exe` shows unexpected NEEDED libraries
- EDR hooks detect `dlsym(RTLD_NEXT, ...)` pattern (classic LD_PRELOAD behavior)

**Bypass:**
- ✓ Shim compiled as `libsystem.so` (name matches common system library pattern)
- ✓ Only spawns implant once (atomic flag prevents spam)
- ✓ Forks before exec (child does exec, parent returns cleanly)
- ○ Use `DT_RUNPATH` injection instead of `ld.so.preload` (harder to audit)
- ○ Set `LD_AUDIT` to our own shim that filters audit events (hides ourselves)
- ○ Patch the GOT/PLT of a running process instead of using LD_PRELOAD

---

## T1543.002 — Systemd Service/Timer

**How detected:**
- `systemctl list-timers` shows unexpected timers
- `systemd-analyze security <unit>` scores the unit (our unit would score LOW)
- Unit files in `/etc/systemd/system/` not owned by any package (`dpkg -S`)
- Timer activation pattern: OnBootSec + OnUnitActiveSec + RandomizedDelaySec is classic malware
- `journalctl -u <unit>` shows execution logs

**Bypass:**
- ✓ Unit named `systemd-helper.service` (looks internal)
- ✓ `StandardOutput=null` + `StandardError=null` (no journal entries)
- ✓ `PrivateTmp=yes` (isolated /tmp — can't see our files from outside)
- ○ Use `systemctl edit --full <existing-service>` to inject ExecStartPost into a REAL service
- ○ Drop-in override: `/etc/systemd/system/sshd.service.d/override.conf` (inherits sshd's security profile)
- ○ Use `systemd-run --user` for user-scoped timers (don't show in `systemctl list-timers`)

---

## T1546.008 — PAM Backdoor

**How detected:**
- `pam_exec.so` in `/etc/pam.d/*` files (rarely used legitimately outside of 2FA modules)
- PAM module loading audit: `auditctl -w /etc/pam.d/ -p wa`
- `auth optional` line that doesn't match distribution default (integrity checkers like `debsums` flag it)
- SSH login delay (pam_exec blocks until child exits)

**Bypass:**
- ✓ Use `pam_exec.so expose_authtok` (captures password for credential harvesting)
- ✓ Binary path `/tmp/.sshd` looks like sshd's temp file
- ○ Replace `pam_unix.so` entirely with a patched version (no config line to find)
- ○ Use `pam_exec` with `quiet` flag to suppress PAM debug output
- ○ Trigger on `session` not `auth` (executes AFTER successful login, no delay for attacker)

---

## T1053.003 — Cron Persistence

**How detected:**
- `crontab -l` for all users (automated by EDR every N minutes)
- `/var/spool/cron/crontabs/` and `/etc/cron.*/` directory monitoring (inotify)
- Cron job that runs a binary in `/tmp/` or `/dev/shm/` (known-malicious paths)
- No `PATH=` or `SHELL=` declaration (malformed crontab)
- Job runs too frequently (every minute = suspicious)

**Bypass:**
- ✓ `# systemd maintenance` comment disguises purpose
- ✓ `*/30 * * * *` (every 30 min, not every minute — less suspicious)
- ✓ `> /dev/null 2>&1` suppresses output (no mail to root)
- ○ Write directly to `/var/spool/cron/crontabs/root` with `utmp` timestamp matching (bypasses crontab command audit)
- ○ Use `@reboot` instead of periodic (only runs once, harder to catch in snapshot)
- ○ Encode the cron entry in base64 and use `echo ... | base64 -d | crontab -` (evades string matching)

---

## T1218 — System Binary Proxy Execution (LOLBins)

**How detected:**
- Sysmon/Splunk rules for specific binary + argument patterns (e.g., `certutil -urlcache`)
- Command-line auditing: unusual arguments to common binaries
- Parent-child process anomalies (e.g., `java` spawning `certutil`)
- EDR behavioral: binary that never makes network connections suddenly does

**Bypass:**
- ✓ 45+ LOLBin catalog rotates techniques (not always the same binary)
- ✓ Arguments mimic legitimate usage (`curl -s -o /tmp/cache http://...` looks like normal curl)
- ✓ Shell commands go through GTFOBins indirection (`find -exec`, `awk system()`)
- ○ Use `busybox` as universal executor (hundreds of applets, impossible to block all)
- ○ LD_PRELOAD interposer that hooks `execve` and strips suspicious args before kernel sees them

---

## T1095/T1571 — Non-Standard Protocol C2 (ICMP/UDP-53)

**How detected:**
- ICMP packets with payload (normal ping payload is patterned: `abcdef...` or timestamp)
- DNS port 53 traffic that isn't DNS protocol (deep packet inspection)
- Unusual ICMP echo request rate or payload size
- netflow/sflow: UDP 53 to non-DNS-server IPs

**Bypass:**
- ✓ Only ZW-marked ICMP packets are processed (normal pings pass through)
- ✓ UDP 53 responses padded to 64+ bytes to look like DNS responses
- ✓ SO_REUSEPORT coexists with real DNS server (port already expected to have traffic)
- ○ Encode payload to look like DNS TXT record responses (base64-encoded "domain names")
- ○ Use ICMP timestamp requests (type 13) instead of echo (less monitored)

---

## T1001.003 — Open Redirect Heartbeat

**How detected:**
- Google/Bing/etc redirect URLs in HTTP proxy logs with unusually long query params
- Referrer chain analysis: `github.com → google.com/url?q=...` is unusual
- URL parameter contains non-ASCII characters (our ZW chars are Unicode)
- WAF/web proxy blocks URLs with control characters or excessive length

**Bypass:**
- ✓ ZW characters in query params are invisible (URL looks like `?q=` with nothing after)
- ✓ Domain fronting hides the actual C2 destination behind CDN TLS
- ✓ Random nonce prevents replay/replay-detection
- ○ Use URL fragment (#) instead of query (?) — fragments aren't sent to server, only client-side

---

## T1070.004 — File Deletion (Self-Unlink)

**How detected:**
- `unlink()` audit trail shows process deleting its own binary
- File disappeared from disk but process still running (forensic artifact)
- `/proc/<pid>/exe` shows `(deleted)` suffix
- Tripwire/AIDE file integrity monitoring triggers on file deletion

**Bypass:**
- ✓ `unlink_self()` via raw libc syscall (bypasses some userland hooks)
- ✓ Binary in `/tmp/.sshd` (tmp directory — files expected to disappear)
- ○ Use `rename()` to move to `/tmp/.<random>` then unlink (two-step — confuses atomic monitors)
- ○ Overwrite file with /dev/zero before unlinking (no forensic recovery possible)
