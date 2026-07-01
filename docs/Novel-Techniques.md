# Novel Techniques — Not Yet Catalogued by MITRE or Human Threat Intel

Techniques discovered in ArcticFox development that have no MITRE ATT&CK
mapping because they are genuinely novel. This document serves as a
blueprint for future ATT&CK submissions.

---

## Currently Implemented & Novel

### NOVEL-001: Zero-Width Unicode Steganography for C2
**→ NOW MAPPED: MITRE T1027.018 (Invisible Unicode) — added April 2026**

**Status:** Implemented in `zwcodec.rs`, `zwtransport`.
**MITRE coverage:** T1027.018 covers general invisible Unicode abuse.
The SPECIFIC application (GitHub README dead-drop C2) is not separately
catalogued but the underlying technique IS mapped.

**Detection strategies MITRE documents (and how we bypass them):**
| MITRE Analytic | What it detects | Our bypass |
|---|---|---|
| AN2063 | Execution of visually benign scripts with runtime decoding | We embed in READMEs, not executables — no script execution event |
| AN2064 | High concentration of invisible Unicode + decode behavior | Our ZW payload is appended to real markdown — low Unicode density, high printable ratio |
| AN2065 | Invisible Unicode reconstructed at runtime via AppleScript/JS/shell | We decode in pure Rust in-memory — no scripting engine involved |

**Verdict:** T1027.018 is the correct mapping. Our evasion against its
detection strategies is effective because we don't trigger any of the
three documented analytics.

---

### NOVEL-002: AEAD-Encrypt-then-ZW-Encode Pipeline

**Status:** Implemented in `crypto.rs`, `zwtransport`. No MITRE mapping.

**What it does:** ChaCha20-Poly1305 encrypts plaintext, producing
ciphertext||tag. This binary blob is then ZW-encoded (base-4 Unicode).
The result is an encrypted payload that looks like whitespace.

**Why no MITRE mapping:** T1027.013 (Encrypted/Encoded File) covers
separate encryption OR encoding. The chained encrypt-then-encode pipeline
producing invisible encrypted text is novel. No attacker has been observed
combining AEAD with Unicode steganography for C2.

---

### NOVEL-003: SO_REUSEPORT Bind Shell on Port 53 Coexisting with DNS

**Status:** Implemented in `bindshell`. Zero MITRE coverage.

**What it does:** Opens UDP port 53 with SO_REUSEPORT, allowing the bind
shell to listen on the same port as the real DNS server. When a packet
arrives, the kernel delivers it to both sockets. The real DNS server
processes legitimate queries; our shell processes ZW-marked packets.

**Why no MITRE mapping:** T1571 (Non-Standard Port) covers unusual ports.
T1095 (Non-Application Layer Protocol) covers non-HTTP C2. Neither covers
port-sharing with legitimate services via kernel-level socket options.

**Detection gap:** NetFlow shows DNS traffic to port 53 — which IS what
DNS looks like. Deep packet inspection sees mixed legitimate DNS + our
traffic on the same port. No detection rule exists for "some packets on
port 53 are not actually DNS."

---

### NOVEL-004: Watchdog Respawn with Rotating Process Names

**Status:** Implemented in `stealth.rs`. Partial MITRE (T1055 process injection, T1036 masquerading). The ROTATION aspect = novel.

**What it does:** A watchdog process monitors the implant PID. On death,
it respawns the implant under a DIFFERENT process name from a pool of 29
legitimate service names. Each respawn changes the name.

**Why rotation is novel:** T1036.005 (Match Legitimate Name) covers static
masquerading. No technique covers dynamic name rotation on respawn. This
breaks PID-to-name correlation that EDRs use for kill-chain analysis.

---

### NOVEL-005: SerialKiller — Anti-Competitor Malware Sweep

**Status:** Implemented in `fbi.rs`. No MITRE mapping.

**What it does:** Identifies and terminates 55 known malware/botnet
processes. This is NOT defense impairment (T1562.001) — it's offensive
counter-intelligence. The implant eliminates competing malware to monopolize
the compromised host.

**Why no MITRE mapping:** MITRE's Impact tactic (TA0040) covers Service Stop
(T1489) but that's for disrupting legitimate services. No technique covers
"terminate competitor malware to secure exclusive access." This is a
botnet-on-botnet warfare technique.

---

### NOVEL-006: ZW-Encoded Heartbeat via Google Open Redirect

**Status:** Implemented in `zw_heartbeat.rs`. Partial MITRE (T1001.003).

**What it does:** Encodes bot heartbeat data in ZW Unicode, then embeds it
in a Google open redirect URL: `google.com/url?q=<ZW_DATA>`. The ZW chars
are invisible in the URL bar. The C2 server monitors redirect logs for
these queries.

**Why novel:** T1001.003 (Protocol Impersonation) covers general traffic
mimicry but the specific combination of ZW steganography + open redirect
as heartbeat relay is novel. Google's redirect service becomes an
unwitting C2 relay.

---

## Planned — Not Yet Implemented, Not on MITRE

### NOVEL-007: LD_AUDIT System-Wide Library Load Interception

**Status:** Planned. Zero known public use for malware.

**What it does:** Sets `LD_AUDIT` environment variable (or `/etc/ld.so.preload`
audit variant) to load a custom shared object that receives callbacks for
EVERY shared library load event on the system. The auditor can inspect and
modify the loading process. This is a glibc debugging feature — almost never
monitored because almost no legitimate software uses it.

**Why undetectable:** No security product monitors `LD_AUDIT`. It's an
obscure glibc feature intended for performance profiling. The audit library
runs in the linker's context before ANY code in the target process.

**MITRE gap:** No technique for dynamic linker auditing abuse.

---

### NOVEL-008: fanotify Self-Hiding (Filesystem Event Filtering)

**Status:** Planned. Zero known public use for malware.

**What it does:** Registers a `fanotify` listener with `FAN_MARK_IGNORED_MASK`
that intercepts filesystem events for our implant files BEFORE they reach
auditd, Splunk, or EDR filesystem monitors. The kernel delivers events to
our listener first, we drop events related to our files, and the monitoring
tools never see them.

**Why undetectable:** fanotify is a legitimate API for antivirus scanning.
Registering as a fanotify listener is expected behavior. The kernel doesn't
distinguish between "AV scanner filtering events" and "malware filtering events."

**MITRE gap:** No technique for filesystem event interception/filtering.

---

### NOVEL-009: systemd Generator Runtime Unit Injection

**Status:** Planned. Zero known public use for malware.

**What it does:** Places a malicious systemd generator in
`/etc/systemd/system-generators/`. Generators run at boot BEFORE any services
start. The generator creates transient units that exist only in systemd's
runtime state — they never touch disk, so `ls /etc/systemd/system/` shows
nothing suspicious.

**Why undetectable:** Generators produce units in `/run/systemd/generator/`
which is tmpfs (in-memory). These units don't persist across reboots but
are recreated by the generator each boot. Integrity checkers that scan
`/etc/systemd/system/` find nothing.

**MITRE gap:** T1543 (Systemd Service) covers static units. No technique
for dynamic generator-based unit creation.

---

### NOVEL-010: eBPF Syscall Audit Filtering

**Status:** Planned. Extremely novel — requires kernel 5.x+.

**What it does:** Loads a small eBPF program into the kernel that attaches
to the `audit_filter` hook. The program inspects syscall audit events and
drops any that match our PID/TID, effectively making our process invisible
to auditd, Sysmon for Linux, and any tool using the audit subsystem.

**Why undetectable:** The eBPF program runs in kernel context. Userspace
tools cannot see it without `bpftool`. Even then, it appears as a legitimate
tracing program. The audit subsystem sees "no events" for our process, which
is indistinguishable from "process didn't make auditable syscalls."

**MITRE gap:** No technique for kernel-level audit filtering via eBPF.

---

### NOVEL-011: CRIU Checkpoint/Restore Process Resurrection

**Status:** Planned. Single known APT use (Sandworm, 2024).

**What it does:** Instead of traditional persistence (cron entries, systemd
units, init scripts), the implant uses CRIU (Checkpoint/Restore In Userspace)
to checkpoint its running state. The checkpoint is stored at an obscure path.
A timerfd-based trigger restores the checkpoint — the process reappears with
the same PID namespace, memory layout, file descriptors, and socket state
as when it was checkpointed.

**Why nearly undetectable:** The restored process looks like it never died.
There's no `execve` event (the process materializes from a checkpoint).
There's no cron entry, no systemd unit, no init script. The only artifact
is the checkpoint file, which is a binary blob with no magic bytes.

**MITRE gap:** No technique for CRIU-based persistence.

---

## Summary Table

| ID | Technique | Status | MITRE Coverage |
|---|---|---|---|
| NOVEL-001 | ZW Unicode Steganography C2 | ✓ Implemented | None |
| NOVEL-002 | AEAD→ZW Pipeline | ✓ Implemented | None |
| NOVEL-003 | SO_REUSEPORT DNS Coexistence | ✓ Implemented | None |
| NOVEL-004 | Rotating Process Name Respawn | ✓ Implemented | Partial |
| NOVEL-005 | Anti-Competitor Malware Sweep | ✓ Implemented | None |
| NOVEL-006 | ZW Google Redirect Heartbeat | ✓ Implemented | Partial |
| NOVEL-007 | LD_AUDIT Interception | ○ Planned | None |
| NOVEL-008 | fanotify Self-Hiding | ○ Planned | None |
| NOVEL-009 | systemd Generator Injection | ○ Planned | None |
| NOVEL-010 | eBPF Audit Filtering | ○ Planned | None |
| NOVEL-011 | CRIU Process Resurrection | ○ Planned | None |
