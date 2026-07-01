# MITRE ATT&CK Mapping & Evasion

ArcticFox C3 is mapped to the MITRE ATT&CK framework (Enterprise + Linux matrix).
Each technique lists the specific evasion implemented.

## Command & Control (TA0011)

| MITRE ID | Technique | ArcticFox Implementation | Evasion |
|---|---|---|---|
| T1090.004 | Proxy: Domain Fronting | `DomainFront` routes through CDN edge (Cloudflare, Fastly, Akamai) | TLS SNI ≠ HTTP Host — network monitors see benign CDN traffic |
| T1102.002 | Web Service: Bidirectional | GitHub/GitLab README dead-drops | No listening ports. Traffic is HTTPS to github.com — indistinguishable from developer activity |
| T1001.003 | Data Obfuscation: Protocol Impersonation | ZW heartbeats via open redirect to google.com/url?q= | Appears as legitimate Google redirect traffic |
| T1573.002 | Encrypted Channel: Asymmetric | ChaCha20-Poly1305 AEAD then ZW-encode | Double-encrypted: ciphertext invisible in Unicode |
| T1008 | Fallback Channels | Multi-repo randomized polling with auto-failover | If one repo dies, agent silently switches to next — no beacon gap |
| T1095 | Non-Application Layer Protocol | ICMP bind shell, UDP/53 bind shell | ICMP echo reply steganography; DNS-port traffic blends with real DNS |
| T1571 | Non-Standard Port | Bind shell on 53/udp (DNS) with SO_REUSEPORT | Coexists with real DNS server — port already open |

## Execution (TA0002)

| MITRE ID | Technique | ArcticFox Implementation | Evasion |
|---|---|---|---|
| T1059.004 | Command & Scripting: Unix Shell | `executor.rs` runs commands via `sh -c` | Uses LOLBins (GTFOBins) to avoid spawning unusual processes |
| T1203 | Exploitation for Client Execution | Rustsploit bridge: `deploy_via_exploit()` | Legitimate exploit chain → implant dropped as post-exploitation payload |
| T1106 | Native API | `memfd_create` + `fexecve` for fileless execution | Binary never touches disk — invisible to file-based AV |

## Persistence (TA0003)

| MITRE ID | Technique | ArcticFox Implementation | Evasion |
|---|---|---|---|
| T1053.003 | Scheduled Task: Cron | Camouflaged cron entry `# systemd maintenance` | Looks like system maintenance, not malware |
| T1547.001 | Boot/Logon Autostart: .desktop | `~/.config/autostart/sshd.desktop` with Hidden=true | Masquerades as sshd autostart entry |
| T1543.002 | Systemd Service | Systemd timer + service disguised as `systemd-helper` | Uses common naming, timer-based activation |
| T1546.004 | Event Triggered Execution: .bashrc | LD_PRELOAD shim injected via `/etc/ld.so.preload` | Loads before any process — undetectable by process enumeration |
| T1546.008 | Event Triggered Execution: PAM | pam.d backdoor via `pam_exec.so` | Executes on every SSH login — looks like PAM module, not malware |
| T1037.004 | Boot Init Scripts: init.d | `/etc/init.d/helper` script with LSB header | Masquerades as legacy init script |
| T1546.016 | Event Triggered Execution: Installer Scripts | `apt.conf.d` hook triggers on package install | Runs only when admin installs packages — extremely rare activation |

## Defense Evasion (TA0005)

| MITRE ID | Technique | ArcticFox Implementation | Evasion |
|---|---|---|---|
| T1027 | Obfuscated Files | ZW Unicode steganography in README.md | Payload invisible in rendered markdown — only detectable in raw source |
| T1027.013 | Encrypted/Encoded File | AEAD encrypt before ZW encode | Double-encrypted — ciphertext structure hidden in ZW encoding |
| T1036.005 | Masquerading: Match Legitimate Name | 29 common process names (sshd, httpd, cron, etc.) | `ps aux` shows `sshd` — indistinguishable from real sshd at a glance |
| T1055 | Process Injection | Watchdog respawn + `/proc/self/exe` unlink | Binary deleted from disk, runs from inode; watchdog re-spawns under new name |
| T1070.004 | Indicator Removal: File Deletion | Self-unlink after launch | Binary gone from disk within milliseconds of execution |
| T1070.006 | Indicator Removal: Timestomp | PID files in `/var/run/` match system file timestamps | Blends with legit PID files |
| T1140 | Deobfuscate/Decode | ZW decode pipeline in agent | Decoding happens in memory only — no temp files |
| T1202 | Indirect Command Execution | All shell commands executed via GTFOBins | `find -exec`, `awk system()`, `python -c` — no `/bin/sh -c` in process tree |
| T1218 | System Binary Proxy Execution | LOLBin catalog (45+ techniques) | Uses legitimate system binaries for all operations |
| T1222.002 | File Permissions Modification: Linux | `chattr +i` on implant binary | Makes file immutable — even root can't delete without `chattr -i` |
| T1562.001 | Impair Defenses: Disable Tools | SerialKiller: 55 malware process names killed | Eliminates competing malware (and sometimes EDR agents) |
| T1564.001 | Hide Artifacts: Hidden Files | Dotfile prefix for implant path (`.sshd`) | `ls` doesn't show dotfiles by default |
| T1574.006 | Hijack Execution Flow: LD_PRELOAD | `/etc/ld.so.preload` injection | Loaded by ld.so before ANY binary — universal hook, undetectable by process enumeration |
| T1620 | Reflective Code Loading | `memfd_create` + in-memory execution | No file on disk, no `mmap` of file-backed region — confirmed T1620 in v19 |
| T1546.016 | Event Triggered Execution: Installer Packages | `apt.conf.d` hook triggers on package install | Runs only when admin installs packages — extremely rare activation, confirmed T1546.016 in v19 |
## Discovery (TA0007)

| MITRE ID | Technique | ArcticFox Implementation |
|---|---|---|
| T1046 | Network Service Discovery | Async telnet scanner with CIDR/random modes |
| T1082 | System Information Discovery | `shell uname -a`, `shell whoami` via C2 |
| T1016 | System Network Configuration Discovery | `shell ip addr`, `shell netstat` via C2 |
| T1033 | System Owner/User Discovery | `shell whoami`, `shell id` via C2 |
| T1083 | File and Directory Discovery | `shell ls -la /`, `shell find / -perm -4000` via C2 |

## Credential Access (TA0006)

| MITRE ID | Technique | ArcticFox Implementation |
|---|---|---|
| T1110.001 | Brute Force: Password Guessing | Telnet brute-forcer with 35 IoT credentials |
| T1110.003 | Brute Force: Password Spraying | Rustsploit credential modules via bridge |
| T1552.001 | Unsecured Credentials: Credentials in Files | Reads `/etc/shadow`, `~/.ssh/id_rsa` via shell commands |
| T1003.008 | OS Credential Dumping: /etc/passwd | `shell cat /etc/passwd` via C2 |

## Lateral Movement (TA0008)

| MITRE ID | Technique | ArcticFox Implementation |
|---|---|---|
| T1021.001 | Remote Desktop Protocol | Rustsploit RDP modules via bridge |
| T1021.004 | Remote Services: SSH | Self-propagation via captured SSH credentials |
| T1091 | Replication Through Removable Media | Not implemented (IoT-focused, no USB) |
| T1210 | Exploitation of Remote Services | Rustsploit exploit modules via bridge |

## Collection (TA0009)

| MITRE ID | Technique | ArcticFox Implementation |
|---|---|---|
| T1005 | Data from Local System | `shell cat /etc/passwd`, file read commands |
| T1119 | Automated Collection | SerialKiller auto-gathers competitor bot IPs |

## Exfiltration (TA0010)

| MITRE ID | Technique | ArcticFox Implementation |
|---|---|---|
| T1041 | Exfiltration Over C2 Channel | All output returned via ZW-encoded C2 channel |
| T1048.003 | Exfiltration Over Unencrypted Non-C2 Protocol | Heartbeat via open redirect (data in URL params) |

## Impact (TA0040)

| MITRE ID | Technique | ArcticFox Implementation |
|---|---|---|
| T1485 | Data Destruction | Permakill: credential lockdown, blocks device access |
| T1489 | Service Stop | SerialKiller: kills processes, closes ports, clears cron |
| T1498 | Network Denial of Service | `dos` command: ping flood (max 300s) |

---

## Detection Evasion Summary

**EDR (CrowdStrike, SentinelOne, Cortex XDR):**
- Process name camouflage defeats process-tree-based detection
- `memfd_create` fileless execution defeats file-scan hooks
- LOLBin usage avoids spawning unusual binaries
- Watchdog respawn with name rotation defeats kill-chain correlation

**AV (ClamAV, Windows Defender on Linux, Sophos):**
- AEAD-encrypted payloads have no static signatures
- ZW encoding hides ciphertext structure
- Binary self-unlinks before AV scan can complete
- `chattr +i` prevents AV from quarantining

**Network Detection (Zeek, Suricata, Snort):**
- GitHub API traffic looks like developer activity
- Domain fronting hides C2 backend behind CDN TLS SNI
- ICMP/DNS-port traffic blends with legitimate protocols
- JARM/JA3 randomization prevents TLS fingerprinting
- Open redirect heartbeats use google.com as referrer

**SIEM / Log Analysis (Splunk, ELK):**
- Cron entries use `# systemd maintenance` comments
- Process names match expected system services
- PID files in standard locations with standard names
- No unusual network connections (everything goes through HTTPS to github.com)

**Forensics:**
- `memfd_create` leaves no disk artifacts
- Watchdog respawn breaks timeline analysis (new PID, new name)
- ZW payloads invisible in text dumps without byte-level inspection
- `chattr +i` prevents imaging tools from modifying implant binaries
