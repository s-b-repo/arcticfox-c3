ArcticFox C3 started as a Python script that hid commands in invisible Unicode inside GitHub README files. The idea was clever but the code had problems — errors were swallowed, threading was messy, and it couldn't survive a reboot.

So I rewrote the entire thing in Rust. Every line. Ten crates. Async I/O throughout. Ring crypto for everything — no OpenSSL, no native-tls. Constant-time token comparison so timing attacks can't leak credentials. Zero unwrap() calls in production code. If something can fail, it returns a Result with a meaningful error.

The implant hides in plain sight. When it runs, your process list shows sshd, httpd, cron, or nginx — twenty-nine common service names rotated on every respawn. A tiny watchdog watches the main implant. If someone kills it, the watchdog brings it back under a completely different name. The PID file goes to /var/run/sshd.pid. Everything looks like it belongs.

The C2 channel is absurdly stealthy. Commands are encrypted with ChaCha20-Poly1305, then encoded into invisible zero-width Unicode characters, then injected into a GitHub README after the first heading. When you look at the README on GitHub, you see normal text. The commands are there — you just can't see them. The agent polls multiple repos in random order, so even if GitHub takes one down, the others keep working.

Then I added bind shells that talk the same ZW-encrypted protocol. TCP works. UDP port 53 works — it shares the port with the real DNS server using SO_REUSEPORT, so the traffic looks like DNS. ICMP works too — only packets with ZW markers get processed, regular pings pass through normally.

Now here's where it gets interesting. I mapped every technique against the MITRE ATT&CK framework and documented exactly how each one is detected, then built bypasses for all of them.

MITRE added T1027.018 — Invisible Unicode — in April 2026. That's our ZW steganography. They documented three detection strategies: look for scripts with high Unicode density that trigger runtime decoding, look for invisible characters followed by base64 decode and eval, and look for Unicode reconstructed via AppleScript or JavaScript. None of them work against us. We embed ZW in real markdown, not scripts. The Unicode density is low because the README has hundreds of visible characters. We decode in pure Rust in-memory — no JavaScript, no AppleScript, no eval.

For the process name masquerading, detection looks for duplicate process names where the parent-child relationship doesn't match systemd's normal spawning behavior. Our bypass: the watchdog spawns the implant via fork, not systemd, and rotates names so the correlation window is too short for EDR to build a kill chain.

For domain fronting, detection looks at TLS SNI mismatches with the HTTP Host header. Our bypass: we use Cloudflare and Fastly edge domains that serve millions of legitimate users. One more ZW-encoded heartbeat looks identical to a million real requests.

For the systemd timer persistence, detection scans /etc/systemd/system/ for units not owned by any package. Our bypass: we use systemd generators instead. Generators run at boot and create units in /run/systemd/generator/ — that's tmpfs, it never touches disk. Integrity checkers skip tmpfs. The units appear with names like systemd-hostnamed and systemd-tmpfiles-clean. They look like they've always been there.

The most exciting part is what ISN'T on MITRE at all. Four techniques we discovered that have zero coverage in any threat intelligence:

First, LD_AUDIT interception. glibc has a debugging interface that receives callbacks for every shared library loaded on the system. Set LD_AUDIT to a malicious .so and you get a hook that fires before any code runs in any process. It's separate from LD_PRELOAD — different mechanism, different detection surface. No security product monitors it because almost nothing legitimate uses it.

Second, fanotify self-hiding. fanotify is the Linux kernel API designed for antivirus scanning. It delivers filesystem events to registered listeners before the operation completes. By registering as a listener with FAN_MARK_IGNORED_MASK, our implant intercepts events for its own files and drops them before auditd or Splunk ever sees them. The kernel doesn't distinguish between AV filtering events and malware filtering events.

Third, eBPF audit suppression. Load a tiny BPF program into the kernel that checks the PID on every audit event. If the PID matches ours, return zero — drop the event. The audit system sees nothing. The BPF program runs in kernel context, invisible to userspace tools. Even bpftool shows it as a legitimate tracing program.

Fourth, CRIU process resurrection. CRIU checkpoints a running process to disk and restores it later. The restored process materializes with the same memory, file descriptors, and sockets — but no execve event in the audit log. No parent PID. It just appears. Combined with a timerfd trigger instead of cron, there's nothing to find.

The framework also talks to Rustsploit — the exploitation framework. It can fire implants as post-exploitation payloads, share credential stores between frameworks, and delegate module execution. The bridge supports PQ-encrypted WebSocket transport using X25519 and ML-KEM-768, same as Rustsploit's native API.

For AI control, there's an MCP server with fifteen tools and a four-tier safety system. At Tier 0, the AI can only read recon data. At Tier 3, it can generate implants and launch network scans. Shell commands require explicit confirmation — the AI has to say "yes, I really want to run this command on all agents." The GTFOBins catalog has forty-five living-off-the-land techniques, and the AI can search and generate commands from it without ever needing to know the binary names.

The whole thing is ten crates, seventy-five tests, zero build errors, Rust 2024 edition. It runs on Linux with io_uring kernel-bypass I/O, falls back gracefully to tokio on other platforms. The implant can execute entirely from memory using memfd_create — the binary never touches disk.

What we built isn't just a C2 framework. It's a catalog of detection bypasses with working code for each one, a set of genuinely novel techniques that aren't in any threat database, and a bridge between exploitation and command-and-control that runs entirely over invisible text in public GitHub repos.
