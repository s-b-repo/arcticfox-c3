//! Stateless SYN Scanning — Raw Socket TCP SYN Scan
//!
//! Sends TCP SYN packets via raw sockets and listens for SYN-ACK
//! responses via recvfrom. 100-1000x faster than full TCP connect.
//! Requires CAP_NET_RAW or root on Linux.

use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::{Duration, Instant};
use tracing::{debug, info, warn};

#[derive(Debug, Clone)]
pub struct SynResult {
    pub ip: u32,
    pub port: u16,
    pub ttl: u8,
    pub window_size: u16,
}

pub struct RateLimiter {
    rate: u32,
    tokens: f64,
    max_tokens: f64,
    last_refill: Instant,
    batch_size: u32,
}

impl RateLimiter {
    pub fn new(rate: u32) -> Self {
        let burst = rate.max(256);
        RateLimiter {
            rate,
            tokens: burst as f64,
            max_tokens: burst as f64,
            last_refill: Instant::now(),
            batch_size: (rate / 100).max(1),
        }
    }

    pub fn wait(&mut self, count: u32) {
        loop {
            let elapsed = self.last_refill.elapsed().as_secs_f64();
            self.tokens = (self.tokens + elapsed * self.rate as f64).min(self.max_tokens);
            self.last_refill = Instant::now();
            if self.tokens >= count as f64 {
                self.tokens -= count as f64;
                return;
            }
            let wait = Duration::from_secs_f64(
                (count as f64 - self.tokens) / self.rate as f64
            );
            std::thread::sleep(wait);
        }
    }
}

/// Build and send TCP SYN packets, receive SYN-ACKs via raw socket.
pub struct SynScanner {
    raw_fd: i32,
    src_ip: u32,
    src_port: u16,
    rate: RateLimiter,
}

impl SynScanner {
    /// Create a new SYN scanner. Requires root/CAP_NET_RAW.
    #[cfg(target_os = "linux")]
    pub fn new(src_ip: Ipv4Addr, rate: u32) -> std::io::Result<Self> {
        let raw_fd = unsafe {
            let fd = libc::socket(libc::AF_INET, libc::SOCK_RAW | libc::SOCK_NONBLOCK, libc::IPPROTO_TCP);
            if fd < 0 {
                return Err(std::io::Error::last_os_error());
            }
            // Tell kernel we'll build our own IP header
            let on: libc::c_int = 1;
            libc::setsockopt(
                fd,
                libc::IPPROTO_IP,
                libc::IP_HDRINCL,
                &on as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as u32,
            );
            fd
        };

        Ok(SynScanner {
            raw_fd,
            src_ip: u32::from(src_ip),
            src_port: (rand::random::<u16>() % 50000 + 1024),
            rate: RateLimiter::new(rate),
        })
    }

    #[cfg(not(target_os = "linux"))]
    pub fn new(_src_ip: Ipv4Addr, _rate: u32) -> std::io::Result<Self> {
        Err(std::io::Error::new(std::io::ErrorKind::Unsupported, "SYN scan only supported on Linux"))
    }

    /// Send a SYN packet to a target IP:port.
    pub fn send_syn(&mut self, dst_ip: u32, dst_port: u16) -> std::io::Result<()> {
        self.rate.wait(self.rate.batch_size);
        let packet = build_syn_packet(self.src_ip, self.src_port, dst_ip, dst_port);
        let addr = libc::sockaddr_in {
            sin_family: libc::AF_INET as u16,
            sin_port: 0u16.to_be(),
            sin_addr: libc::in_addr { s_addr: dst_ip.to_be() },
            sin_zero: [0u8; 8],
        };
        let ret = unsafe {
            libc::sendto(
                self.raw_fd,
                packet.as_ptr() as *const libc::c_void,
                packet.len(),
                0,
                &addr as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as u32,
            )
        };
        if ret < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::WouldBlock { return Ok(()); }
            return Err(e);
        }
        Ok(())
    }

    /// Receive SYN-ACK responses (non-blocking, drains up to `max` packets).
    pub fn recv_syn_acks(&self, max: usize) -> Vec<SynResult> {
        let mut results = Vec::new();
        let mut buf = [0u8; 4096];
        for _ in 0..max {
            let n = unsafe {
                libc::recvfrom(
                    self.raw_fd,
                    buf.as_mut_ptr() as *mut libc::c_void,
                    buf.len(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            };
            if n <= 0 { break; }
            if n >= 40 {
                if let Some(r) = parse_syn_ack(&buf[..n as usize]) {
                    results.push(r);
                }
            }
        }
        results
    }
}

impl Drop for SynScanner {
    fn drop(&mut self) {
        unsafe { libc::close(self.raw_fd); }
    }
}

fn build_syn_packet(src_ip: u32, src_port: u16, dst_ip: u32, dst_port: u16) -> Vec<u8> {
    let tcp_header_len = 20;
    let ip_header_len = 20;
    let total_len = (ip_header_len + tcp_header_len) as u16;
    let ip_id: u16 = rand::random();
    let tcp_seq: u32 = rand::random();
    let window: u16 = 65535;

    let mut packet = vec![0u8; total_len as usize];

    // IP Header
    packet[0] = 0x45;
    packet[1] = 0x00;
    packet[2..4].copy_from_slice(&total_len.to_be_bytes());
    packet[4..6].copy_from_slice(&ip_id.to_be_bytes());
    packet[8] = 64;
    packet[9] = 6; // TCP
    packet[12..16].copy_from_slice(&src_ip.to_be_bytes());
    packet[16..20].copy_from_slice(&dst_ip.to_be_bytes());
    let ip_csum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&ip_csum.to_be_bytes());

    // TCP Header
    let tcp_off = 20;
    packet[tcp_off..tcp_off + 2].copy_from_slice(&src_port.to_be_bytes());
    packet[tcp_off + 2..tcp_off + 4].copy_from_slice(&dst_port.to_be_bytes());
    packet[tcp_off + 4..tcp_off + 8].copy_from_slice(&tcp_seq.to_be_bytes());
    packet[tcp_off + 12] = 0x50; // IHL=5
    packet[tcp_off + 13] = 0x02; // SYN
    packet[tcp_off + 14..tcp_off + 16].copy_from_slice(&window.to_be_bytes());
    let tcp_csum = tcp_checksum(&packet[tcp_off..tcp_off + tcp_header_len], src_ip, dst_ip);
    packet[tcp_off + 16..tcp_off + 18].copy_from_slice(&tcp_csum.to_be_bytes());

    packet
}

fn parse_syn_ack(packet: &[u8]) -> Option<SynResult> {
    if packet.len() < 40 { return None; }
    let ihl = (packet[0] & 0x0F) as usize;
    if ihl < 5 { return None; }
    let ip_header_len = ihl * 4;
    if packet.len() < ip_header_len + 20 { return None; }
    if packet[9] != 6 { return None; }

    let src_ip = u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]);
    let ttl = packet[8];
    let tcp = &packet[ip_header_len..];
    let src_port = u16::from_be_bytes([tcp[0], tcp[1]]);
    let flags = tcp[13];
    if (flags & 0x12) != 0x12 { return None; }
    let window = u16::from_be_bytes([tcp[14], tcp[15]]);
    Some(SynResult { ip: src_ip, port: src_port, ttl, window_size: window })
}

fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    for chunk in data.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

fn tcp_checksum(tcp_segment: &[u8], src_ip: u32, dst_ip: u32) -> u16 {
    let mut sum: u32 = 0;
    sum += (src_ip >> 16) as u32;
    sum += (src_ip & 0xFFFF) as u32;
    sum += (dst_ip >> 16) as u32;
    sum += (dst_ip & 0xFFFF) as u32;
    sum += 6u32;
    sum += tcp_segment.len() as u32;
    for chunk in tcp_segment.chunks(2) {
        let word = if chunk.len() == 2 {
            u16::from_be_bytes([chunk[0], chunk[1]]) as u32
        } else {
            (chunk[0] as u32) << 8
        };
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 { sum = (sum & 0xFFFF) + (sum >> 16); }
    !(sum as u16)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn syn_packet_valid() {
        let pkt = build_syn_packet(0x0A000001, 12345, 0x08080808, 80);
        assert!(pkt.len() >= 40);
        assert_eq!(pkt[0], 0x45);
        assert_eq!(pkt[9], 6);
        assert_eq!(pkt[20 + 13], 0x02);
    }

    #[test]
    fn syn_ack_parses() {
        let mut pkt = vec![0u8; 40];
        pkt[0] = 0x45; pkt[8] = 55; pkt[9] = 6;
        pkt[12..16].copy_from_slice(&0x7F000001u32.to_be_bytes());
        pkt[20..22].copy_from_slice(&7443u16.to_be_bytes());
        pkt[33] = 0x12;
        pkt[34..36].copy_from_slice(&65535u16.to_be_bytes());
        let r = parse_syn_ack(&pkt).unwrap();
        assert_eq!(r.ip, 0x7F000001);
        assert_eq!(r.port, 7443);
        assert_eq!(r.ttl, 55);
    }
}
