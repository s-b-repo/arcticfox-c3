# c3 Dashboard — Usage Guide

The `c3` binary provides a unified terminal UI for managing the entire
asynchronous dead-drop framework. It connects to the REST API server and
provides 8 tabbed panels with keyboard-driven navigation.

## Launch

```bash
# Remote mode (connect to an existing API server)
c3 --connect http://c2-server:7443 --token <admin_token>

# With environment variable
C3_TOKEN=<admin_token> c3 --connect http://c2-server:7443

# Default (localhost, needs --token or C3_TOKEN)
c3 --token <admin_token>
```

## Tab Reference

### 1. Bots (F1)
Live table of connected agents showing bot ID, IP, last-seen time, heartbeat count,
and alive/offline status. Auto-refreshes on tab switch. Press `d` to delete a bot.

### 2. Repos (F2)
Dead-drop repository manager. Shows platform, owner/repo, branch, and health status.
- `a` — Add new repo (enter spec like `gh:owner/repo` then Enter)
- `d` — Delete selected repo
- `c` — Health-check all repos
- `Esc` — Cancel input mode

### 3. Commands (F3)
Command queue management with type-based color coding:
- **Red**: Shell commands (`cmd`, `shell`)
- **Yellow**: Downloads (`download`)
- **Magenta**: DoS (`dos`)
- **Cyan**: Popup messages (`popmsg`)
- **Green**: Agent control (`sleep`, `set_interval`, `set_key`, `add_repo`)

- `a` — Add command (type then Enter)
- `d` — Remove selected command
- `c` — Clear all commands
- `p` — Push payload to all alive repos
- `w` — Toggle ZW padding (1MB noise)

### 4. Attack Studio (F4)
Three sub-tabs for attack generation:
1. **Permakill** — Credential lockdown script generator. Set username/password, generate a script that changes all user passwords, locks root, and wipes SSH keys.
2. **SerialKiller** — Competitor malware removal. Toggle aggressive mode (adds crontab/tmp cleanup and iptables rules). Generates kill commands for 50+ malware families.
3. **LOLBin** — Living Off the Land catalog browser. Select category (Execute, Download, ReverseShell, etc.), target OS, and binary to generate native tool commands. Press Tab to cycle binaries, Enter to generate.

### 5. Scanner (F5)
Network scanner configuration. Set target CIDR range, ports, and thread count. Results appear in a scrollable list below. For full scanning capabilities, use the `arcticfox-scan` binary directly.

### 6. Implants (F6)
Payload generator. Select implant type (ShellDropper, MemfdLoader, LdPreloadShim, PamBackdoor, SystemdTimer, RawBinary), target OS, and architecture. Press Enter to generate a JSON spec. Use the Repos tab to configure which dead-drops the implant will poll.

### 7. Config (F7)
Global configuration panel:
- `r` — Set heartbeat redirect URL
- `t` — Set heartbeat tracking URL
- `i` — Set heartbeat interval (seconds)
- `g` — Set GitHub token
- `l` — Set GitLab token
- `w` — Toggle ZW padding
- `s` — Save config to disk

### 8. Stats (F8)
Aggregate dashboard with four metric cards (Total Bots, Alive Bots, Total Repos, Queued Commands) and a detail panel. Press `r` to refresh.

## Keyboard Reference

| Key | Action |
|-----|--------|
| `F1-F8` or `1-8` | Switch to tab |
| `Left`/`Right` or `Tab` | Previous/next tab |
| `Up`/`Down` | Navigate items in panel |
| `r` | Refresh current tab data |
| `q` or `Esc` | Quit |
| `?` | Help overlay |

## Workflow Example

```bash
# 1. Start the API server
./target/release/arcticfox-api

# 2. Launch the dashboard
C3_TOKEN=$(grep admin_token api_config.json | cut -d'"' -f4) ./target/release/c3

# 3. In the dashboard:
#    F2 → add repo: gh:my-org/c2-repo
#    F7 → set GitHub token: ghp_xxxxxxxx
#    F3 → add command: shell whoami
#    F3 → add command: shell uname -a
#    F3 → press p to push
#    F1 → watch for bot heartbeats
```
