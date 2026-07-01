# Rustsploit Interop — API Requirements

This document specifies what ArcticFox C3 needs from a Rustsploit API server
to enable full bidirectional interop: credential sharing, scan→exploit→deploy
pipelines, and module delegation.

## Required Endpoints

### 1. Health Check
```
GET /health
→ 200 {"status":"ok","version":"0.5.0"}
```
Used by: `RustsploitClient::health_check()`

### 2. Module Listing
```
GET /api/modules
→ 200 {"modules":[{"name":"ssh_bruteforce","category":"creds","rank":"excellent"},...]}
```
Used by: `RustsploitClient::list_modules()`

### 3. Module Execution
```
POST /api/modules/{name}/run
Body: {"target":"192.168.1.1:22","options":{"wordlist":"default","timeout":"30"}}
→ 200 {"status":"completed","findings":[{"type":"credential","host":"...","username":"root","password":"admin"}]}
```
Used by: `RustsploitClient::run_module()`

### 4. Credential Import
```
POST /api/creds/import
Body: [{"host":"10.0.0.1","port":22,"username":"root","password":"toor","service":"ssh","source":"arcticfox","timestamp":1719000000}]
→ 200 {"imported":1}
```
Used by: `RustsploitClient::share_credentials()`

### 5. Credential Export
```
GET /api/creds
→ 200 [{"host":"10.0.0.1","port":23,"username":"admin","password":"1234","service":"telnet","source":"rustsploit","timestamp":1719000100}]
```
Used by: `RustsploitClient::import_credentials()`

### 6. Host/Service Tracking
```
GET /api/hosts
→ 200 {"hosts":[{"ip":"10.0.0.1","os":"Linux","services":[{"port":22,"proto":"tcp","name":"ssh"}]}]}

POST /api/hosts
Body: {"ip":"10.0.0.2","os":"Linux 4.19","services":[{"port":23,"proto":"tcp","name":"telnet"}]}
→ 201
```

### 7. Implant Deployment
```
POST /api/deploy
Body: {"target":"10.0.0.1:22","credential":{"username":"root","password":"toor"},"payload":"<base64 implant binary>","args":["--daemon","--stealth-name=sshd"]}
→ 200 {"status":"deployed","pid":12345}
```

### 8. Background Job Management (async scans)
```
POST /api/modules/{name}/run  with {"background":true}
→ 202 {"job_id":"uuid","status":"queued"}

GET /api/jobs/{job_id}
→ 200 {"status":"running|completed|failed","result":{...}}

GET /api/jobs
→ 200 {"jobs":[{"id":"uuid","status":"completed","module":"port_scanner"}]}
```

## Authentication

Rustsploit uses a post-quantum enrollment flow:
1. Server prints one-time enrollment token at startup
2. Client POSTs X25519 pubkey + ML-KEM-768 encapsulation key to `/pq/register-key`
3. Subsequent requests use PQ-encrypted WebSocket or session token

For ArcticFox interop, a **shared API key** (32-byte hex) is simpler:
```
Authorization: Bearer <shared-key>
```

The ArcticFox `rustsploit_bridge.rs` supports both PQ and Bearer modes.

## Shared Credential Schema

```json
{
  "host": "10.0.0.1",
  "port": 22,
  "username": "root",
  "password": "toor",
  "service": "ssh",
  "source": "arcticfox|rustsploit",
  "timestamp": 1719000000
}
```

## Pipeline: Scan → Exploit → Deploy

```
1. ArcticFox scanner finds open telnet + valid creds
2. Credential shared with Rustsploit via POST /api/creds/import
3. Rustsploit runs privilege escalation module via POST /api/modules/privesc_linux/run
4. On root, ArcticFox deploys implant via POST /api/deploy
5. Implant phones home via ZW dead-drop
6. Both frameworks can now control the same bot
```

## Current ArcticFox Bridge Status

The `rustsploit_bridge.rs` module implements:
- `health_check()` — working
- `run_module()` — requires Rustsploit `/api/modules` endpoint
- `share_credentials()` — requires Rustsploit `/api/creds/import`
- `import_credentials()` — requires Rustsploit `/api/creds`
- `list_modules()` — requires Rustsploit `/api/modules`
- `deploy_via_exploit()` — requires scan + exploit + deploy chain

All methods gracefully handle missing endpoints (return `Result::Err` with descriptive messages).
