ArcticFox C3 needs the following from Rustsploit's API to achieve full bidirectional interop. Each item has a priority and the Rustsploit endpoint required.

PRIORITY 1 — BLOCKING

These must exist for basic interop to work.

1. Module listing endpoint
   GET /api/modules
   Returns JSON array of module metadata: name, category, rank, description
   Used by: list_modules() in rustsploit_bridge.rs

2. Module execution endpoint
   POST /api/modules/{name}/run
   Body: { target, options }
   Returns: { status, findings[] }
   Used by: run_module() — this is the core integration point

3. Health check
   GET /health
   Returns 200 with server info
   Used by: health_check() — basic connectivity test

PRIORITY 2 — HIGH VALUE

These enable credential sharing and automated pipelines.

4. Credential import endpoint
   POST /api/creds/import
   Body: [{ host, port, username, password, service, source, timestamp }]
   Returns: { imported: N }
   Used by: share_credentials() — arcticfox sends discovered creds to rustsploit

5. Credential export endpoint
   GET /api/creds
   Returns array of credentials in same schema
   Used by: import_credentials() — arcticfox pulls rustsploit's cred store

6. Background job management
   POST /api/modules/{name}/run with { background: true }
   Returns: { job_id, status }
   GET /api/jobs/{id} returns job status and results
   GET /api/jobs returns all jobs
   Used by: long-running scans that exceed MCP tool timeout

7. Implant deployment endpoint
   POST /api/deploy
   Body: { target, credential, payload_base64, args[] }
   Returns: { status, pid }
   Used by: deploy_via_exploit() — the scan-exploit-deploy pipeline

PRIORITY 3 — NICE TO HAVE

These complete the integration but aren't blockers.

8. Host and service tracking
   POST /api/hosts with { ip, os, services[] }
   GET /api/hosts returns all tracked hosts
   Enables shared situational awareness between frameworks

9. Authentication
   Shared API key (32-byte hex) via Authorization: Bearer header
   Alternative: PQ enrollment flow (X25519 + ML-KEM-768)
   Currently rustsploit uses one-time enrollment tokens. For arcticfox interop, a persistent shared key is simpler.

10. Loot sharing
    POST /api/loot with { host, path, content, type }
    GET /api/loot returns collected files/data

IMPLEMENTATION NOTES

The arcticfox rustsploit_bridge.rs module already has all client code written. It gracefully handles missing endpoints by returning descriptive errors. To test: start rustsploit with --api, then run arcticfox-control and use the rustsploit subcommands. All calls are async with proper error handling — no unwrap, no panic.

SHARED CREDENTIAL SCHEMA

{
  "host": "10.0.0.1",
  "port": 22,
  "username": "root",
  "password": "toor",
  "service": "ssh",
  "source": "arcticfox",
  "timestamp": 1719000000
}

PIPELINE FLOW

arcticfox-scan finds open telnet + valid creds
  → share_credentials() sends to rustsploit
    → rustsploit runs priv esc module
      → on root, arcticfox deploys implant via deploy_via_exploit()
        → implant phones home via ZW dead-drop
          → both frameworks control same bot
