//! Tab F5: Network Scanner — live scan control with API integration.

use crate::api::ApiClient;
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, ListState, Paragraph};
use ratatui::Frame;
use std::time::Instant;

#[derive(Default)]
pub struct ScanTabState {
    pub target: String,
    pub ports: String,
    pub target_count: String,
    pub results: Vec<ScanResultItem>,
    pub scanning: bool,
    pub selected: usize,
    pub list_state: ListState,
    pub input_mode: bool,
    pub input_field: usize,
    // Live progress from API
    pub progress: Option<ScanProgress>,
    pub last_refresh: Option<Instant>,
}

#[derive(Debug, Clone)]
struct ScanResultItem {
    ip: String,
    port: u16,
    banner: String,
    username: Option<String>,
    is_honeypot: bool,
}

#[derive(Debug, Clone)]
struct ScanProgress {
    targets_scanned: u64,
    targets_total: u64,
    open_ports: u64,
    honeypots: u64,
    cracked: u64,
}

pub fn render(f: &mut Frame, area: Rect, state: &mut ScanTabState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let target = if state.target.is_empty() { "0.0.0.0/0" } else { &state.target };
    let ports = if state.ports.is_empty() { "23,2323" } else { &state.ports };
    let count = if state.target_count.is_empty() { "100000" } else { &state.target_count };
    let status = if state.scanning { "RUNNING" } else { "IDLE" };
    let status_color = if state.scanning { Color::Green } else { Color::DarkGray };

    let form_lines = vec![
        Line::from(format!("  Status:  {} (press Enter to start, s to stop)", status)),
        Line::from(format!("  Target:  {target}    (t to edit)")),
        Line::from(format!("  Ports:   {ports}    (p to edit)")),
        Line::from(format!("  Max:     {count} targets    (m to edit)")),
    ];

    let mut progress_lines = form_lines;
    if let Some(ref prog) = state.progress {
        let pct = if prog.targets_total > 0 {
            (prog.targets_scanned as f64 / prog.targets_total as f64) * 100.0
        } else { 0.0 };
        progress_lines.push(Line::from(format!(
            "  Progress: {}/{} ({:.1}%) | Open: {} | HP: {} | Cracked: {}",
            prog.targets_scanned, prog.targets_total, pct,
            prog.open_ports, prog.honeypots, prog.cracked
        )));
    }

    let form = Paragraph::new(progress_lines)
        .block(ui::block_border(" NETWORK SCANNER "))
        .style(Style::default().fg(Color::White));
    f.render_widget(form, chunks[0]);

    let results_title = format!(" RESULTS ({} entries) ", state.results.len());
    let items: Vec<ListItem> = state.results.iter().map(|r| {
        let hp = if r.is_honeypot { " [HP]" } else { "" };
        let cred = r.username.as_ref().map(|u| format!("  {u}:****")).unwrap_or_default();
        ListItem::new(format!("  {}:{}{}{}", r.ip, r.port, hp, cred))
    }).collect();

    let list = List::new(items)
        .block(ui::block_border(&results_title))
        .highlight_style(Style::default().bg(Color::DarkGray));

    if !state.results.is_empty() && state.list_state.selected().is_none() {
        state.list_state.select(Some(0));
    }
    f.render_stateful_widget(list, chunks[1], &mut state.list_state);
}

pub async fn handle_key(key: KeyCode, state: &mut ScanTabState, api: &ApiClient, status: &mut String) {
    if state.input_mode {
        match key {
            KeyCode::Enter | KeyCode::Esc => state.input_mode = false,
            KeyCode::Char(c) => {
                match state.input_field {
                    0 => state.target.push(c),
                    1 => state.ports.push(c),
                    2 => state.target_count.push(c),
                    _ => {}
                }
            }
            KeyCode::Backspace => {
                match state.input_field {
                    0 => { state.target.pop(); }
                    1 => { state.ports.pop(); }
                    2 => { state.target_count.pop(); }
                    _ => {}
                }
            }
            _ => {}
        }
        return;
    }

    match key {
        KeyCode::Char('t') => { state.input_mode = true; state.input_field = 0; }
        KeyCode::Char('p') => { state.input_mode = true; state.input_field = 1; }
        KeyCode::Char('m') => { state.input_mode = true; state.input_field = 2; }
        KeyCode::Enter => {
            if state.scanning {
                *status = "Scan already running.".into();
                return;
            }
            let target = if state.target.is_empty() { "0.0.0.0/0".to_string() } else { state.target.clone() };
            let ports = if state.ports.is_empty() { "23,2323".to_string() } else { state.ports.clone() };
            let count: u64 = state.target_count.parse().unwrap_or(100000);
            match api.start_scan(&target, &ports, count).await {
                Ok(_) => {
                    state.scanning = true;
                    state.results.clear();
                    state.progress = Some(ScanProgress {
                        targets_scanned: 0, targets_total: count,
                        open_ports: 0, honeypots: 0, cracked: 0,
                    });
                    state.last_refresh = Some(Instant::now());
                    *status = format!("Scan started: {target} on ports {ports}");
                }
                Err(e) => *status = format!("Error: {e}"),
            }
        }
        KeyCode::Char('s') => {
            if state.scanning {
                match api.stop_scan().await {
                    Ok(_) => {
                        state.scanning = false;
                        *status = "Scan stopped.".into();
                    }
                    Err(e) => *status = format!("Error: {e}"),
                }
            }
        }
        KeyCode::Char('r') => {
            // Refresh status and results
            if state.scanning {
                if let Ok(v) = api.get_scan_status().await {
                    state.progress = Some(ScanProgress {
                        targets_scanned: v["targets_scanned"].as_u64().unwrap_or(0),
                        targets_total: v["targets_total"].as_u64().unwrap_or(0),
                        open_ports: v["open_ports"].as_u64().unwrap_or(0),
                        honeypots: v["honeypots"].as_u64().unwrap_or(0),
                        cracked: v["cracked"].as_u64().unwrap_or(0),
                    });
                    if !v["running"].as_bool().unwrap_or(false) {
                        state.scanning = false;
                    }
                }
            }
            if let Ok(v) = api.get_scan_results().await {
                if let Some(arr) = v["results"].as_array() {
                    state.results = arr.iter().map(|r| ScanResultItem {
                        ip: r["ip"].as_str().unwrap_or("?").to_string(),
                        port: r["port"].as_u64().unwrap_or(0) as u16,
                        banner: r["banner"].as_str().unwrap_or("").to_string(),
                        username: r["username"].as_str().map(|s| s.to_string()),
                        is_honeypot: r["is_honeypot"].as_bool().unwrap_or(false),
                    }).collect();
                }
            }
            *status = "Results refreshed.".into();
        }
        KeyCode::Char('c') => {
            match api.clear_scan().await {
                Ok(_) => {
                    state.results.clear();
                    state.progress = None;
                    state.scanning = false;
                    *status = "Scan results cleared.".into();
                }
                Err(e) => *status = format!("Error: {e}"),
            }
        }
        KeyCode::Up => {
            let len = state.results.len().max(1);
            state.selected = state.selected.saturating_sub(1).min(len - 1);
            state.list_state.select(Some(state.selected));
        }
        KeyCode::Down => {
            let len = state.results.len().max(1);
            state.selected = (state.selected + 1).min(len - 1);
            state.list_state.select(Some(state.selected));
        }
        _ => {}
    }
}
