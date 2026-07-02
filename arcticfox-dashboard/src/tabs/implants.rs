//! Tab F6: Implant Generator — generate payload specs for deployment.

use crate::api::ApiClient;
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

#[derive(Default)]
pub struct ImplantTabState {
    pub payload_type: usize,
    pub target_os: usize,
    pub arch: usize,
    pub repos: Vec<String>,
    pub stealth_name: String,
    pub preview: String,
    pub input_mode: bool,
    pub input_buf: String,
}

const PAYLOAD_TYPES: &[&str] = &["ShellDropper", "MemfdLoader", "LdPreloadShim", "PamBackdoor", "SystemdTimer", "RawBinary"];
const TARGET_OSES: &[&str] = &["linux", "windows", "macos"];
const ARCHES: &[&str] = &["x86_64", "aarch64", "armv7", "i686"];

pub fn render(f: &mut Frame, area: Rect, state: &mut ImplantTabState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let session_key_hex = hex::encode(arcticfox_core::crypto::generate_session_key());
    let key_short = &session_key_hex[..16];

    let form_text = vec![
        Line::from(format!("  Type:   {}    OS: {}    Arch: {}", 
            PAYLOAD_TYPES[state.payload_type], TARGET_OSES[state.target_os], ARCHES[state.arch])),
        Line::from(format!("  Repos:  {} repo(s) configured (from dashboard repos)", state.repos.len())),
        Line::from(format!("  Name:   {}    (random service name)", 
            if state.stealth_name.is_empty() { "sshd (auto)" } else { &state.stealth_name })),
        Line::from(format!("  Key:    {key_short}... (auto-generated)")),
        Line::from(""),
        Line::from("  [← →] Change type   [↑ ↓] Change OS   [Tab] Change arch"),
        Line::from("  [Enter] Generate Spec   [d] Deploy to Dead-Drop"),
    ];

    let form = Paragraph::new(form_text)
        .block(ui::block_border(" IMPLANT GENERATOR "))
        .style(Style::default().fg(Color::White));
    f.render_widget(form, chunks[0]);

    if !state.preview.is_empty() {
        let preview = Paragraph::new(state.preview.as_str())
            .block(ui::block_plain(" Generated Spec (JSON) "))
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(preview, chunks[1]);
    } else {
        let hint = Paragraph::new("Press Enter to generate a payload spec")
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(hint, chunks[1]);
    }
}

pub async fn handle_key(key: KeyCode, state: &mut ImplantTabState, _api: &ApiClient, _status: &mut String) {
    match key {
        KeyCode::Left => {
            state.payload_type = (state.payload_type + PAYLOAD_TYPES.len() - 1) % PAYLOAD_TYPES.len();
        }
        KeyCode::Right => {
            state.payload_type = (state.payload_type + 1) % PAYLOAD_TYPES.len();
        }
        KeyCode::Up => {
            state.target_os = (state.target_os + TARGET_OSES.len() - 1) % TARGET_OSES.len();
        }
        KeyCode::Down => {
            state.target_os = (state.target_os + 1) % TARGET_OSES.len();
        }
        KeyCode::Tab => {
            state.arch = (state.arch + 1) % ARCHES.len();
        }
        KeyCode::Enter => {
            let spec = serde_json::json!({
                "payload_type": PAYLOAD_TYPES[state.payload_type],
                "os": TARGET_OSES[state.target_os],
                "arch": ARCHES[state.arch],
                "session_key": hex::encode(arcticfox_core::crypto::generate_session_key()),
                "repos": state.repos,
                "stealth_name": if state.stealth_name.is_empty() { "sshd" } else { &state.stealth_name },
            });
            state.preview = serde_json::to_string_pretty(&spec).unwrap_or_default();
        }
        _ => {}
    }
}
