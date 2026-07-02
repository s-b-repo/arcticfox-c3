//! Tab F7: Configuration — manage tokens, heartbeat, padding.

use crate::api::{ApiClient, HeartbeatConfig};
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::Paragraph;
use ratatui::Frame;

pub struct ConfigTabState {
    pub heartbeat: Option<HeartbeatConfig>,
    pub padding_enabled: bool,
    pub input_mode: bool,
    pub input_field: usize, // 0=redirect, 1=tracking, 2=interval, 3=gh_token, 4=gl_token
    pub input_buf: String,
    pub gh_token_set: bool,
    pub gl_token_set: bool,
}

impl Default for ConfigTabState {
    fn default() -> Self {
        ConfigTabState {
            heartbeat: None,
            padding_enabled: false,
            input_mode: false,
            input_field: 0,
            input_buf: String::new(),
            gh_token_set: false,
            gl_token_set: false,
        }
    }
}

pub fn render(f: &mut Frame, area: Rect, state: &ConfigTabState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(14), Constraint::Min(0)])
        .split(area);

    let hb = state.heartbeat.as_ref();
    let redirect = hb.map(|h| h.redirect.as_str()).unwrap_or("(not set)");
    let tracking = hb.map(|h| h.tracking.as_str()).unwrap_or("(not set)");
    let interval = hb.map(|h| h.interval).unwrap_or(300);

    let form_text = vec![
        Line::from("── Heartbeat ──"),
        Line::from(format!("  Redirect URL:  {redirect}")),
        Line::from(format!("  Tracking URL:  {tracking}")),
        Line::from(format!("  Interval:       {interval}s")),
        Line::from(""),
        Line::from("── Tokens ──"),
        Line::from(format!("  GitHub:  {}", if state.gh_token_set { "●●●●●●● (set)" } else { "(not set)" })),
        Line::from(format!("  GitLab:  {}", if state.gl_token_set { "●●●●●●● (set)" } else { "(not set)" })),
        Line::from(""),
        Line::from(format!("── Padding ── {}", if state.padding_enabled { "ON (1MB ZW noise)" } else { "OFF" })),
        Line::from(""),
        Line::from("  [r] Set redirect   [t] Set tracking   [i] Set interval"),
        Line::from("  [g] Set GH token   [l] Set GL token   [w] Toggle padding"),
        Line::from("  [s] Save config"),
    ];

    let form = Paragraph::new(form_text)
        .block(ui::block_border(" CONFIGURATION "))
        .style(Style::default().fg(Color::White));
    f.render_widget(form, chunks[0]);
}

pub async fn handle_key(key: KeyCode, state: &mut ConfigTabState, api: &ApiClient, status: &mut String) {
    if state.input_mode {
        match key {
            KeyCode::Enter => {
                let value = state.input_buf.clone();
                state.input_buf.clear();
                state.input_mode = false;
                match state.input_field {
                    0 => { let _ = api.set_heartbeat(Some(&value), None, None).await; *status = "Redirect updated.".to_string(); }
                    1 => { let _ = api.set_heartbeat(None, Some(&value), None).await; *status = "Tracking updated.".to_string(); }
                    2 => {
                        if let Ok(secs) = value.parse::<u64>() {
                            let _ = api.set_heartbeat(None, None, Some(secs)).await;
                            *status = format!("Interval set to {secs}s.");
                        }
                    }
                    3 => {
                        state.gh_token_set = true;
                        let _ = api.set_tokens(Some(&value), None).await;
                        *status = "GitHub token set.".to_string();
                    }
                    4 => {
                        state.gl_token_set = true;
                        let _ = api.set_tokens(None, Some(&value)).await;
                        *status = "GitLab token set.".to_string();
                    }
                    _ => {}
                }
                if let Ok(hb) = api.get_heartbeat().await { state.heartbeat = Some(hb); }
            }
            KeyCode::Esc => { state.input_buf.clear(); state.input_mode = false; }
            KeyCode::Char(c) => state.input_buf.push(c),
            KeyCode::Backspace => { state.input_buf.pop(); }
            _ => {}
        }
        return;
    }

    match key {
        KeyCode::Char('r') => { state.input_mode = true; state.input_field = 0; }
        KeyCode::Char('t') => { state.input_mode = true; state.input_field = 1; }
        KeyCode::Char('i') => { state.input_mode = true; state.input_field = 2; }
        KeyCode::Char('g') => { state.input_mode = true; state.input_field = 3; }
        KeyCode::Char('l') => { state.input_mode = true; state.input_field = 4; }
        KeyCode::Char('w') => {
            state.padding_enabled = !state.padding_enabled;
            let _ = api.toggle_padding(Some(state.padding_enabled)).await;
            *status = format!("Padding: {}", if state.padding_enabled { "ON" } else { "OFF" });
        }
        KeyCode::Char('s') => {
            match api.save_config().await {
                Ok(_) => *status = "Config saved.".into(),
                Err(e) => *status = format!("Error: {e}"),
            }
        }
        _ => {}
    }
}
