//! Tab F1: Bot Fleet — live agent tracking with auto-refresh.

use crate::api::{ApiClient, BotInfo};
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Cell, Row, Table, TableState};
use ratatui::Frame;

#[derive(Default)]
pub struct BotTabState {
    pub bots: Vec<BotInfo>,
    pub table_state: TableState,
    pub selected: usize,
}

pub fn render(f: &mut Frame, area: Rect, state: &mut BotTabState) {
    let header = Row::new(vec![
        Cell::from("●"),
        Cell::from("Bot ID"),
        Cell::from("IP"),
        Cell::from("Last Seen"),
        Cell::from("Hits"),
        Cell::from("Status"),
    ]).style(Style::default().fg(Color::Cyan));

    let now = chrono::Utc::now().timestamp() as f64;
    let rows: Vec<Row> = state.bots.iter().map(|b| {
        let alive = (now - b.last_seen) < 600.0;
        let dot = if alive { "●" } else { "○" };
        let dot_color = if alive { Color::Green } else { Color::DarkGray };
        let rel = format_relative(now - b.last_seen);
        Row::new(vec![
            Cell::from(dot).style(Style::default().fg(dot_color)),
            Cell::from(b.id.as_str()),
            Cell::from(b.ip.as_str()),
            Cell::from(rel),
            Cell::from(b.hits.to_string()),
            Cell::from(if alive { "alive" } else { "offline" })
                .style(Style::default().fg(if alive { Color::Green } else { Color::Red })),
        ])
    }).collect();

    let widths = [
        Constraint::Length(1),
        Constraint::Length(20),
        Constraint::Length(18),
        Constraint::Length(12),
        Constraint::Length(8),
        Constraint::Length(10),
    ];

    let title = format!(" BOT FLEET ({} total) ", state.bots.len());
    let table = Table::new(rows, widths)
        .header(header)
        .block(ui::block_border(&title))
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    if !state.bots.is_empty() {
        if state.table_state.selected().is_none() {
            state.table_state.select(Some(0));
        }
    }

    f.render_stateful_widget(table, area, &mut state.table_state);
}

pub async fn handle_key(key: KeyCode, state: &mut BotTabState, api: &ApiClient, status: &mut String) {
    match key {
        KeyCode::Up => {
            let len = state.bots.len().max(1);
            state.selected = state.selected.saturating_sub(1).min(len - 1);
            state.table_state.select(Some(state.selected));
        }
        KeyCode::Down => {
            let len = state.bots.len().max(1);
            state.selected = (state.selected + 1).min(len - 1);
            state.table_state.select(Some(state.selected));
        }
        KeyCode::Char('d') => {
            if let Some(bot) = state.bots.get(state.selected) {
                let id = bot.id.clone();
                match api.delete_bot(&id).await {
                    Ok(_) => *status = format!("Deleted bot {}", id),
                    Err(e) => *status = format!("Error: {e}"),
                }
                match api.list_bots().await {
                    Ok(bots) => state.bots = bots,
                    Err(_) => {}
                }
            }
        }
        _ => {}
    }
}

fn format_relative(seconds: f64) -> String {
    if seconds < 60.0 {
        format!("{}s ago", seconds as u64)
    } else if seconds < 3600.0 {
        format!("{}m ago", (seconds / 60.0) as u64)
    } else if seconds < 86400.0 {
        format!("{}h ago", (seconds / 3600.0) as u64)
    } else {
        format!("{}d ago", (seconds / 86400.0) as u64)
    }
}
