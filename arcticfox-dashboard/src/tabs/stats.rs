//! Tab F8: Stats Dashboard — aggregate C2 telemetry.

use crate::api::{ApiClient, StatsInfo};
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

#[derive(Default)]
pub struct StatsTabState {
    pub stats: Option<StatsInfo>,
}

pub fn render(f: &mut Frame, area: Rect, state: &StatsTabState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(8), Constraint::Min(0)])
        .split(area);

    let stats = state.stats.as_ref();

    let cards = Layout::default()
        .direction(ratatui::layout::Direction::Horizontal)
        .constraints([
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
            Constraint::Ratio(1, 4),
        ])
        .split(chunks[0]);

    // Card helper
    let render_card = |f: &mut Frame, area: Rect, title: &str, value: u64, color: Color| {
        let block = Block::default()
            .borders(Borders::ALL)
            .border_type(ratatui::widgets::BorderType::Rounded)
            .border_style(Style::default().fg(color))
            .title(title);
        let inner = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(1), Constraint::Length(2)])
            .split(block.inner(area));
        let value_text = Paragraph::new(value.to_string())
            .style(Style::default().fg(color))
            .centered();
        f.render_widget(block, area);
        f.render_widget(value_text, inner[1]);
    };

    render_card(f, cards[0], "Bots", stats.map(|s| s.bots_total).unwrap_or(0), Color::Cyan);
    render_card(f, cards[1], "Alive", stats.map(|s| s.bots_alive).unwrap_or(0), Color::Green);
    render_card(f, cards[2], "Repos", stats.map(|s| s.repos_total).unwrap_or(0), Color::Yellow);
    render_card(f, cards[3], "Queued", stats.map(|s| s.commands_queued).unwrap_or(0), Color::Magenta);

    let detail_text = if let Some(s) = stats {
        vec![
            Line::from(""),
            Line::from(format!("  Total Bots:     {}    ({} alive, {} offline)", s.bots_total, s.bots_alive, s.bots_total.saturating_sub(s.bots_alive))),
            Line::from(format!("  Total Repos:    {}    ({} alive, {} dead)", s.repos_total, s.repos_alive, s.repos_total.saturating_sub(s.repos_alive))),
            Line::from(format!("  Commands:       {} queued", s.commands_queued)),
            Line::from(format!("  Padding:        {}", if s.padding_enabled { "ON" } else { "OFF" })),
        ]
    } else {
        vec![Line::from("  (no data — press r to refresh)")]
    };

    let detail = Paragraph::new(detail_text)
        .block(ui::block_border(" DETAILS "))
        .style(Style::default().fg(Color::White));
    f.render_widget(detail, chunks[1]);
}

pub async fn handle_key(key: KeyCode, _state: &mut StatsTabState, _api: &ApiClient, _status: &mut String) {
    match key {
        KeyCode::Char('r') => {
            // Refresh is handled by app-level 'r' handler
        }
        _ => {}
    }
}
