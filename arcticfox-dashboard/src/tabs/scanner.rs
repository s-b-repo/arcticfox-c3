//! Tab F5: Network Scanner — configure and run telnet/port scans.

use crate::api::ApiClient;
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::Frame;

#[derive(Default)]
pub struct ScanTabState {
    pub target: String,
    pub ports: String,
    pub threads: String,
    pub results: Vec<String>,
    pub scanning: bool,
    pub selected: usize,
    pub list_state: ListState,
    pub input_mode: bool,
    pub input_field: usize, // 0=target, 1=ports, 2=threads
}

pub fn render(f: &mut Frame, area: Rect, state: &mut ScanTabState) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(0)])
        .split(area);

    let target_display = if state.target.is_empty() { "192.168.1.0/24" } else { &state.target };
    let ports_display = if state.ports.is_empty() { "23,2323" } else { &state.ports };
    let threads_display = if state.threads.is_empty() { "24" } else { &state.threads };

    let form_text = vec![
        Line::from(format!("  Target:  {target_display}    (press t to edit)")),
        Line::from(format!("  Ports:   {ports_display}    (press p to edit)")),
        Line::from(format!("  Threads: {threads_display}    (press h to edit)")),
        Line::from(""),
        Line::from("  [Enter] Start Scan   [s] Stop   [r] Refresh Results"),
    ];

    let form = Paragraph::new(form_text)
        .block(ui::block_border(" NETWORK SCANNER "))
        .style(Style::default().fg(Color::White));
    f.render_widget(form, chunks[0]);

    let results_title = if state.scanning {
        " SCAN RESULTS (scanning...) "
    } else {
        &format!(" SCAN RESULTS ({} entries) ", state.results.len())
    };

    let items: Vec<ListItem> = state.results.iter().map(|r| ListItem::new(r.as_str())).collect();
    let list = List::new(items)
        .block(ui::block_border(results_title))
        .highlight_style(Style::default().bg(Color::DarkGray));

    if !state.results.is_empty() && state.list_state.selected().is_none() {
        state.list_state.select(Some(0));
    }

    f.render_stateful_widget(list, chunks[1], &mut state.list_state);
}

pub async fn handle_key(key: KeyCode, state: &mut ScanTabState, _api: &ApiClient, status: &mut String) {
    if state.input_mode {
        match key {
            KeyCode::Enter | KeyCode::Esc => state.input_mode = false,
            KeyCode::Char(c) => {
                match state.input_field {
                    0 => state.target.push(c),
                    1 => state.ports.push(c),
                    2 => state.threads.push(c),
                    _ => {}
                }
            }
            KeyCode::Backspace => {
                match state.input_field {
                    0 => { state.target.pop(); }
                    1 => { state.ports.pop(); }
                    2 => { state.threads.pop(); }
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
        KeyCode::Char('h') => { state.input_mode = true; state.input_field = 2; }
        KeyCode::Enter => {
            state.scanning = true;
            *status = "Starting scan...".into();
            let target = if state.target.is_empty() { "192.168.1.0/24" } else { &state.target };
            state.results.push(format!("Scan targeted: {target} — use CLI for full scan capabilities"));
            state.scanning = false;
        }
        KeyCode::Char('s') => {
            state.scanning = false;
            *status = "Scan stopped.".into();
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
