//! Tab F2: Repo Health — manage dead-drop repositories.

use crate::api::{ApiClient, RepoInfo};
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Rect};
use ratatui::style::{Color, Style};
use ratatui::widgets::{Cell, Row, Table, TableState};
use ratatui::Frame;

#[derive(Default)]
pub struct RepoTabState {
    pub repos: Vec<RepoInfo>,
    pub table_state: TableState,
    pub selected: usize,
    pub input_mode: bool,
    pub input_buf: String,
}

pub fn render(f: &mut Frame, area: Rect, state: &mut RepoTabState) {
    let header = Row::new(vec![
        Cell::from("#").style(Style::default().fg(Color::Cyan)),
        Cell::from("Platform"),
        Cell::from("Owner/Repo"),
        Cell::from("Branch"),
        Cell::from("File"),
        Cell::from("Status"),
    ]).style(Style::default().fg(Color::Cyan));

    let rows: Vec<Row> = state.repos.iter().enumerate().map(|(i, r)| {
        let status_color = if r.alive { Color::Green } else { Color::Red };
        Row::new(vec![
            Cell::from(i.to_string()),
            Cell::from(r.platform.as_str()),
            Cell::from(format!("{}/{}", r.owner, r.repo)),
            Cell::from(r.branch.as_str()),
            Cell::from(r.file_path.as_str()),
            Cell::from(if r.alive { "OK" } else { "FAIL" }).style(Style::default().fg(status_color)),
        ])
    }).collect();

    let widths = [
        Constraint::Length(3),
        Constraint::Length(10),
        Constraint::Length(30),
        Constraint::Length(10),
        Constraint::Length(15),
        Constraint::Length(8),
    ];

    let title = if state.input_mode {
        " ADD REPO — enter spec (gh:/gl:/dp:owner/repo) then Enter: "
    } else {
        &format!(" REPOSITORIES ({} total) ", state.repos.len())
    };

    let mut block = ui::block_border(title);
    if state.input_mode {
        block = block.border_style(Style::default().fg(Color::Yellow));
    }

    let table = Table::new(rows, widths)
        .header(header)
        .block(block)
        .row_highlight_style(Style::default().bg(Color::DarkGray));

    if !state.repos.is_empty() && state.table_state.selected().is_none() {
        state.table_state.select(Some(0));
    }

    f.render_stateful_widget(table, area, &mut state.table_state);
}

pub async fn handle_key(key: KeyCode, state: &mut RepoTabState, api: &ApiClient, status: &mut String) {
    if state.input_mode {
        match key {
            KeyCode::Enter => {
                let spec = state.input_buf.clone();
                state.input_buf.clear();
                state.input_mode = false;
                match api.add_repo(&spec).await {
                    Ok(_) => {
                        *status = format!("Added repo: {spec}");
                        match api.list_repos().await {
                            Ok(repos) => state.repos = repos,
                            Err(_) => {}
                        }
                    }
                    Err(e) => *status = format!("Error: {e}"),
                }
            }
            KeyCode::Esc => {
                state.input_buf.clear();
                state.input_mode = false;
            }
            KeyCode::Char(c) => state.input_buf.push(c),
            KeyCode::Backspace => { state.input_buf.pop(); }
            _ => {}
        }
        return;
    }

    match key {
        KeyCode::Up => {
            let len = state.repos.len().max(1);
            state.selected = state.selected.saturating_sub(1).min(len - 1);
            state.table_state.select(Some(state.selected));
        }
        KeyCode::Down => {
            let len = state.repos.len().max(1);
            state.selected = (state.selected + 1).min(len - 1);
            state.table_state.select(Some(state.selected));
        }
        KeyCode::Char('a') => {
            state.input_mode = true;
        }
        KeyCode::Char('d') => {
            if !state.repos.is_empty() {
                let idx = state.selected;
                match api.remove_repo(idx).await {
                    Ok(_) => {
                        *status = format!("Removed repo at index {idx}");
                        match api.list_repos().await {
                            Ok(repos) => state.repos = repos,
                            Err(_) => {}
                        }
                    }
                    Err(e) => *status = format!("Error: {e}"),
                }
            }
        }
        KeyCode::Char('c') => {
            *status = "Checking repos...".to_string();
            match api.check_repos().await {
                Ok(_) => {
                    *status = "Repos checked.".to_string();
                    match api.list_repos().await {
                        Ok(repos) => state.repos = repos,
                        Err(_) => {}
                    }
                }
                Err(e) => *status = format!("Error: {e}"),
            }
        }
        KeyCode::Char('p') => {
            match api.create_paste().await {
                Ok(v) => {
                    let id = v["paste_id"].as_str().unwrap_or("?");
                    *status = format!("Created paste: {id}");
                    match api.list_repos().await {
                        Ok(repos) => state.repos = repos,
                        Err(_) => {}
                    }
                }
                Err(e) => *status = format!("Error: {e}"),
            }
        }
        KeyCode::Char('v') => {
            if !state.repos.is_empty() {
                let idx = state.selected;
                match api.pull(idx).await {
                    Ok(v) => { *status = format!("Payload: {:.200}", v); }
                    Err(e) => *status = format!("Error: {e}"),
                }
            }
        }
        _ => {}
    }
}
