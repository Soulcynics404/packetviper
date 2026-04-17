pub mod dashboard;
pub mod inspection;
pub mod stats;
pub mod filters;
pub mod threats;
pub mod help;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Tabs, Paragraph};

use crate::app::{ActiveTab, App};

pub fn render(f: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),  // Tab bar
            Constraint::Min(10),   // Main content
            Constraint::Length(3), // Status bar
        ])
        .split(f.area());

    render_tabs(f, app, chunks[0]);

    match app.active_tab {
        ActiveTab::Dashboard => dashboard::render(f, app, chunks[1]),
        ActiveTab::Inspection => inspection::render(f, app, chunks[1]),
        ActiveTab::Stats => stats::render(f, app, chunks[1]),
        ActiveTab::Filters => filters::render(f, app, chunks[1]),
        ActiveTab::Threats => threats::render(f, app, chunks[1]),
        ActiveTab::Help => help::render(f, app, chunks[1]),
    }

    render_status_bar(f, app, chunks[2]);
}

fn render_tabs(f: &mut Frame, app: &App, area: Rect) {
    let threat_count = app.threat_detector.critical_count();
    let threat_badge = if threat_count > 0 {
        format!(" ⚠️ {}", threat_count)
    } else {
        String::new()
    };

    let titles: Vec<Line> = ActiveTab::titles()
        .iter()
        .enumerate()
        .map(|(i, t)| {
            let label = if i == 4 {
                format!("{}{}", t, threat_badge)
            } else {
                t.to_string()
            };
            Line::from(Span::styled(label, Style::default().fg(Color::White)))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(" PacketViper 🐍 ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .select(app.active_tab.index())
        .style(Style::default().fg(Color::DarkGray))
        .highlight_style(
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD),
        );

    f.render_widget(tabs, area);
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let capture_status = if app.capturing {
        Span::styled(
            " ● CAPTURING ",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::styled(" ○ STOPPED ", Style::default().fg(Color::DarkGray))
    };

    let filter_info = if !app.filter_engine.expression().is_empty() {
        Span::styled(
            format!("Filter: {} ", app.filter_engine.expression()),
            Style::default().fg(Color::Yellow),
        )
    } else if app.filter_input_active {
        Span::styled(
            format!("/{}", app.filter_input),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )
    } else {
        Span::raw("")
    };

    let info = Line::from(vec![
        capture_status,
        Span::raw(" | "),
        Span::styled(
            format!("Pkts: {} ", app.packet_count()),
            Style::default().fg(Color::Cyan),
        ),
        Span::raw("| "),
        Span::styled(
            format!("Shown: {} ", app.filtered_count()),
            Style::default().fg(Color::Yellow),
        ),
        Span::raw("| "),
        Span::styled(
            format!("{} ", format_bytes(app.total_bytes)),
            Style::default().fg(Color::Magenta),
        ),
        Span::raw("| "),
        filter_info,
        Span::raw("| "),
        Span::styled(
            app.status_message.clone(),
            Style::default().fg(Color::White),
        ),
    ]);

    let status = Paragraph::new(info).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::DarkGray)),
    );

    f.render_widget(status, area);
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 {
        format!("{} B", bytes)
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KB", bytes as f64 / 1024.0)
    } else if bytes < 1024 * 1024 * 1024 {
        format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0))
    } else {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    }
}