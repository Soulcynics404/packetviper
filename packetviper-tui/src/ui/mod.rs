pub mod dashboard;
pub mod inspection;
pub mod stats;
pub mod filters;
pub mod threats;
pub mod help;

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Tabs, Paragraph};

use crate::app::{ActiveTab, App};

pub fn render(f: &mut Frame, app: &App) {
    let t = &app.theme;

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(10),
            Constraint::Length(3),
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
    let t = &app.theme;
    let threat_count = app.threat_detector.critical_count();
    let threat_badge = if threat_count > 0 { format!(" ⚠ {}", threat_count) } else { String::new() };

    let titles: Vec<Line> = ActiveTab::titles()
        .iter()
        .enumerate()
        .map(|(i, title)| {
            let label = if i == 4 { format!("{}{}", title, threat_badge) } else { title.to_string() };
            Line::from(Span::styled(label, Style::default().fg(t.text)))
        })
        .collect();

    let tabs = Tabs::new(titles)
        .block(
            Block::default()
                .title(format!(" PacketViper 🐍 [{}] ", t.name.name()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(t.border)),
        )
        .select(app.active_tab.index())
        .style(Style::default().fg(t.text_dim))
        .highlight_style(Style::default().fg(t.border_highlight).add_modifier(Modifier::BOLD));

    f.render_widget(tabs, area);
}

fn render_status_bar(f: &mut Frame, app: &App, area: Rect) {
    let t = &app.theme;

    let capture_status = if app.capturing {
        Span::styled(" ● LIVE ", Style::default().fg(t.capture_active).add_modifier(Modifier::BOLD))
    } else {
        Span::styled(" ○ STOP ", Style::default().fg(t.capture_stopped))
    };

    let filter_info = if !app.filter_engine.expression().is_empty() {
        Span::styled(format!("F:{} ", app.filter_engine.expression()), Style::default().fg(t.accent3))
    } else if app.filter_input_active {
        Span::styled(format!("/{}", app.filter_input), Style::default().fg(t.accent3).add_modifier(Modifier::BOLD))
    } else {
        Span::raw("")
    };

    let bm_info = if app.show_bookmarks_only {
        Span::styled(format!("★{} ", app.bookmarked_packets.len()), Style::default().fg(t.bookmark))
    } else {
        Span::raw("")
    };

    let info = Line::from(vec![
        capture_status,
        Span::raw("| "),
        Span::styled(format!("P:{} ", app.packet_count()), Style::default().fg(t.accent1)),
        Span::styled(format!("S:{} ", app.filtered_count()), Style::default().fg(t.accent3)),
        Span::styled(format!("{} ", format_bytes(app.total_bytes)), Style::default().fg(t.accent2)),
        Span::raw("| "),
        filter_info,
        bm_info,
        Span::styled(app.status_message.clone(), Style::default().fg(t.text)),
    ]);

    let status = Paragraph::new(info).block(
        Block::default().borders(Borders::ALL).border_style(Style::default().fg(t.text_dim)),
    );

    f.render_widget(status, area);
}

pub fn format_bytes(bytes: u64) -> String {
    if bytes < 1024 { format!("{} B", bytes) }
    else if bytes < 1024 * 1024 { format!("{:.1} KB", bytes as f64 / 1024.0) }
    else if bytes < 1024 * 1024 * 1024 { format!("{:.1} MB", bytes as f64 / (1024.0 * 1024.0)) }
    else { format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0)) }
}