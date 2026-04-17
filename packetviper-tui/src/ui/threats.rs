use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Row, Table, Cell};

use crate::app::App;
use packetviper_core::threat::detector::ThreatLevel;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Summary
            Constraint::Min(10),   // Alert list
        ])
        .split(area);

    // Summary bar
    let total = app.threat_detector.alert_count();
    let critical = app.threat_detector.alerts.iter()
        .filter(|a| matches!(a.level, ThreatLevel::Critical)).count();
    let high = app.threat_detector.alerts.iter()
        .filter(|a| matches!(a.level, ThreatLevel::High)).count();
    let medium = app.threat_detector.alerts.iter()
        .filter(|a| matches!(a.level, ThreatLevel::Medium)).count();
    let low = app.threat_detector.alerts.iter()
        .filter(|a| matches!(a.level, ThreatLevel::Low)).count();

    let summary = Paragraph::new(vec![
        Line::from(""),
        Line::from(vec![
            Span::styled(
                format!("  Total: {} ", total),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("CRITICAL: {} ", critical),
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("HIGH: {} ", high),
                Style::default().fg(Color::LightRed),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("MEDIUM: {} ", medium),
                Style::default().fg(Color::Yellow),
            ),
            Span::raw(" | "),
            Span::styled(
                format!("LOW: {} ", low),
                Style::default().fg(Color::Blue),
            ),
        ]),
        Line::from(""),
    ])
    .block(
        Block::default()
            .title(" 🛡️  Threat Summary ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(if critical > 0 {
                Color::Red
            } else if high > 0 {
                Color::LightRed
            } else {
                Color::Green
            })),
    );

    f.render_widget(summary, chunks[0]);

    // Alert list
    if app.threat_detector.alerts.is_empty() {
        let no_alerts = Paragraph::new(vec![
            Line::from(""),
            Line::from(Span::styled(
                "  ✅ No threats detected",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from("  The threat detector monitors for:"),
            Line::from("    • Port scanning (>15 unique ports from same source)"),
            Line::from("    • ARP spoofing (multiple MACs for same IP)"),
            Line::from("    • DNS tunneling (unusually long domain queries)"),
            Line::from("    • Suspicious port usage (known malware ports)"),
            Line::from("    • High traffic rate (>500 pkt/10s from one source)"),
        ])
        .block(
            Block::default()
                .title(" 📋 Alerts ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        );
        f.render_widget(no_alerts, chunks[1]);
    } else {
        let rows: Vec<Row> = app
            .threat_detector
            .alerts
            .iter()
            .rev()
            .map(|alert| {
                let level_color = match alert.level {
                    ThreatLevel::Critical => Color::Red,
                    ThreatLevel::High => Color::LightRed,
                    ThreatLevel::Medium => Color::Yellow,
                    ThreatLevel::Low => Color::Blue,
                    ThreatLevel::Info => Color::DarkGray,
                };

                let level_icon = match alert.level {
                    ThreatLevel::Critical => "🔴",
                    ThreatLevel::High => "🟠",
                    ThreatLevel::Medium => "🟡",
                    ThreatLevel::Low => "🔵",
                    ThreatLevel::Info => "⚪",
                };

                Row::new(vec![
                    Cell::from(Span::styled(
                        format!(" {} {}", level_icon, alert.level),
                        Style::default().fg(level_color).add_modifier(Modifier::BOLD),
                    )),
                    Cell::from(alert.timestamp.format("%H:%M:%S").to_string()),
                    Cell::from(Span::styled(
                        alert.category.clone(),
                        Style::default().fg(Color::White),
                    )),
                    Cell::from(alert.source_ip.clone()),
                    Cell::from(truncate(&alert.description, 45)),
                ])
            })
            .collect();

        let table = Table::new(
            rows,
            [
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Length(16),
                Constraint::Length(18),
                Constraint::Min(30),
            ],
        )
        .header(
            Row::new(vec![" Level", "Time", "Category", "Source", "Description"])
                .style(
                    Style::default()
                        .fg(Color::Green)
                        .add_modifier(Modifier::BOLD),
                )
                .bottom_margin(1),
        )
        .block(
            Block::default()
                .title(format!(" 📋 Alerts ({}) ", app.threat_detector.alert_count()))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        );

        f.render_widget(table, chunks[1]);
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_string()
    }
}