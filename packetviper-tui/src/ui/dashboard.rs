//! Dashboard view — overview of capture session

use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect, Alignment};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Padding};

use crate::app::App;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(8),  // Banner
            Constraint::Length(10), // Stats overview
            Constraint::Min(5),    // Recent packets
        ])
        .split(area);

    render_banner(f, chunks[0]);
    render_stats_overview(f, app, chunks[1]);
    render_recent_packets(f, app, chunks[2]);
}

fn render_banner(f: &mut Frame, area: Rect) {
    let banner = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ╔═══════════════════════════════════════╗",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "  ║     🐍 PacketViper v0.1.0 🐍         ║",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::styled(
            "  ║   Network Traffic Analyzer            ║",
            Style::default().fg(Color::Green),
        )),
        Line::from(Span::styled(
            "  ╚═══════════════════════════════════════╝",
            Style::default().fg(Color::Green),
        )),
        Line::from(""),
    ];

    let paragraph = Paragraph::new(banner)
        .alignment(Alignment::Center)
        .block(Block::default());

    f.render_widget(paragraph, area);
}

fn render_stats_overview(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
            Constraint::Percentage(25),
        ])
        .split(area);

    let card_style = Style::default().fg(Color::Green);

    // Card 1: Total Packets
    let card1 = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", app.packet_count()),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::raw("  Total Packets")),
    ])
    .block(
        Block::default()
            .title(" 📦 Packets ")
            .borders(Borders::ALL)
            .border_style(card_style)
            .padding(Padding::uniform(1)),
    );

    // Card 2: Total Bytes
    let card2 = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", super::format_bytes(app.total_bytes)),
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::raw("  Data Captured")),
    ])
    .block(
        Block::default()
            .title(" 💾 Data ")
            .borders(Borders::ALL)
            .border_style(card_style)
            .padding(Padding::uniform(1)),
    );

    // Card 3: Interface
    let card3 = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", app.interface),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::raw("  Interface")),
    ])
    .block(
        Block::default()
            .title(" 🌐 Interface ")
            .borders(Borders::ALL)
            .border_style(card_style)
            .padding(Padding::uniform(1)),
    );

    // Card 4: Status
    let status_text = if app.capturing { "ACTIVE" } else { "STOPPED" };
    let status_color = if app.capturing { Color::Red } else { Color::DarkGray };
    let card4 = Paragraph::new(vec![
        Line::from(""),
        Line::from(Span::styled(
            format!("  {}", status_text),
            Style::default().fg(status_color).add_modifier(Modifier::BOLD),
        )),
        Line::from(""),
        Line::from(Span::raw("  Capture Status")),
    ])
    .block(
        Block::default()
            .title(" 📡 Status ")
            .borders(Borders::ALL)
            .border_style(card_style)
            .padding(Padding::uniform(1)),
    );

    f.render_widget(card1, cols[0]);
    f.render_widget(card2, cols[1]);
    f.render_widget(card3, cols[2]);
    f.render_widget(card4, cols[3]);
}

fn render_recent_packets(f: &mut Frame, app: &App, area: Rect) {
    let recent: Vec<Line> = app
        .packets
        .iter()
        .rev()
        .take(20)
        .map(|pkt| {
            let proto_color = match pkt.protocol.as_str() {
                "TCP" => Color::Cyan,
                "UDP" => Color::Yellow,
                "ICMP" | "ICMPv6" => Color::Green,
                "DNS" => Color::Magenta,
                "HTTP" => Color::Blue,
                "TLS" => Color::Red,
                "ARP" => Color::LightYellow,
                _ => Color::White,
            };

            Line::from(vec![
                Span::styled(
                    format!(" {:>5} ", pkt.protocol),
                    Style::default().fg(proto_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} ", pkt.timestamp.format("%H:%M:%S%.3f")),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(format!("{} -> {} ", pkt.source, pkt.destination)),
                Span::styled(
                    format!("({} bytes)", pkt.length),
                    Style::default().fg(Color::DarkGray),
                ),
            ])
        })
        .collect();

    let paragraph = Paragraph::new(recent).block(
        Block::default()
            .title(" 📋 Recent Packets (newest first) ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(paragraph, area);
}