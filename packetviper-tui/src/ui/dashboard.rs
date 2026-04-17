use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Padding, Row, Table, Cell};

use crate::app::App;
use super::format_bytes;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Stats cards
            Constraint::Length(10), // Connections + GeoIP
            Constraint::Min(5),    // Recent packets
        ])
        .split(area);

    render_stats_cards(f, app, chunks[0]);
    render_connections_and_geo(f, app, chunks[1]);
    render_recent_packets(f, app, chunks[2]);
}

fn render_stats_cards(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
            Constraint::Percentage(20),
        ])
        .split(area);

    let card_style = Style::default().fg(Color::Green);

    // Packets
    let card1 = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("  {}", app.packet_count()),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("  Packets")),
    ])
    .block(Block::default().title(" 📦 ").borders(Borders::ALL).border_style(card_style).padding(Padding::top(1)));

    // Data
    let card2 = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("  {}", format_bytes(app.total_bytes)),
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("  Data")),
    ])
    .block(Block::default().title(" 💾 ").borders(Borders::ALL).border_style(card_style).padding(Padding::top(1)));

    // Connections
    let card3 = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("  {}", app.connection_tracker.total()),
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("  Connections")),
    ])
    .block(Block::default().title(" 🔗 ").borders(Borders::ALL).border_style(card_style).padding(Padding::top(1)));

    // Threats
    let threat_color = if app.threat_detector.critical_count() > 0 {
        Color::Red
    } else {
        Color::Green
    };
    let card4 = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("  {}", app.threat_detector.alert_count()),
            Style::default().fg(threat_color).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("  Threats")),
    ])
    .block(Block::default().title(" 🛡️ ").borders(Borders::ALL).border_style(card_style).padding(Padding::top(1)));

    // Interface
    let status_text = if app.capturing { "🟢" } else { "🔴" };
    let card5 = Paragraph::new(vec![
        Line::from(Span::styled(
            format!("  {} {}", status_text, app.interface),
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from(Span::raw("  Interface")),
    ])
    .block(Block::default().title(" 🌐 ").borders(Borders::ALL).border_style(card_style).padding(Padding::top(1)));

    f.render_widget(card1, cols[0]);
    f.render_widget(card2, cols[1]);
    f.render_widget(card3, cols[2]);
    f.render_widget(card4, cols[3]);
    f.render_widget(card5, cols[4]);
}

fn render_connections_and_geo(f: &mut Frame, app: &App, area: Rect) {
    let cols = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);

    // Active Connections
    let conns = app.connection_tracker.active_connections();
    let conn_rows: Vec<Row> = conns
        .iter()
        .take(8)
        .map(|conn| {
            let state_color = match conn.state {
                packetviper_core::stats::connections::ConnectionState::Established => Color::Green,
                packetviper_core::stats::connections::ConnectionState::SynSent => Color::Yellow,
                packetviper_core::stats::connections::ConnectionState::FinWait => Color::Red,
                packetviper_core::stats::connections::ConnectionState::Reset => Color::LightRed,
                packetviper_core::stats::connections::ConnectionState::Closed => Color::DarkGray,
                _ => Color::White,
            };

            Row::new(vec![
                Cell::from(Span::styled(
                    format!(" {:<5}", conn.protocol),
                    Style::default().fg(Color::Cyan),
                )),
                Cell::from(truncate(&format!("{}:{}", conn.src_ip, conn.src_port), 18)),
                Cell::from(truncate(&format!("{}:{}", conn.dst_ip, conn.dst_port), 18)),
                Cell::from(Span::styled(
                    format!("{}", conn.state),
                    Style::default().fg(state_color),
                )),
                Cell::from(format_bytes(conn.total_bytes())),
            ])
        })
        .collect();

    let state_counts = app.connection_tracker.count_by_state();
    let established = state_counts.get("ESTABLISHED").unwrap_or(&0);

    let conn_table = Table::new(
        conn_rows,
        [
            Constraint::Length(7),
            Constraint::Min(14),
            Constraint::Min(14),
            Constraint::Length(12),
            Constraint::Length(9),
        ],
    )
    .header(
        Row::new(vec![" Proto", "Source", "Destination", "State", "Bytes"])
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(format!(
                " 🔗 Connections ({} total, {} established) ",
                app.connection_tracker.total(),
                established
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(conn_table, cols[0]);

    // GeoIP - Recent external IPs
    let mut geo_lines = vec![
        Line::from(""),
    ];

    let mut seen_ips: std::collections::HashSet<String> = std::collections::HashSet::new();
    let mut geo_count = 0;

    for pkt in app.packets.iter().rev() {
        if geo_count >= 7 {
            break;
        }

        for ip_addr in [&pkt.source, &pkt.destination] {
            let clean = clean_ip(ip_addr);
            if !seen_ips.contains(&clean) {
                if let Some(geo) = app.lookup_geo(&clean) {
                    seen_ips.insert(clean.clone());
                    geo_lines.push(Line::from(vec![
                        Span::styled(
                            format!("  {} ", geo),
                            Style::default().fg(Color::White),
                        ),
                    ]));
                    geo_lines.push(Line::from(Span::styled(
                        format!("    └─ {}", truncate(&clean, 25)),
                        Style::default().fg(Color::DarkGray),
                    )));
                    geo_count += 1;
                }
            }
        }
    }

    if geo_count == 0 {
        geo_lines.push(Line::from(Span::styled(
            "  No external IPs detected yet",
            Style::default().fg(Color::DarkGray),
        )));
    }

    let geoip_status = if app.geoip.is_available() { "active" } else { "no database" };

    let geo_panel = Paragraph::new(geo_lines).block(
        Block::default()
            .title(format!(" 🌍 GeoIP ({}) ", geoip_status))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(geo_panel, cols[1]);
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

            let bookmark = if app.is_bookmarked(pkt.id) { "★" } else { " " };

            Line::from(vec![
                Span::styled(bookmark, Style::default().fg(Color::Yellow)),
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
                    format!("({}B)", pkt.length),
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

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_string()
    }
}

fn clean_ip(addr: &str) -> String {
    if let Some(last_colon) = addr.rfind(':') {
        let after = &addr[last_colon + 1..];
        if after.parse::<u16>().is_ok() {
            let colon_count = addr.matches(':').count();
            if colon_count == 1 {
                return addr[..last_colon].to_string();
            }
        }
    }
    addr.to_string()
}