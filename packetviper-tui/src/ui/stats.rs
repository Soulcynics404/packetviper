use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline, Row, Table, Cell};

use crate::app::App;
use super::format_bytes;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let stats = app.bandwidth_monitor.snapshot();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Bandwidth sparkline
            Constraint::Length(12), // Protocol + TCP flags
            Constraint::Min(8),    // Top talkers
        ])
        .split(area);

    // -- Bandwidth Sparkline --
    let bw_data: Vec<u64> = stats.bandwidth_history.clone();
    let current_bps = bw_data.last().copied().unwrap_or(0);
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(format!(
                    " 📈 Bandwidth: {}/s | Avg: {}/s | Packets/s: {:.1} ",
                    format_bytes(current_bps),
                    format_bytes(stats.bytes_per_second as u64),
                    stats.packets_per_second,
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        )
        .data(&bw_data)
        .style(Style::default().fg(Color::Cyan));

    f.render_widget(sparkline, chunks[0]);

    // -- Protocol Distribution + TCP Flags --
    let proto_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(50),
            Constraint::Percentage(50),
        ])
        .split(chunks[1]);

    // Protocol table
    let proto_rows: Vec<Row> = stats
        .protocol_counts
        .iter()
        .map(|(proto, count)| {
            let bytes = stats.protocol_bytes.get(proto).unwrap_or(&0);
            let pct = if stats.total_packets > 0 {
                *count as f64 / stats.total_packets as f64 * 100.0
            } else {
                0.0
            };
            let color = match proto.as_str() {
                "TCP" => Color::Cyan,
                "UDP" => Color::Yellow,
                "ICMP" | "ICMPv6" => Color::Green,
                "DNS" => Color::Magenta,
                "HTTP" => Color::Blue,
                "TLS" => Color::Red,
                "ARP" => Color::LightYellow,
                "SSH" => Color::LightRed,
                _ => Color::White,
            };
            Row::new(vec![
                Cell::from(Span::styled(
                    format!(" {}", proto),
                    Style::default().fg(color).add_modifier(Modifier::BOLD),
                )),
                Cell::from(format!("{}", count)),
                Cell::from(format_bytes(*bytes)),
                Cell::from(format!("{:.1}%", pct)),
            ])
        })
        .collect();

    let proto_table = Table::new(
        proto_rows,
        [
            Constraint::Length(10),
            Constraint::Length(8),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    )
    .header(
        Row::new(vec![" Proto", "Count", "Bytes", "%"])
            .style(Style::default().fg(Color::Green).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(
        Block::default()
            .title(" 📊 Protocol Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(proto_table, proto_chunks[0]);

    // TCP Flags + General Stats
    let mut info_lines = vec![
        Line::from(Span::styled(
            " ── General ──",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  Total Packets: {}", stats.total_packets)),
        Line::from(format!("  Total Data:    {}", format_bytes(stats.total_bytes))),
        Line::from(format!("  Avg Pkt Size:  {:.0} bytes", stats.avg_packet_size)),
        Line::from(format!("  ↓ Incoming:    {}", format_bytes(stats.incoming_bytes))),
        Line::from(format!("  ↑ Outgoing:    {}", format_bytes(stats.outgoing_bytes))),
        Line::from(""),
        Line::from(Span::styled(
            " ── TCP Flags ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
    ];

    for (flag, count) in &stats.tcp_flags_count {
        info_lines.push(Line::from(format!("  {:<10} {}", flag, count)));
    }

    let info_panel = Paragraph::new(info_lines).block(
        Block::default()
            .title(" 📋 Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(info_panel, proto_chunks[1]);

    // -- Top Talkers --
    let talker_chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage(33),
            Constraint::Percentage(34),
            Constraint::Percentage(33),
        ])
        .split(chunks[2]);

    // Top Sources
    let src_rows: Vec<Row> = stats
        .top_sources
        .iter()
        .take(8)
        .map(|(ip, count)| {
            Row::new(vec![
                Cell::from(format!(" {}", truncate(ip, 20))),
                Cell::from(format!("{}", count)),
            ])
        })
        .collect();

    let src_table = Table::new(
        src_rows,
        [Constraint::Min(15), Constraint::Length(8)],
    )
    .header(
        Row::new(vec![" Source", "Pkts"])
            .style(Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" 🔼 Top Sources ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(src_table, talker_chunks[0]);

    // Top Destinations
    let dst_rows: Vec<Row> = stats
        .top_destinations
        .iter()
        .take(8)
        .map(|(ip, count)| {
            Row::new(vec![
                Cell::from(format!(" {}", truncate(ip, 20))),
                Cell::from(format!("{}", count)),
            ])
        })
        .collect();

    let dst_table = Table::new(
        dst_rows,
        [Constraint::Min(15), Constraint::Length(8)],
    )
    .header(
        Row::new(vec![" Destination", "Pkts"])
            .style(Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" 🔽 Top Destinations ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(dst_table, talker_chunks[1]);

    // Top Conversations
    let conv_rows: Vec<Row> = stats
        .top_conversations
        .iter()
        .take(8)
        .map(|(s, d, count)| {
            Row::new(vec![
                Cell::from(format!(" {}", truncate(s, 14))),
                Cell::from("↔"),
                Cell::from(truncate(d, 14)),
                Cell::from(format!("{}", count)),
            ])
        })
        .collect();

    let conv_table = Table::new(
        conv_rows,
        [
            Constraint::Min(10),
            Constraint::Length(2),
            Constraint::Min(10),
            Constraint::Length(6),
        ],
    )
    .header(
        Row::new(vec![" Src", "", "Dst", "Pkts"])
            .style(Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" 🔄 Top Conversations ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(conv_table, talker_chunks[2]);
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() > max {
        format!("{}…", &s[..max - 1])
    } else {
        s.to_string()
    }
}