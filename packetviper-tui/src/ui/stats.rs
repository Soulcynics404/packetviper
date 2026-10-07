use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Sparkline, Row, Table, Cell};

use crate::app::App;
use super::{format_bytes, truncate};

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let stats = app.bandwidth_monitor.snapshot();

    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Bandwidth sparkline
            Constraint::Length(12), // Protocol + TCP flags
            Constraint::Min(8),     // Top talkers (by IP)
            Constraint::Length(10), // Top uploaders (by app)
        ])
        .split(area);

    // -- Bandwidth Sparkline --
    let bw_data: Vec<u64> = stats.bandwidth_history.clone();
    let sparkline = Sparkline::default()
        .block(
            Block::default()
                .title(format!(
                    " 📈 ▼ Down {}/s   ▲ Up {}/s   (peak up {}/s) | Avg {}/s | {:.0} pkt/s ",
                    format_bytes(app.bandwidth_monitor.in_rate()),
                    format_bytes(app.bandwidth_monitor.out_rate()),
                    format_bytes(app.bandwidth_monitor.peak_out_rate()),
                    format_bytes(stats.bytes_per_second as u64),
                    stats.packets_per_second,
                ))
                .borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)),
        )
        .data(&bw_data)
        .style(Style::default().fg(app.theme.accent1));

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
            let color = app.theme.proto_color(proto.as_str());
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
            .style(Style::default().fg(app.theme.border).add_modifier(Modifier::BOLD))
            .bottom_margin(1),
    )
    .block(
        Block::default()
            .title(" 📊 Protocol Distribution ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(proto_table, proto_chunks[0]);

    // TCP Flags + General Stats
    let mut info_lines = vec![
        Line::from(Span::styled(
            " ── General ──",
            Style::default().fg(app.theme.border).add_modifier(Modifier::BOLD),
        )),
        Line::from(format!("  Total Packets: {}", stats.total_packets)),
        Line::from(format!("  Total Data:    {}", format_bytes(stats.total_bytes))),
        Line::from(format!("  Avg Pkt Size:  {:.0} bytes", stats.avg_packet_size)),
        Line::from(format!("  ↓ Incoming:    {}", format_bytes(stats.incoming_bytes))),
        Line::from(format!("  ↑ Outgoing:    {}", format_bytes(stats.outgoing_bytes))),
        Line::from(""),
        Line::from(Span::styled(
            " ── TCP Flags ──",
            Style::default().fg(app.theme.accent1).add_modifier(Modifier::BOLD),
        )),
    ];

    for (flag, count) in &stats.tcp_flags_count {
        info_lines.push(Line::from(format!("  {:<10} {}", flag, count)));
    }

    let info_panel = Paragraph::new(info_lines).block(
        Block::default()
            .title(" 📋 Details ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
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
            .style(Style::default().fg(app.theme.accent1).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" 🔼 Top Sources ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
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
            .style(Style::default().fg(app.theme.accent3).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" 🔽 Top Destinations ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
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
            .style(Style::default().fg(app.theme.accent2).add_modifier(Modifier::BOLD)),
    )
    .block(
        Block::default()
            .title(" 🔄 Top Conversations ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)),
    );

    f.render_widget(conv_table, talker_chunks[2]);

    render_uploaders(f, app, chunks[3]);
}

/// Per-application upload/download table, so a sudden upload spike can be traced to the app causing it.
fn render_uploaders(f: &mut Frame, app: &App, area: Rect) {
    if !app.net_monitor.is_available() {
        let note = Paragraph::new(" Per-app traffic is Linux-only (needs root). Not available on this OS.")
            .block(Block::default().title(" 📤 Top Uploaders (by app) ").borders(Borders::ALL)
                .border_style(Style::default().fg(app.theme.border)));
        f.render_widget(note, area);
        return;
    }
    let rows: Vec<Row> = app.net_monitor.top_uploaders(8).iter().map(|p| {
        let dests = p.remote_ips.len();
        Row::new(vec![
            Cell::from(format!(" {}", truncate(&p.name, 22))),
            Cell::from(format!("{}", p.pid)),
            Cell::from(Span::styled(format!("▲ {}", format_bytes(p.out_bytes)), Style::default().fg(app.theme.accent3))),
            Cell::from(format!("▼ {}", format_bytes(p.in_bytes))),
            Cell::from(format!("{} dst", dests)),
        ])
    }).collect();
    let table = Table::new(rows, [Constraint::Min(16), Constraint::Length(7), Constraint::Length(14), Constraint::Length(14), Constraint::Length(8)])
        .header(Row::new(vec![" App", "PID", "Uploaded", "Downloaded", "Internet"])
            .style(Style::default().fg(app.theme.accent1).add_modifier(Modifier::BOLD)))
        .block(Block::default().title(" 📤 Top Uploaders (by app) — watch the Uploaded column ").borders(Borders::ALL)
            .border_style(Style::default().fg(app.theme.border)));
    f.render_widget(table, area);
}

