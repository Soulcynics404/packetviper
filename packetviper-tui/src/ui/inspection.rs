use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::app::App;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    if app.show_detail {
        let chunks = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        render_packet_list(f, app, chunks[0]);
        render_packet_detail(f, app, chunks[1]);
    } else {
        render_packet_list(f, app, area);
    }
}

fn render_packet_list(f: &mut Frame, app: &App, area: Rect) {
    let visible_height = area.height.saturating_sub(2) as usize;
    let start = if app.selected_index >= visible_height {
        app.selected_index - visible_height + 1
    } else {
        0
    };

    let items: Vec<ListItem> = app
        .filtered_indices
        .iter()
        .enumerate()
        .skip(start)
        .take(visible_height)
        .map(|(display_idx, &pkt_idx)| {
            let pkt = &app.packets[pkt_idx];
            let is_selected = display_idx == app.selected_index;
            let is_bookmarked = app.is_bookmarked(pkt.id);

            let proto_color = match pkt.protocol.as_str() {
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

            let direction_icon = match pkt.direction {
                packetviper_core::packets::PacketDirection::Incoming => "⬇",
                packetviper_core::packets::PacketDirection::Outgoing => "⬆",
                packetviper_core::packets::PacketDirection::Unknown => "─",
            };

            let bookmark_icon = if is_bookmarked { "★ " } else { "  " };

            let line = Line::from(vec![
                Span::styled(
                    bookmark_icon,
                    Style::default().fg(Color::Yellow),
                ),
                Span::styled(
                    format!("{:>5} ", pkt.id),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::styled(
                    format!("{} ", direction_icon),
                    Style::default().fg(Color::White),
                ),
                Span::styled(
                    format!("{:<6} ", pkt.protocol),
                    Style::default().fg(proto_color).add_modifier(Modifier::BOLD),
                ),
                Span::styled(
                    format!("{} ", pkt.timestamp.format("%H:%M:%S")),
                    Style::default().fg(Color::DarkGray),
                ),
                Span::raw(format!(
                    "{} -> {} ",
                    truncate_str(&pkt.source, 21),
                    truncate_str(&pkt.destination, 21)
                )),
                Span::styled(
                    format!("{:>5}B", pkt.length),
                    Style::default().fg(Color::DarkGray),
                ),
            ]);

            let style = if is_selected {
                Style::default().bg(Color::DarkGray).fg(Color::White)
            } else {
                Style::default()
            };

            ListItem::new(line).style(style)
        })
        .collect();

    let bookmark_info = if app.show_bookmarks_only {
        format!(" [BOOKMARKS: {}] ", app.bookmarked_packets.len())
    } else {
        String::new()
    };

    let list = List::new(items).block(
        Block::default()
            .title(format!(
                " 🔍 Packets [{}/{}]{} (b: bookmark, B: filter bookmarks) ",
                app.selected_index + 1,
                app.filtered_count(),
                bookmark_info,
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(list, area);
}

fn render_packet_detail(f: &mut Frame, app: &App, area: Rect) {
    let detail_text = if let Some(pkt) = app.selected_packet() {
        let mut lines = vec![
            Line::from(Span::styled(
                " ── General ──",
                Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
            )),
            Line::from(format!("  ID:        {}", pkt.id)),
            Line::from(format!(
                "  Time:      {}",
                pkt.timestamp.format("%Y-%m-%d %H:%M:%S%.6f")
            )),
            Line::from(format!("  Interface: {}", pkt.interface)),
            Line::from(format!("  Direction: {}", pkt.direction)),
            Line::from(format!("  Length:    {} bytes", pkt.length)),
            Line::from(format!("  Protocol:  {}", pkt.protocol)),
            Line::from(format!(
                "  Bookmarked: {}",
                if app.is_bookmarked(pkt.id) { "★ Yes" } else { "No" }
            )),
            Line::from(""),
        ];

        // GeoIP info
        if let Some(geo_src) = app.lookup_geo(&pkt.source) {
            lines.push(Line::from(Span::styled(
                " ── GeoIP ──",
                Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  Source:      {}", geo_src)));
            if let Some(geo_dst) = app.lookup_geo(&pkt.destination) {
                lines.push(Line::from(format!("  Destination: {}", geo_dst)));
            }
            lines.push(Line::from(""));
        } else if let Some(geo_dst) = app.lookup_geo(&pkt.destination) {
            lines.push(Line::from(Span::styled(
                " ── GeoIP ──",
                Style::default().fg(Color::Blue).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  Destination: {}", geo_dst)));
            lines.push(Line::from(""));
        }

        if let Some(ref link) = pkt.layers.link {
            lines.push(Line::from(Span::styled(
                " ── Link Layer ──",
                Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  {}", link)));
            lines.push(Line::from(""));
        }

        if let Some(ref network) = pkt.layers.network {
            lines.push(Line::from(Span::styled(
                " ── Network Layer ──",
                Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  {}", network)));
            lines.push(Line::from(""));
        }

        if let Some(ref transport) = pkt.layers.transport {
            lines.push(Line::from(Span::styled(
                " ── Transport Layer ──",
                Style::default()
                    .fg(Color::Magenta)
                    .add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  {}", transport)));
            lines.push(Line::from(""));
        }

        if let Some(ref app_layer) = pkt.layers.application {
            lines.push(Line::from(Span::styled(
                " ── Application Layer ──",
                Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
            )));
            lines.push(Line::from(format!("  {}", app_layer)));
            lines.push(Line::from(""));
        }

        lines.push(Line::from(Span::styled(
            " ── Hex Dump ──",
            Style::default()
                .fg(Color::DarkGray)
                .add_modifier(Modifier::BOLD),
        )));
        for hex_line in pkt.hex_dump().lines() {
            lines.push(Line::from(Span::styled(
                format!("  {}", hex_line),
                Style::default().fg(Color::DarkGray),
            )));
        }

        lines
    } else {
        vec![Line::from("  No packet selected")]
    };

    let paragraph = Paragraph::new(detail_text)
        .wrap(Wrap { trim: false })
        .block(
            Block::default()
                .title(" 📄 Packet Detail ")
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        );

    f.render_widget(paragraph, area);
}

fn truncate_str(s: &str, max_len: usize) -> String {
    if s.len() > max_len {
        format!("{}…", &s[..max_len - 1])
    } else {
        format!("{:<width$}", s, width = max_len)
    }
}