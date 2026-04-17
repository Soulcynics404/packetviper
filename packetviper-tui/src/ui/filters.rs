use ratatui::Frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

pub fn render(f: &mut Frame, app: &App, area: Rect) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),  // Current filter
            Constraint::Length(14), // Filter input
            Constraint::Min(8),    // Help / Examples
        ])
        .split(area);

    // Current filter status
    let current_filter = if app.filter_engine.expression().is_empty() {
        Span::styled("  None (showing all packets)", Style::default().fg(Color::DarkGray))
    } else {
        Span::styled(
            format!("  {}", app.filter_engine.expression()),
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )
    };

    let filter_status = Paragraph::new(vec![
        Line::from(""),
        Line::from(current_filter),
        Line::from(""),
    ])
    .block(
        Block::default()
            .title(format!(
                " 🔧 Active Filter (matched: {}/{}) ",
                app.filtered_count(),
                app.packet_count(),
            ))
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(filter_status, chunks[0]);

    // Filter input area
    let input_text = if app.filter_input_active {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  ▸ Type your filter expression:",
                Style::default().fg(Color::Yellow),
            )),
            Line::from(""),
            Line::from(Span::styled(
                format!("    {}█", app.filter_input),
                Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(Span::styled(
                "  Enter: apply | Esc: cancel",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    } else {
        vec![
            Line::from(""),
            Line::from(Span::styled(
                "  Press '/' to enter a filter expression",
                Style::default().fg(Color::DarkGray),
            )),
            Line::from(Span::styled(
                "  Press 'x' to clear current filter",
                Style::default().fg(Color::DarkGray),
            )),
        ]
    };

    let border_color = if app.filter_input_active {
        Color::Yellow
    } else {
        Color::Green
    };

    let input_box = Paragraph::new(input_text).block(
        Block::default()
            .title(" ✏️  Filter Input ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(border_color)),
    );

    f.render_widget(input_box, chunks[1]);

    // Filter DSL examples
    let examples = vec![
        Line::from(""),
        Line::from(Span::styled(
            " ── Protocol Filters ──",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from("   tcp                       All TCP packets (includes HTTP, TLS, SSH)"),
        Line::from("   udp                       All UDP packets (includes DNS, DHCP)"),
        Line::from("   dns                       DNS packets only"),
        Line::from("   http || tls               HTTP or TLS traffic"),
        Line::from("   arp                       ARP packets"),
        Line::from("   icmp                      ICMP packets"),
        Line::from(""),
        Line::from(Span::styled(
            " ── Field Filters ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from("   ip == 192.168.1.1         Source IP matches"),
        Line::from("   dst == 8.8.8.8            Destination IP"),
        Line::from("   port == 443               Source or destination port"),
        Line::from("   sport == 80               Source port only"),
        Line::from("   dport == 53               Destination port only"),
        Line::from("   port 80..443              Port range"),
        Line::from("   len > 1000                Packet size > 1000 bytes"),
        Line::from("   ttl < 64                  TTL less than 64"),
        Line::from("   direction == in            Incoming packets only"),
        Line::from(""),
        Line::from(Span::styled(
            " ── Compound Filters ──",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from("   tcp && port == 443        TCP on port 443"),
        Line::from("   dns || http               DNS or HTTP"),
        Line::from("   !arp                      Everything except ARP"),
        Line::from("   tcp && len > 500 && dst == 10.0.0.1"),
        Line::from("   (http || dns) && direction == out"),
        Line::from("   contains \"google\"         Packets mentioning google"),
    ];

    let help_box = Paragraph::new(examples).block(
        Block::default()
            .title(" 📖 Filter DSL Reference ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(help_box, chunks[2]);
}