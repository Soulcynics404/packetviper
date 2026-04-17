use ratatui::Frame;
use ratatui::layout::Rect;
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};

use crate::app::App;

pub fn render(f: &mut Frame, _app: &App, area: Rect) {
    let help_text = vec![
        Line::from(""),
        Line::from(Span::styled(
            "  ── Navigation ──",
            Style::default().fg(Color::Green).add_modifier(Modifier::BOLD),
        )),
        Line::from("   Tab / Shift+Tab    Switch between tabs"),
        Line::from("   j / ↓              Scroll down"),
        Line::from("   k / ↑              Scroll up"),
        Line::from("   g                  Go to first packet"),
        Line::from("   G                  Go to last packet"),
        Line::from("   Enter              Toggle packet detail view"),
        Line::from("   a                  Toggle auto-scroll"),
        Line::from(""),
        Line::from(Span::styled(
            "  ── Capture ──",
            Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD),
        )),
        Line::from("   c                  Start/Stop capture"),
        Line::from("   /                  Open filter input"),
        Line::from("   x                  Clear current filter"),
        Line::from(""),
        Line::from(Span::styled(
            "  ── Bookmarks ──",
            Style::default().fg(Color::Yellow).add_modifier(Modifier::BOLD),
        )),
        Line::from("   b                  Toggle bookmark on selected packet"),
        Line::from("   B                  Show only bookmarked packets"),
        Line::from(""),
        Line::from(Span::styled(
            "  ── Export ──",
            Style::default().fg(Color::Magenta).add_modifier(Modifier::BOLD),
        )),
        Line::from("   e                  Export to JSON"),
        Line::from("   E                  Export to CSV"),
        Line::from("   p                  Export to PCAP"),
        Line::from(""),
        Line::from(Span::styled(
            "  ── Filter Examples ──",
            Style::default().fg(Color::Red).add_modifier(Modifier::BOLD),
        )),
        Line::from("   tcp                         All TCP traffic"),
        Line::from("   dns || http                 DNS or HTTP"),
        Line::from("   port == 443                 Port 443"),
        Line::from("   ip == 192.168.1.1           Specific IP"),
        Line::from("   len > 1000                  Large packets"),
        Line::from("   tcp && port 80..443         TCP on port range"),
        Line::from("   !arp                        Exclude ARP"),
        Line::from("   contains \"google\"           Text search"),
        Line::from(""),
        Line::from(Span::styled(
            "  ── About ──",
            Style::default().fg(Color::White).add_modifier(Modifier::BOLD),
        )),
        Line::from("   PacketViper v0.1.0"),
        Line::from("   Network Traffic Analyzer + Threat Detector"),
        Line::from("   Rust + Ratatui + pnet + GeoIP"),
        Line::from("   Author: Harsshh (github.com/Soulcynics404)"),
        Line::from(""),
    ];

    let paragraph = Paragraph::new(help_text).block(
        Block::default()
            .title(" ❓ Help ")
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Green)),
    );

    f.render_widget(paragraph, area);
}