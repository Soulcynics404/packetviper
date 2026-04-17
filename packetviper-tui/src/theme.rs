//! Color themes for PacketViper TUI

use ratatui::style::Color;

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ThemeName {
    Cyberpunk,
    Ocean,
    Matrix,
    Dracula,
    Solarized,
}

impl ThemeName {
    pub fn all() -> Vec<ThemeName> {
        vec![
            ThemeName::Cyberpunk,
            ThemeName::Ocean,
            ThemeName::Matrix,
            ThemeName::Dracula,
            ThemeName::Solarized,
        ]
    }

    pub fn name(&self) -> &str {
        match self {
            ThemeName::Cyberpunk => "Cyberpunk",
            ThemeName::Ocean => "Ocean",
            ThemeName::Matrix => "Matrix",
            ThemeName::Dracula => "Dracula",
            ThemeName::Solarized => "Solarized",
        }
    }

    pub fn next(&self) -> Self {
        match self {
            ThemeName::Cyberpunk => ThemeName::Ocean,
            ThemeName::Ocean => ThemeName::Matrix,
            ThemeName::Matrix => ThemeName::Dracula,
            ThemeName::Dracula => ThemeName::Solarized,
            ThemeName::Solarized => ThemeName::Cyberpunk,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub name: ThemeName,
    pub border: Color,
    pub border_highlight: Color,
    pub title: Color,
    pub text: Color,
    pub text_dim: Color,
    pub accent1: Color,
    pub accent2: Color,
    pub accent3: Color,
    pub proto_tcp: Color,
    pub proto_udp: Color,
    pub proto_icmp: Color,
    pub proto_dns: Color,
    pub proto_http: Color,
    pub proto_tls: Color,
    pub proto_arp: Color,
    pub proto_ssh: Color,
    pub selected_bg: Color,
    pub selected_fg: Color,
    pub capture_active: Color,
    pub capture_stopped: Color,
    pub threat_critical: Color,
    pub threat_high: Color,
    pub threat_medium: Color,
    pub threat_low: Color,
    pub bookmark: Color,
}

impl Theme {
    pub fn from_name(name: ThemeName) -> Self {
        match name {
            ThemeName::Cyberpunk => Self::cyberpunk(),
            ThemeName::Ocean => Self::ocean(),
            ThemeName::Matrix => Self::matrix(),
            ThemeName::Dracula => Self::dracula(),
            ThemeName::Solarized => Self::solarized(),
        }
    }

    pub fn proto_color(&self, protocol: &str) -> Color {
        match protocol {
            "TCP" => self.proto_tcp,
            "UDP" => self.proto_udp,
            "ICMP" | "ICMPv6" => self.proto_icmp,
            "DNS" => self.proto_dns,
            "HTTP" => self.proto_http,
            "TLS" => self.proto_tls,
            "ARP" => self.proto_arp,
            "SSH" => self.proto_ssh,
            _ => self.text,
        }
    }

    fn cyberpunk() -> Self {
        Self {
            name: ThemeName::Cyberpunk,
            border: Color::Green,
            border_highlight: Color::LightGreen,
            title: Color::Green,
            text: Color::White,
            text_dim: Color::DarkGray,
            accent1: Color::Cyan,
            accent2: Color::Magenta,
            accent3: Color::Yellow,
            proto_tcp: Color::Cyan,
            proto_udp: Color::Yellow,
            proto_icmp: Color::Green,
            proto_dns: Color::Magenta,
            proto_http: Color::Blue,
            proto_tls: Color::Red,
            proto_arp: Color::LightYellow,
            proto_ssh: Color::LightRed,
            selected_bg: Color::DarkGray,
            selected_fg: Color::White,
            capture_active: Color::Red,
            capture_stopped: Color::DarkGray,
            threat_critical: Color::Red,
            threat_high: Color::LightRed,
            threat_medium: Color::Yellow,
            threat_low: Color::Blue,
            bookmark: Color::Yellow,
        }
    }

    fn ocean() -> Self {
        Self {
            name: ThemeName::Ocean,
            border: Color::Rgb(100, 149, 237),    // Cornflower blue
            border_highlight: Color::Rgb(135, 206, 250), // Light sky blue
            title: Color::Rgb(100, 149, 237),
            text: Color::Rgb(230, 230, 250),       // Lavender
            text_dim: Color::Rgb(119, 136, 153),   // Light slate gray
            accent1: Color::Rgb(0, 206, 209),      // Dark turquoise
            accent2: Color::Rgb(127, 255, 212),    // Aquamarine
            accent3: Color::Rgb(255, 215, 0),      // Gold
            proto_tcp: Color::Rgb(0, 206, 209),
            proto_udp: Color::Rgb(255, 215, 0),
            proto_icmp: Color::Rgb(127, 255, 212),
            proto_dns: Color::Rgb(186, 85, 211),
            proto_http: Color::Rgb(100, 149, 237),
            proto_tls: Color::Rgb(255, 99, 71),
            proto_arp: Color::Rgb(255, 255, 100),
            proto_ssh: Color::Rgb(255, 160, 122),
            selected_bg: Color::Rgb(25, 25, 112),
            selected_fg: Color::White,
            capture_active: Color::Rgb(255, 69, 0),
            capture_stopped: Color::Rgb(119, 136, 153),
            threat_critical: Color::Rgb(255, 0, 0),
            threat_high: Color::Rgb(255, 99, 71),
            threat_medium: Color::Rgb(255, 215, 0),
            threat_low: Color::Rgb(100, 149, 237),
            bookmark: Color::Rgb(255, 215, 0),
        }
    }

    fn matrix() -> Self {
        Self {
            name: ThemeName::Matrix,
            border: Color::Rgb(0, 255, 0),
            border_highlight: Color::Rgb(50, 255, 50),
            title: Color::Rgb(0, 255, 0),
            text: Color::Rgb(0, 200, 0),
            text_dim: Color::Rgb(0, 100, 0),
            accent1: Color::Rgb(0, 255, 0),
            accent2: Color::Rgb(100, 255, 100),
            accent3: Color::Rgb(200, 255, 200),
            proto_tcp: Color::Rgb(0, 255, 0),
            proto_udp: Color::Rgb(100, 255, 100),
            proto_icmp: Color::Rgb(0, 200, 0),
            proto_dns: Color::Rgb(150, 255, 150),
            proto_http: Color::Rgb(0, 180, 0),
            proto_tls: Color::Rgb(200, 255, 200),
            proto_arp: Color::Rgb(50, 255, 50),
            proto_ssh: Color::Rgb(0, 150, 0),
            selected_bg: Color::Rgb(0, 80, 0),
            selected_fg: Color::Rgb(0, 255, 0),
            capture_active: Color::Rgb(255, 0, 0),
            capture_stopped: Color::Rgb(0, 100, 0),
            threat_critical: Color::Rgb(255, 0, 0),
            threat_high: Color::Rgb(255, 100, 0),
            threat_medium: Color::Rgb(255, 255, 0),
            threat_low: Color::Rgb(0, 150, 0),
            bookmark: Color::Rgb(255, 255, 0),
        }
    }

    fn dracula() -> Self {
        Self {
            name: ThemeName::Dracula,
            border: Color::Rgb(189, 147, 249),    // Purple
            border_highlight: Color::Rgb(255, 121, 198), // Pink
            title: Color::Rgb(189, 147, 249),
            text: Color::Rgb(248, 248, 242),       // Foreground
            text_dim: Color::Rgb(98, 114, 164),    // Comment
            accent1: Color::Rgb(139, 233, 253),    // Cyan
            accent2: Color::Rgb(255, 121, 198),    // Pink
            accent3: Color::Rgb(241, 250, 140),    // Yellow
            proto_tcp: Color::Rgb(139, 233, 253),
            proto_udp: Color::Rgb(241, 250, 140),
            proto_icmp: Color::Rgb(80, 250, 123),
            proto_dns: Color::Rgb(255, 121, 198),
            proto_http: Color::Rgb(189, 147, 249),
            proto_tls: Color::Rgb(255, 85, 85),
            proto_arp: Color::Rgb(255, 184, 108),
            proto_ssh: Color::Rgb(255, 85, 85),
            selected_bg: Color::Rgb(68, 71, 90),
            selected_fg: Color::Rgb(248, 248, 242),
            capture_active: Color::Rgb(255, 85, 85),
            capture_stopped: Color::Rgb(98, 114, 164),
            threat_critical: Color::Rgb(255, 85, 85),
            threat_high: Color::Rgb(255, 184, 108),
            threat_medium: Color::Rgb(241, 250, 140),
            threat_low: Color::Rgb(139, 233, 253),
            bookmark: Color::Rgb(241, 250, 140),
        }
    }

    fn solarized() -> Self {
        Self {
            name: ThemeName::Solarized,
            border: Color::Rgb(38, 139, 210),      // Blue
            border_highlight: Color::Rgb(42, 161, 152), // Cyan
            title: Color::Rgb(38, 139, 210),
            text: Color::Rgb(131, 148, 150),        // Base0
            text_dim: Color::Rgb(88, 110, 117),     // Base01
            accent1: Color::Rgb(42, 161, 152),      // Cyan
            accent2: Color::Rgb(211, 54, 130),      // Magenta
            accent3: Color::Rgb(181, 137, 0),       // Yellow
            proto_tcp: Color::Rgb(42, 161, 152),
            proto_udp: Color::Rgb(181, 137, 0),
            proto_icmp: Color::Rgb(133, 153, 0),
            proto_dns: Color::Rgb(211, 54, 130),
            proto_http: Color::Rgb(38, 139, 210),
            proto_tls: Color::Rgb(220, 50, 47),
            proto_arp: Color::Rgb(203, 75, 22),
            proto_ssh: Color::Rgb(220, 50, 47),
            selected_bg: Color::Rgb(7, 54, 66),
            selected_fg: Color::Rgb(238, 232, 213),
            capture_active: Color::Rgb(220, 50, 47),
            capture_stopped: Color::Rgb(88, 110, 117),
            threat_critical: Color::Rgb(220, 50, 47),
            threat_high: Color::Rgb(203, 75, 22),
            threat_medium: Color::Rgb(181, 137, 0),
            threat_low: Color::Rgb(38, 139, 210),
            bookmark: Color::Rgb(181, 137, 0),
        }
    }
}