//! Packet data structures representing captured network traffic.

pub mod link;
pub mod network;
pub mod transport;
pub mod application;

use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use link::LinkLayerInfo;
use network::NetworkLayerInfo;
use transport::TransportLayerInfo;
use application::AppLayerInfo;

/// Replaces control characters (ESC, CR, LF, ...) so packet-derived text can't drive the terminal.
pub fn sanitize(s: &str) -> String {
    s.chars().map(|c| if c.is_control() { '?' } else { c }).collect()
}

/// Strips the port from "1.2.3.4:80" or "[2001:db8::1]:80". Bare addresses (v4 or v6) are returned as-is.
pub fn strip_port(addr: &str) -> &str {
    if let Some(rest) = addr.strip_prefix('[') {
        return rest.split(']').next().unwrap_or(rest);
    }
    match addr.rsplit_once(':') {
        Some((ip, port)) if !ip.contains(':') && port.parse::<u16>().is_ok() => ip,
        _ => addr,
    }
}

/// Direction of packet flow
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum PacketDirection {
    Incoming,
    Outgoing,
    Unknown,
}

impl std::fmt::Display for PacketDirection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PacketDirection::Incoming => write!(f, "IN"),
            PacketDirection::Outgoing => write!(f, "OUT"),
            PacketDirection::Unknown => write!(f, "???"),
        }
    }
}

/// Information about each parsed layer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerInfo {
    pub link: Option<LinkLayerInfo>,
    pub network: Option<NetworkLayerInfo>,
    pub transport: Option<TransportLayerInfo>,
    pub application: Option<AppLayerInfo>,
}

/// A fully parsed captured packet
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapturedPacket {
    /// Unique packet ID
    pub id: u64,
    /// Timestamp of capture
    pub timestamp: DateTime<Local>,
    /// Total length in bytes
    pub length: usize,
    /// Interface it was captured on
    pub interface: String,
    /// Direction of the packet
    pub direction: PacketDirection,
    /// Parsed layer information
    pub layers: LayerInfo,
    /// Raw bytes (first 128 bytes for display)
    pub raw_preview: Vec<u8>,
    /// Summary string for quick display
    pub summary: String,
    /// Protocol name for display
    pub protocol: String,
    /// Source address (IP or MAC)
    pub source: String,
    /// Destination address (IP or MAC)
    pub destination: String,
}

impl CapturedPacket {
    /// Source IP from the network layer (no port), if the packet has one.
    pub fn src_ip(&self) -> Option<&str> {
        use network::NetworkLayerInfo::*;
        match self.layers.network.as_ref()? {
            IPv4(i) => Some(&i.src_ip),
            IPv6(i) => Some(&i.src_ip),
            Icmp(i) => Some(&i.src_ip),
            Icmpv6(i) => Some(&i.src_ip),
        }
    }

    /// Destination IP from the network layer (no port), if the packet has one.
    pub fn dst_ip(&self) -> Option<&str> {
        use network::NetworkLayerInfo::*;
        match self.layers.network.as_ref()? {
            IPv4(i) => Some(&i.dst_ip),
            IPv6(i) => Some(&i.dst_ip),
            Icmp(i) => Some(&i.dst_ip),
            Icmpv6(i) => Some(&i.dst_ip),
        }
    }

    /// Hex dump of raw_preview
    pub fn hex_dump(&self) -> String {
        self.raw_preview
            .chunks(16)
            .enumerate()
            .map(|(i, chunk)| {
                let hex: Vec<String> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
                let ascii: String = chunk
                    .iter()
                    .map(|b| {
                        if b.is_ascii_graphic() || *b == b' ' {
                            *b as char
                        } else {
                            '.'
                        }
                    })
                    .collect();
                format!("{:08x}  {:48}  |{}|", i * 16, hex.join(" "), ascii)
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strip_port_handles_v4_v6_and_bare() {
        assert_eq!(strip_port("1.2.3.4:80"), "1.2.3.4");
        assert_eq!(strip_port("1.2.3.4"), "1.2.3.4");
        assert_eq!(strip_port("[2001:db8::1]:443"), "2001:db8::1");
        assert_eq!(strip_port("2001:db8::1"), "2001:db8::1");
        assert_eq!(strip_port("fe80::1:80"), "fe80::1:80");
    }

    #[test]
    fn sanitize_replaces_control_chars() {
        assert_eq!(sanitize("a\x1b[2Jb\r\n"), "a?[2Jb??");
    }
}
