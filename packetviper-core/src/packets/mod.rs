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