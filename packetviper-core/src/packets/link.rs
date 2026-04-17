//! Link Layer (Layer 2) packet structures

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LinkLayerInfo {
    Ethernet(EthernetInfo),
    Arp(ArpInfo),
    Unknown { ethertype: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EthernetInfo {
    pub src_mac: String,
    pub dst_mac: String,
    pub ethertype: u16,
    pub ethertype_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArpInfo {
    pub operation: String,       // "Request" or "Reply"
    pub sender_mac: String,
    pub sender_ip: String,
    pub target_mac: String,
    pub target_ip: String,
}

impl std::fmt::Display for LinkLayerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkLayerInfo::Ethernet(eth) => {
                write!(f, "Ethernet {} -> {} ({})", eth.src_mac, eth.dst_mac, eth.ethertype_name)
            }
            LinkLayerInfo::Arp(arp) => {
                write!(f, "ARP {} {} -> {}", arp.operation, arp.sender_ip, arp.target_ip)
            }
            LinkLayerInfo::Unknown { ethertype } => {
                write!(f, "Unknown EtherType: 0x{:04x}", ethertype)
            }
        }
    }
}