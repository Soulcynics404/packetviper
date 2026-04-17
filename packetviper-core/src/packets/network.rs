//! Network Layer (Layer 3) packet structures

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum NetworkLayerInfo {
    IPv4(IPv4Info),
    IPv6(IPv6Info),
    Icmp(IcmpInfo),
    Icmpv6(Icmpv6Info),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPv4Info {
    pub src_ip: String,
    pub dst_ip: String,
    pub ttl: u8,
    pub protocol: u8,
    pub protocol_name: String,
    pub header_length: u8,
    pub total_length: u16,
    pub flags: u8,
    pub dscp: u8,
    pub identification: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IPv6Info {
    pub src_ip: String,
    pub dst_ip: String,
    pub hop_limit: u8,
    pub next_header: u8,
    pub traffic_class: u8,
    pub flow_label: u32,
    pub payload_length: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IcmpInfo {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub type_name: String,
    pub src_ip: String,
    pub dst_ip: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Icmpv6Info {
    pub icmp_type: u8,
    pub icmp_code: u8,
    pub type_name: String,
    pub src_ip: String,
    pub dst_ip: String,
}

impl std::fmt::Display for NetworkLayerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            NetworkLayerInfo::IPv4(ip) => {
                write!(f, "IPv4 {} -> {} (TTL:{}, Proto:{})",
                    ip.src_ip, ip.dst_ip, ip.ttl, ip.protocol_name)
            }
            NetworkLayerInfo::IPv6(ip) => {
                write!(f, "IPv6 {} -> {} (Hop:{})",
                    ip.src_ip, ip.dst_ip, ip.hop_limit)
            }
            NetworkLayerInfo::Icmp(icmp) => {
                write!(f, "ICMP {} ({}) {} -> {}",
                    icmp.type_name, icmp.icmp_type, icmp.src_ip, icmp.dst_ip)
            }
            NetworkLayerInfo::Icmpv6(icmp) => {
                write!(f, "ICMPv6 {} ({}) {} -> {}",
                    icmp.type_name, icmp.icmp_type, icmp.src_ip, icmp.dst_ip)
            }
        }
    }
}