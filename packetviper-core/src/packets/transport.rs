//! Transport Layer (Layer 4) packet structures

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransportLayerInfo {
    Tcp(TcpInfo),
    Udp(UdpInfo),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub seq_number: u32,
    pub ack_number: u32,
    pub flags: TcpFlags,
    pub window_size: u16,
    pub header_length: u8,
    pub urgent_pointer: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpFlags {
    pub syn: bool,
    pub ack: bool,
    pub fin: bool,
    pub rst: bool,
    pub psh: bool,
    pub urg: bool,
    pub ece: bool,
    pub cwr: bool,
}

impl std::fmt::Display for TcpFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        if self.syn { flags.push("SYN"); }
        if self.ack { flags.push("ACK"); }
        if self.fin { flags.push("FIN"); }
        if self.rst { flags.push("RST"); }
        if self.psh { flags.push("PSH"); }
        if self.urg { flags.push("URG"); }
        if self.ece { flags.push("ECE"); }
        if self.cwr { flags.push("CWR"); }
        write!(f, "[{}]", flags.join(","))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UdpInfo {
    pub src_port: u16,
    pub dst_port: u16,
    pub length: u16,
    pub checksum: u16,
}

impl std::fmt::Display for TransportLayerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TransportLayerInfo::Tcp(tcp) => {
                write!(f, "TCP {} -> {} {}", tcp.src_port, tcp.dst_port, tcp.flags)
            }
            TransportLayerInfo::Udp(udp) => {
                write!(f, "UDP {} -> {} (len:{})", udp.src_port, udp.dst_port, udp.length)
            }
        }
    }
}