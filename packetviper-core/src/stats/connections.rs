//! TCP Connection tracking — monitors connection states

use std::collections::HashMap;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

use crate::packets::CapturedPacket;
use crate::packets::transport::TransportLayerInfo;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ConnectionState {
    SynSent,
    SynAckReceived,
    Established,
    FinWait,
    Closed,
    Reset,
}

impl std::fmt::Display for ConnectionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectionState::SynSent => write!(f, "SYN_SENT"),
            ConnectionState::SynAckReceived => write!(f, "SYN_ACK"),
            ConnectionState::Established => write!(f, "ESTABLISHED"),
            ConnectionState::FinWait => write!(f, "FIN_WAIT"),
            ConnectionState::Closed => write!(f, "CLOSED"),
            ConnectionState::Reset => write!(f, "RESET"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub state: ConnectionState,
    pub packets_sent: u64,
    pub packets_recv: u64,
    pub bytes_sent: u64,
    pub bytes_recv: u64,
    pub start_time: DateTime<Local>,
    pub last_seen: DateTime<Local>,
    pub protocol: String,
}

impl Connection {
    pub fn key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> String {
        // Normalize key so both directions map to same connection
        if (src_ip, src_port) < (dst_ip, dst_port) {
            format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port)
        } else {
            format!("{}:{}-{}:{}", dst_ip, dst_port, src_ip, src_port)
        }
    }

    pub fn duration_secs(&self) -> f64 {
        self.last_seen
            .signed_duration_since(self.start_time)
            .num_milliseconds() as f64
            / 1000.0
    }

    pub fn total_bytes(&self) -> u64 {
        self.bytes_sent + self.bytes_recv
    }

    pub fn total_packets(&self) -> u64 {
        self.packets_sent + self.packets_recv
    }
}

/// Upper bound on tracked connections so spoofed-source floods can't grow memory without limit.
const MAX_CONNECTIONS: usize = 10_000;

pub struct ConnectionTracker {
    pub connections: HashMap<String, Connection>,
}

impl ConnectionTracker {
    pub fn new() -> Self {
        Self {
            connections: HashMap::new(),
        }
    }

    pub fn track_packet(&mut self, packet: &CapturedPacket) {
        let Some(transport) = &packet.layers.transport else { return };
        let (sport, dport, transport_name) = match transport {
            TransportLayerInfo::Tcp(t) => (t.src_port, t.dst_port, "TCP"),
            TransportLayerInfo::Udp(u) => (u.src_port, u.dst_port, "UDP"),
        };
        let src_ip = crate::packets::strip_port(&packet.source);
        let dst_ip = crate::packets::strip_port(&packet.destination);
        let key = Connection::key(src_ip, sport, dst_ip, dport);

        if !self.connections.contains_key(&key) && self.connections.len() >= MAX_CONNECTIONS {
            self.evict_idle(packet.timestamp);
        }

        let conn = self.connections.entry(key).or_insert_with(|| {
            // The initiator is the client. A SYN+ACK as the first packet seen means the sender is the server.
            let sender_is_server = matches!(transport, TransportLayerInfo::Tcp(t) if t.flags.syn && t.flags.ack);
            let (c_ip, c_port, s_ip, s_port) = if sender_is_server { (dst_ip, dport, src_ip, sport) } else { (src_ip, sport, dst_ip, dport) };
            Connection {
                src_ip: c_ip.to_string(),
                src_port: c_port,
                dst_ip: s_ip.to_string(),
                dst_port: s_port,
                state: if transport_name == "TCP" { ConnectionState::SynSent } else { ConnectionState::Established },
                packets_sent: 0,
                packets_recv: 0,
                bytes_sent: 0,
                bytes_recv: 0,
                start_time: packet.timestamp,
                last_seen: packet.timestamp,
                protocol: packet.protocol.clone(),
            }
        });

        // "sent" = client to server.
        if conn.src_ip == src_ip && conn.src_port == sport {
            conn.packets_sent += 1;
            conn.bytes_sent += packet.length as u64;
        } else {
            conn.packets_recv += 1;
            conn.bytes_recv += packet.length as u64;
        }
        conn.last_seen = packet.timestamp;

        if let TransportLayerInfo::Tcp(tcp) = transport {
            if tcp.flags.rst {
                conn.state = ConnectionState::Reset;
            } else if tcp.flags.fin {
                conn.state = ConnectionState::FinWait;
            } else if tcp.flags.syn && tcp.flags.ack {
                conn.state = ConnectionState::SynAckReceived;
            } else if tcp.flags.syn {
                conn.state = ConnectionState::SynSent;
            } else if tcp.flags.ack && matches!(conn.state, ConnectionState::SynSent | ConnectionState::SynAckReceived) {
                conn.state = ConnectionState::Established;
            }
        }

        // Update protocol if app-layer detected
        if packet.protocol != transport_name {
            conn.protocol = packet.protocol.clone();
        }
    }

    /// Drops connections idle for over 5 minutes; if still full, drops the least recently seen half.
    fn evict_idle(&mut self, now: DateTime<Local>) {
        self.connections.retain(|_, c| now.signed_duration_since(c.last_seen).num_seconds() < 300);
        if self.connections.len() >= MAX_CONNECTIONS {
            let mut seen: Vec<DateTime<Local>> = self.connections.values().map(|c| c.last_seen).collect();
            let mid = seen.len() / 2;
            let (_, cutoff, _) = seen.select_nth_unstable(mid);
            let cutoff = *cutoff;
            self.connections.retain(|_, c| c.last_seen > cutoff);
        }
    }

    /// Get active connections sorted by total bytes
    pub fn active_connections(&self) -> Vec<&Connection> {
        let mut conns: Vec<&Connection> = self.connections.values().collect();
        conns.sort_by(|a, b| b.total_bytes().cmp(&a.total_bytes()));
        conns
    }

    /// Count by state
    pub fn count_by_state(&self) -> HashMap<String, usize> {
        let mut counts = HashMap::new();
        for conn in self.connections.values() {
            *counts.entry(conn.state.to_string()).or_insert(0) += 1;
        }
        counts
    }

    /// Total active connections
    pub fn total(&self) -> usize {
        self.connections.len()
    }

}