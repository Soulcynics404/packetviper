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
        if let Some(ref transport) = packet.layers.transport {
            match transport {
                TransportLayerInfo::Tcp(tcp) => {
                    let src_ip = Self::extract_ip(&packet.source);
                    let dst_ip = Self::extract_ip(&packet.destination);
                    let key = Connection::key(
                        &src_ip,
                        tcp.src_port,
                        &dst_ip,
                        tcp.dst_port,
                    );

                    let is_forward = (src_ip.as_str(), tcp.src_port)
                        < (dst_ip.as_str(), tcp.dst_port);

                    let conn = self
                        .connections
                        .entry(key)
                        .or_insert_with(|| Connection {
                            src_ip: if is_forward {
                                src_ip.clone()
                            } else {
                                dst_ip.clone()
                            },
                            src_port: if is_forward {
                                tcp.src_port
                            } else {
                                tcp.dst_port
                            },
                            dst_ip: if is_forward {
                                dst_ip.clone()
                            } else {
                                src_ip.clone()
                            },
                            dst_port: if is_forward {
                                tcp.dst_port
                            } else {
                                tcp.src_port
                            },
                            state: ConnectionState::SynSent,
                            packets_sent: 0,
                            packets_recv: 0,
                            bytes_sent: 0,
                            bytes_recv: 0,
                            start_time: packet.timestamp,
                            last_seen: packet.timestamp,
                            protocol: packet.protocol.clone(),
                        });

                    // Update counts
                    if is_forward {
                        conn.packets_sent += 1;
                        conn.bytes_sent += packet.length as u64;
                    } else {
                        conn.packets_recv += 1;
                        conn.bytes_recv += packet.length as u64;
                    }
                    conn.last_seen = packet.timestamp;

                    // Update state machine
                    if tcp.flags.syn && !tcp.flags.ack {
                        conn.state = ConnectionState::SynSent;
                    } else if tcp.flags.syn && tcp.flags.ack {
                        conn.state = ConnectionState::SynAckReceived;
                    } else if tcp.flags.ack
                        && !tcp.flags.syn
                        && !tcp.flags.fin
                        && !tcp.flags.rst
                    {
                        if conn.state == ConnectionState::SynAckReceived
                            || conn.state == ConnectionState::SynSent
                        {
                            conn.state = ConnectionState::Established;
                        }
                    } else if tcp.flags.fin {
                        conn.state = ConnectionState::FinWait;
                    } else if tcp.flags.rst {
                        conn.state = ConnectionState::Reset;
                    }

                    // Update protocol if app-layer detected
                    if packet.protocol != "TCP" {
                        conn.protocol = packet.protocol.clone();
                    }
                }
                TransportLayerInfo::Udp(udp) => {
                    let src_ip = Self::extract_ip(&packet.source);
                    let dst_ip = Self::extract_ip(&packet.destination);
                    let key = Connection::key(
                        &src_ip,
                        udp.src_port,
                        &dst_ip,
                        udp.dst_port,
                    );

                    let is_forward = (src_ip.as_str(), udp.src_port)
                        < (dst_ip.as_str(), udp.dst_port);

                    let conn = self
                        .connections
                        .entry(key)
                        .or_insert_with(|| Connection {
                            src_ip: if is_forward {
                                src_ip.clone()
                            } else {
                                dst_ip.clone()
                            },
                            src_port: if is_forward {
                                udp.src_port
                            } else {
                                udp.dst_port
                            },
                            dst_ip: if is_forward {
                                dst_ip.clone()
                            } else {
                                src_ip.clone()
                            },
                            dst_port: if is_forward {
                                udp.dst_port
                            } else {
                                udp.src_port
                            },
                            state: ConnectionState::Established,
                            packets_sent: 0,
                            packets_recv: 0,
                            bytes_sent: 0,
                            bytes_recv: 0,
                            start_time: packet.timestamp,
                            last_seen: packet.timestamp,
                            protocol: packet.protocol.clone(),
                        });

                    if is_forward {
                        conn.packets_sent += 1;
                        conn.bytes_sent += packet.length as u64;
                    } else {
                        conn.packets_recv += 1;
                        conn.bytes_recv += packet.length as u64;
                    }
                    conn.last_seen = packet.timestamp;

                    if packet.protocol != "UDP" {
                        conn.protocol = packet.protocol.clone();
                    }
                }
            }
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

    fn extract_ip(addr: &str) -> String {
        if let Some(last_colon) = addr.rfind(':') {
            let after = &addr[last_colon + 1..];
            if after.parse::<u16>().is_ok() {
                let colon_count = addr.matches(':').count();
                if colon_count == 1 {
                    return addr[..last_colon].to_string();
                }
            }
        }
        addr.to_string()
    }
}