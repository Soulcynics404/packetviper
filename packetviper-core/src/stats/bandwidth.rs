//! Bandwidth monitoring and traffic statistics

use std::collections::HashMap;
use crate::packets::CapturedPacket;
use serde::{Deserialize, Serialize};

/// Stats snapshot for display
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct TrafficStats {
    pub total_packets: u64,
    pub total_bytes: u64,
    pub protocol_counts: HashMap<String, u64>,
    pub protocol_bytes: HashMap<String, u64>,
    pub top_sources: Vec<(String, u64)>,
    pub top_destinations: Vec<(String, u64)>,
    pub top_conversations: Vec<(String, String, u64)>,
    pub packets_per_second: f64,
    pub bytes_per_second: f64,
    /// Last N bytes-per-second samples for sparkline
    pub bandwidth_history: Vec<u64>,
    pub tcp_flags_count: HashMap<String, u64>,
    pub avg_packet_size: f64,
    pub incoming_bytes: u64,
    pub outgoing_bytes: u64,
}

pub struct BandwidthMonitor {
    source_counts: HashMap<String, u64>,
    dest_counts: HashMap<String, u64>,
    conversation_counts: HashMap<(String, String), u64>,
    protocol_counts: HashMap<String, u64>,
    protocol_bytes: HashMap<String, u64>,
    tcp_flags_count: HashMap<String, u64>,
    total_packets: u64,
    total_bytes: u64,
    incoming_bytes: u64,
    outgoing_bytes: u64,
    bandwidth_history: Vec<u64>,
    last_tick_bytes: u64,
    last_tick_time: std::time::Instant,
    start_time: std::time::Instant,
}

impl BandwidthMonitor {
    pub fn new() -> Self {
        let now = std::time::Instant::now();
        Self {
            source_counts: HashMap::new(),
            dest_counts: HashMap::new(),
            conversation_counts: HashMap::new(),
            protocol_counts: HashMap::new(),
            protocol_bytes: HashMap::new(),
            tcp_flags_count: HashMap::new(),
            total_packets: 0,
            total_bytes: 0,
            incoming_bytes: 0,
            outgoing_bytes: 0,
            bandwidth_history: Vec::new(),
            last_tick_bytes: 0,
            last_tick_time: now,
            start_time: now,
        }
    }

    /// Record a new packet
    pub fn record_packet(&mut self, packet: &CapturedPacket) {
        self.total_packets += 1;
        self.total_bytes += packet.length as u64;

        // Protocol stats
        *self.protocol_counts.entry(packet.protocol.clone()).or_insert(0) += 1;
        *self.protocol_bytes.entry(packet.protocol.clone()).or_insert(0) += packet.length as u64;

        // Source/dest tracking (use IP without port)
        let src = Self::extract_ip(&packet.source);
        let dst = Self::extract_ip(&packet.destination);
        *self.source_counts.entry(src.clone()).or_insert(0) += 1;
        *self.dest_counts.entry(dst.clone()).or_insert(0) += 1;

        // Conversation tracking
        let conv_key = if src < dst {
            (src, dst)
        } else {
            (dst, src)
        };
        *self.conversation_counts.entry(conv_key).or_insert(0) += 1;

        // Direction bytes
        match &packet.direction {
            crate::packets::PacketDirection::Incoming => {
                self.incoming_bytes += packet.length as u64;
            }
            crate::packets::PacketDirection::Outgoing => {
                self.outgoing_bytes += packet.length as u64;
            }
            _ => {}
        }

        // TCP flags
        if let Some(ref transport) = packet.layers.transport {
            if let crate::packets::transport::TransportLayerInfo::Tcp(ref tcp) = transport {
                if tcp.flags.syn && !tcp.flags.ack {
                    *self.tcp_flags_count.entry("SYN".to_string()).or_insert(0) += 1;
                }
                if tcp.flags.syn && tcp.flags.ack {
                    *self.tcp_flags_count.entry("SYN-ACK".to_string()).or_insert(0) += 1;
                }
                if tcp.flags.fin {
                    *self.tcp_flags_count.entry("FIN".to_string()).or_insert(0) += 1;
                }
                if tcp.flags.rst {
                    *self.tcp_flags_count.entry("RST".to_string()).or_insert(0) += 1;
                }
                if tcp.flags.ack && !tcp.flags.syn && !tcp.flags.fin && !tcp.flags.rst {
                    *self.tcp_flags_count.entry("ACK".to_string()).or_insert(0) += 1;
                }
                if tcp.flags.psh {
                    *self.tcp_flags_count.entry("PSH".to_string()).or_insert(0) += 1;
                }
            }
        }
    }

    /// Call this periodically (e.g., every second) to update bandwidth history
    pub fn tick(&mut self) {
        let now = std::time::Instant::now();
        let elapsed = now.duration_since(self.last_tick_time).as_secs_f64();

        if elapsed >= 1.0 {
            let bytes_this_tick = self.total_bytes - self.last_tick_bytes;
            let bps = (bytes_this_tick as f64 / elapsed) as u64;
            self.bandwidth_history.push(bps);

            // Keep last 60 samples (1 minute of data)
            if self.bandwidth_history.len() > 60 {
                self.bandwidth_history.remove(0);
            }

            self.last_tick_bytes = self.total_bytes;
            self.last_tick_time = now;
        }
    }

    /// Generate a stats snapshot for display
    pub fn snapshot(&self) -> TrafficStats {
        let elapsed = self.start_time.elapsed().as_secs_f64().max(1.0);

        let mut top_sources: Vec<(String, u64)> = self.source_counts.clone().into_iter().collect();
        top_sources.sort_by(|a, b| b.1.cmp(&a.1));
        top_sources.truncate(10);

        let mut top_destinations: Vec<(String, u64)> =
            self.dest_counts.clone().into_iter().collect();
        top_destinations.sort_by(|a, b| b.1.cmp(&a.1));
        top_destinations.truncate(10);

        let mut top_conversations: Vec<(String, String, u64)> = self
            .conversation_counts
            .iter()
            .map(|((s, d), c)| (s.clone(), d.clone(), *c))
            .collect();
        top_conversations.sort_by(|a, b| b.2.cmp(&a.2));
        top_conversations.truncate(10);

        TrafficStats {
            total_packets: self.total_packets,
            total_bytes: self.total_bytes,
            protocol_counts: self.protocol_counts.clone(),
            protocol_bytes: self.protocol_bytes.clone(),
            top_sources,
            top_destinations,
            top_conversations,
            packets_per_second: self.total_packets as f64 / elapsed,
            bytes_per_second: self.total_bytes as f64 / elapsed,
            bandwidth_history: self.bandwidth_history.clone(),
            tcp_flags_count: self.tcp_flags_count.clone(),
            avg_packet_size: if self.total_packets > 0 {
                self.total_bytes as f64 / self.total_packets as f64
            } else {
                0.0
            },
            incoming_bytes: self.incoming_bytes,
            outgoing_bytes: self.outgoing_bytes,
        }
    }

    fn extract_ip(addr: &str) -> String {
        if let Some(last_colon) = addr.rfind(':') {
            let potential_port = &addr[last_colon + 1..];
            if potential_port.parse::<u16>().is_ok() {
                let colon_count = addr.matches(':').count();
                if colon_count == 1 {
                    return addr[..last_colon].to_string();
                }
            }
        }
        addr.to_string()
    }
}