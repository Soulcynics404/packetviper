//! TCP Stream Reassembly — tracks and reconstructs TCP conversations

use std::collections::HashMap;
use chrono::{DateTime, Local};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TcpStream {
    pub id: u64,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub protocol: String,
    pub start_time: DateTime<Local>,
    pub last_time: DateTime<Local>,
    pub client_data: Vec<u8>,
    pub server_data: Vec<u8>,
    pub client_packets: u64,
    pub server_packets: u64,
    pub state: StreamState,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum StreamState {
    Opening,
    Open,
    Closing,
    Closed,
}

impl std::fmt::Display for StreamState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StreamState::Opening => write!(f, "OPENING"),
            StreamState::Open => write!(f, "OPEN"),
            StreamState::Closing => write!(f, "CLOSING"),
            StreamState::Closed => write!(f, "CLOSED"),
        }
    }
}

impl TcpStream {
    pub fn client_data_preview(&self, max_len: usize) -> String {
        let len = std::cmp::min(self.client_data.len(), max_len);
        let slice = &self.client_data[..len];
        if let Ok(text) = std::str::from_utf8(slice) {
            text.chars()
                .map(|c| if c.is_control() && c != '\n' && c != '\r' { '.' } else { c })
                .collect()
        } else {
            slice.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
        }
    }

    pub fn server_data_preview(&self, max_len: usize) -> String {
        let len = std::cmp::min(self.server_data.len(), max_len);
        let slice = &self.server_data[..len];
        if let Ok(text) = std::str::from_utf8(slice) {
            text.chars()
                .map(|c| if c.is_control() && c != '\n' && c != '\r' { '.' } else { c })
                .collect()
        } else {
            slice.iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join(" ")
        }
    }

    pub fn total_bytes(&self) -> usize {
        self.client_data.len() + self.server_data.len()
    }

    pub fn duration_secs(&self) -> f64 {
        self.last_time
            .signed_duration_since(self.start_time)
            .num_milliseconds() as f64
            / 1000.0
    }
}

pub struct StreamTracker {
    streams: HashMap<String, TcpStream>,
    stream_counter: u64,
    max_stream_data: usize,
}

impl StreamTracker {
    pub fn new() -> Self {
        Self {
            streams: HashMap::new(),
            stream_counter: 0,
            max_stream_data: 4096, // Store max 4KB per direction
        }
    }

    pub fn process_tcp_packet(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        flags_syn: bool,
        flags_ack: bool,
        flags_fin: bool,
        flags_rst: bool,
        payload: &[u8],
        timestamp: DateTime<Local>,
        protocol: &str,
    ) {
        let key = Self::stream_key(src_ip, src_port, dst_ip, dst_port);
        let is_client = Self::is_client_direction(src_ip, src_port, dst_ip, dst_port, &key);

        // SYN = new stream
        if flags_syn && !flags_ack {
            self.stream_counter += 1;
            let stream = TcpStream {
                id: self.stream_counter,
                src_ip: src_ip.to_string(),
                src_port,
                dst_ip: dst_ip.to_string(),
                dst_port,
                protocol: protocol.to_string(),
                start_time: timestamp,
                last_time: timestamp,
                client_data: Vec::new(),
                server_data: Vec::new(),
                client_packets: 1,
                server_packets: 0,
                state: StreamState::Opening,
            };
            self.streams.insert(key, stream);
            return;
        }

        if let Some(stream) = self.streams.get_mut(&key) {
            stream.last_time = timestamp;

            if flags_syn && flags_ack {
                stream.state = StreamState::Opening;
                stream.server_packets += 1;
            } else if flags_fin || flags_rst {
                stream.state = if flags_rst {
                    StreamState::Closed
                } else {
                    StreamState::Closing
                };
            } else if flags_ack && stream.state == StreamState::Opening {
                stream.state = StreamState::Open;
            }

            // Store payload data
            if !payload.is_empty() {
                if is_client {
                    stream.client_packets += 1;
                    if stream.client_data.len() < self.max_stream_data {
                        let remaining = self.max_stream_data - stream.client_data.len();
                        let to_copy = std::cmp::min(payload.len(), remaining);
                        stream.client_data.extend_from_slice(&payload[..to_copy]);
                    }
                } else {
                    stream.server_packets += 1;
                    if stream.server_data.len() < self.max_stream_data {
                        let remaining = self.max_stream_data - stream.server_data.len();
                        let to_copy = std::cmp::min(payload.len(), remaining);
                        stream.server_data.extend_from_slice(&payload[..to_copy]);
                    }
                }
            } else {
                if is_client {
                    stream.client_packets += 1;
                } else {
                    stream.server_packets += 1;
                }
            }

            if protocol != "TCP" && stream.protocol == "TCP" {
                stream.protocol = protocol.to_string();
            }
        }
    }

    pub fn get_streams(&self) -> Vec<&TcpStream> {
        let mut streams: Vec<&TcpStream> = self.streams.values().collect();
        streams.sort_by(|a, b| b.last_time.cmp(&a.last_time));
        streams
    }

    pub fn get_stream_by_id(&self, id: u64) -> Option<&TcpStream> {
        self.streams.values().find(|s| s.id == id)
    }

    pub fn open_count(&self) -> usize {
        self.streams.values().filter(|s| s.state == StreamState::Open || s.state == StreamState::Opening).count()
    }

    pub fn total_count(&self) -> usize {
        self.streams.len()
    }

    pub fn cleanup_closed(&mut self) {
        self.streams.retain(|_, s| s.state != StreamState::Closed);
    }

    fn stream_key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> String {
        if (src_ip, src_port) < (dst_ip, dst_port) {
            format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port)
        } else {
            format!("{}:{}-{}:{}", dst_ip, dst_port, src_ip, src_port)
        }
    }

    fn is_client_direction(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16, key: &str) -> bool {
        let forward = format!("{}:{}-{}:{}", src_ip, src_port, dst_ip, dst_port);
        forward == *key
    }
}