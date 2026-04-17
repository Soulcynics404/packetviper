//! Filter engine — evaluates filter expressions against packets

use crate::filters::parser::{CompareOp, FilterExpr, FilterValue};
use crate::packets::CapturedPacket;
use crate::packets::transport::TransportLayerInfo;
use crate::packets::network::NetworkLayerInfo;
use crate::packets::PacketDirection;

pub struct FilterEngine {
    filter: FilterExpr,
    raw_expression: String,
}

impl FilterEngine {
    pub fn new() -> Self {
        Self {
            filter: FilterExpr::True,
            raw_expression: String::new(),
        }
    }

    /// Set a new filter expression
    pub fn set_filter(&mut self, expression: &str) -> Result<(), String> {
        let parsed = crate::filters::parser::parse_filter(expression)?;
        self.filter = parsed;
        self.raw_expression = expression.to_string();
        Ok(())
    }

    /// Clear filter (match everything)
    pub fn clear(&mut self) {
        self.filter = FilterExpr::True;
        self.raw_expression.clear();
    }

    /// Get the current filter expression string
    pub fn expression(&self) -> &str {
        &self.raw_expression
    }

    /// Check if a packet matches the current filter
    pub fn matches(&self, packet: &CapturedPacket) -> bool {
        Self::eval(&self.filter, packet)
    }

    fn eval(expr: &FilterExpr, packet: &CapturedPacket) -> bool {
        match expr {
            FilterExpr::True => true,

            FilterExpr::Protocol(proto) => {
                let pkt_proto = packet.protocol.to_lowercase();
                match proto.as_str() {
                    "tcp" => pkt_proto == "tcp" || pkt_proto == "http" || pkt_proto == "tls" || pkt_proto == "ssh",
                    "udp" => pkt_proto == "udp" || pkt_proto == "dns" || pkt_proto == "dhcp",
                    other => pkt_proto == other,
                }
            }

            FilterExpr::Comparison { field, op, value } => {
                Self::eval_comparison(field, op, value, packet)
            }

            FilterExpr::PortRange { start, end } => {
                if let Some(ref transport) = packet.layers.transport {
                    let (src, dst) = match transport {
                        TransportLayerInfo::Tcp(tcp) => (tcp.src_port, tcp.dst_port),
                        TransportLayerInfo::Udp(udp) => (udp.src_port, udp.dst_port),
                    };
                    (src >= *start && src <= *end) || (dst >= *start && dst <= *end)
                } else {
                    false
                }
            }

            FilterExpr::And(a, b) => Self::eval(a, packet) && Self::eval(b, packet),
            FilterExpr::Or(a, b) => Self::eval(a, packet) || Self::eval(b, packet),
            FilterExpr::Not(e) => !Self::eval(e, packet),

            FilterExpr::Contains(s) => {
                let s_lower = s.to_lowercase();
                packet.summary.to_lowercase().contains(&s_lower)
                    || packet.source.to_lowercase().contains(&s_lower)
                    || packet.destination.to_lowercase().contains(&s_lower)
                    || packet.protocol.to_lowercase().contains(&s_lower)
            }
        }
    }

    fn eval_comparison(
        field: &str,
        op: &CompareOp,
        value: &FilterValue,
        packet: &CapturedPacket,
    ) -> bool {
        match field {
            "ip" | "src" => {
                if let FilterValue::Str(target) = value {
                    let src = Self::extract_ip(&packet.source);
                    Self::compare_str(&src, op, target)
                } else {
                    false
                }
            }
            "dst" => {
                if let FilterValue::Str(target) = value {
                    let dst = Self::extract_ip(&packet.destination);
                    Self::compare_str(&dst, op, target)
                } else {
                    false
                }
            }
            "port" => {
                if let FilterValue::Num(target_port) = value {
                    if let Some(ref transport) = packet.layers.transport {
                        let (src, dst) = match transport {
                            TransportLayerInfo::Tcp(tcp) => (tcp.src_port, tcp.dst_port),
                            TransportLayerInfo::Udp(udp) => (udp.src_port, udp.dst_port),
                        };
                        Self::compare_num(src as u64, op, *target_port)
                            || Self::compare_num(dst as u64, op, *target_port)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            "sport" => {
                if let FilterValue::Num(target_port) = value {
                    if let Some(ref transport) = packet.layers.transport {
                        let src = match transport {
                            TransportLayerInfo::Tcp(tcp) => tcp.src_port,
                            TransportLayerInfo::Udp(udp) => udp.src_port,
                        };
                        Self::compare_num(src as u64, op, *target_port)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            "dport" => {
                if let FilterValue::Num(target_port) = value {
                    if let Some(ref transport) = packet.layers.transport {
                        let dst = match transport {
                            TransportLayerInfo::Tcp(tcp) => tcp.dst_port,
                            TransportLayerInfo::Udp(udp) => udp.dst_port,
                        };
                        Self::compare_num(dst as u64, op, *target_port)
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            "len" | "length" => {
                if let FilterValue::Num(target_len) = value {
                    Self::compare_num(packet.length as u64, op, *target_len)
                } else {
                    false
                }
            }
            "ttl" => {
                if let FilterValue::Num(target_ttl) = value {
                    if let Some(ref network) = packet.layers.network {
                        match network {
                            NetworkLayerInfo::IPv4(ip) => {
                                Self::compare_num(ip.ttl as u64, op, *target_ttl)
                            }
                            NetworkLayerInfo::IPv6(ip) => {
                                Self::compare_num(ip.hop_limit as u64, op, *target_ttl)
                            }
                            _ => false,
                        }
                    } else {
                        false
                    }
                } else {
                    false
                }
            }
            "direction" | "dir" => {
                if let FilterValue::Str(target) = value {
                    let dir = match &packet.direction {
                        PacketDirection::Incoming => "in",
                        PacketDirection::Outgoing => "out",
                        PacketDirection::Unknown => "unknown",
                    };
                    let target_lower = target.to_lowercase();
                    match op {
                        CompareOp::Eq => {
                            dir == target_lower
                                || (target_lower == "incoming" && dir == "in")
                                || (target_lower == "outgoing" && dir == "out")
                        }
                        CompareOp::NotEq => {
                            dir != target_lower
                                && !(target_lower == "incoming" && dir == "in")
                                && !(target_lower == "outgoing" && dir == "out")
                        }
                        _ => false,
                    }
                } else {
                    false
                }
            }
            "interface" | "iface" => {
                if let FilterValue::Str(target) = value {
                    Self::compare_str(&packet.interface, op, target)
                } else {
                    false
                }
            }
            _ => false,
        }
    }

    fn extract_ip(addr: &str) -> String {
        // Remove port from "ip:port" format
        if let Some(last_colon) = addr.rfind(':') {
            let potential_port = &addr[last_colon + 1..];
            if potential_port.parse::<u16>().is_ok() {
                // Check if it's IPv6 (contains multiple colons)
                let colon_count = addr.matches(':').count();
                if colon_count == 1 {
                    // IPv4:port
                    return addr[..last_colon].to_string();
                }
            }
        }
        addr.to_string()
    }

    fn compare_str(actual: &str, op: &CompareOp, expected: &str) -> bool {
        match op {
            CompareOp::Eq => actual.to_lowercase() == expected.to_lowercase(),
            CompareOp::NotEq => actual.to_lowercase() != expected.to_lowercase(),
            _ => false,
        }
    }

    fn compare_num(actual: u64, op: &CompareOp, expected: u64) -> bool {
        match op {
            CompareOp::Eq => actual == expected,
            CompareOp::NotEq => actual != expected,
            CompareOp::Gt => actual > expected,
            CompareOp::Lt => actual < expected,
            CompareOp::GtEq => actual >= expected,
            CompareOp::LtEq => actual <= expected,
        }
    }
}