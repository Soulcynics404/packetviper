//! Filter engine — evaluates filter expressions against packets

use crate::filters::parser::{CompareOp, FilterExpr, FilterValue};
use crate::packets::CapturedPacket;
use crate::packets::transport::TransportLayerInfo;
use crate::packets::network::NetworkLayerInfo;
use crate::packets::PacketDirection;
use crate::packets::link::LinkLayerInfo;

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
                match proto.as_str() {
                    "tcp" => matches!(packet.layers.transport, Some(TransportLayerInfo::Tcp(_))),
                    "udp" => matches!(packet.layers.transport, Some(TransportLayerInfo::Udp(_))),
                    "ipv4" => matches!(packet.layers.network, Some(NetworkLayerInfo::IPv4(_)) | Some(NetworkLayerInfo::Icmp(_))),
                    "ipv6" => matches!(packet.layers.network, Some(NetworkLayerInfo::IPv6(_)) | Some(NetworkLayerInfo::Icmpv6(_))),
                    other => packet.protocol.eq_ignore_ascii_case(other),
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
                // Pattern is lowercased once at parse time.
                [&packet.summary, &packet.source, &packet.destination, &packet.protocol]
                    .iter()
                    .any(|h| contains_ignore_ascii_case(h, s))
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
            "ip" => {
                if let FilterValue::Str(target) = value {
                    let either = Self::compare_str(crate::packets::strip_port(&packet.source), &CompareOp::Eq, target)
                        || Self::compare_str(crate::packets::strip_port(&packet.destination), &CompareOp::Eq, target);
                    Self::apply_either(either, op)
                } else {
                    false
                }
            }
            "mac" => {
                if let FilterValue::Str(target) = value {
                    match &packet.layers.link {
                        Some(LinkLayerInfo::Ethernet(e)) => Self::apply_either(e.src_mac.eq_ignore_ascii_case(target) || e.dst_mac.eq_ignore_ascii_case(target), op),
                        Some(LinkLayerInfo::Arp(a)) => Self::apply_either(a.sender_mac.eq_ignore_ascii_case(target) || a.target_mac.eq_ignore_ascii_case(target), op),
                        _ => false,
                    }
                } else {
                    false
                }
            }
            "src" => {
                if let FilterValue::Str(target) = value {
                    let src = crate::packets::strip_port(&packet.source).to_string();
                    Self::compare_str(&src, op, target)
                } else {
                    false
                }
            }
            "dst" => {
                if let FilterValue::Str(target) = value {
                    let dst = crate::packets::strip_port(&packet.destination).to_string();
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
                        if *op == CompareOp::NotEq {
                            src as u64 != *target_port && dst as u64 != *target_port
                        } else {
                            Self::compare_num(src as u64, op, *target_port)
                                || Self::compare_num(dst as u64, op, *target_port)
                        }
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


    /// For fields that match on either side (ip, mac): `==` means either side equals, `!=` means neither does.
    fn apply_either(either_equal: bool, op: &CompareOp) -> bool {
        match op {
            CompareOp::Eq => either_equal,
            CompareOp::NotEq => !either_equal,
            _ => false,
        }
    }

    fn compare_str(actual: &str, op: &CompareOp, expected: &str) -> bool {
        match op {
            CompareOp::Eq => actual.eq_ignore_ascii_case(expected),
            CompareOp::NotEq => !actual.eq_ignore_ascii_case(expected),
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

/// `needle` must already be lowercase.
fn contains_ignore_ascii_case(haystack: &str, needle: &str) -> bool {
    needle.is_empty() || haystack.as_bytes().windows(needle.len()).any(|w| w.eq_ignore_ascii_case(needle.as_bytes()))
}
