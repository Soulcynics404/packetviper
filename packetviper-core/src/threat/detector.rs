//! Threat detection engine
//!
//! Detects:
//! - Port scanning (many SYN to different ports from same source)
//! - ARP spoofing (multiple MACs claiming same IP)
//! - DNS tunneling (unusually long DNS queries)
//! - Suspicious ports (known malware ports)
//! - High traffic from single source (DDoS indicator)

use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Local, Duration};
use serde::{Deserialize, Serialize};

use crate::packets::CapturedPacket;
use crate::packets::transport::TransportLayerInfo;
use crate::packets::link::LinkLayerInfo;
use crate::packets::application::AppLayerInfo;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatLevel {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for ThreatLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatLevel::Info => write!(f, "INFO"),
            ThreatLevel::Low => write!(f, "LOW"),
            ThreatLevel::Medium => write!(f, "MEDIUM"),
            ThreatLevel::High => write!(f, "HIGH"),
            ThreatLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThreatAlert {
    pub id: u64,
    pub timestamp: DateTime<Local>,
    pub level: ThreatLevel,
    pub category: String,
    pub description: String,
    pub source_ip: String,
    pub details: String,
}

pub struct ThreatDetector {
    alert_counter: u64,
    pub alerts: Vec<ThreatAlert>,

    // Port scan detection: source_ip -> set of destination ports
    syn_tracker: HashMap<String, HashSet<u16>>,
    syn_timestamps: HashMap<String, DateTime<Local>>,

    // ARP spoof detection: IP -> set of MACs
    arp_table: HashMap<String, HashSet<String>>,

    // Rate tracking: source_ip -> packet count in window
    rate_tracker: HashMap<String, Vec<DateTime<Local>>>,

    // Known suspicious ports
    suspicious_ports: HashSet<u16>,

    // Already alerted (to avoid spam)
    alerted_scans: HashSet<String>,
    alerted_arp: HashSet<String>,
}

impl ThreatDetector {
    pub fn new() -> Self {
        let mut suspicious_ports = HashSet::new();
        // Known malware / suspicious ports
        for port in [
            4444, 5555, 6666, 6667, 1337, 31337, 12345, 27374, 65535,
            3389, // RDP (external)
            4443, 8443, // Alt HTTPS
            1080, // SOCKS
            9050, 9051, // Tor
            5900, 5901, // VNC
            2222, // Alt SSH
            8888, 9999, // Common backdoors
        ] {
            suspicious_ports.insert(port);
        }

        Self {
            alert_counter: 0,
            alerts: Vec::new(),
            syn_tracker: HashMap::new(),
            syn_timestamps: HashMap::new(),
            arp_table: HashMap::new(),
            rate_tracker: HashMap::new(),
            suspicious_ports,
            alerted_scans: HashSet::new(),
            alerted_arp: HashSet::new(),
        }
    }

    /// Analyze a packet for threats
    pub fn analyze(&mut self, packet: &CapturedPacket) {
        self.detect_port_scan(packet);
        self.detect_arp_spoof(packet);
        self.detect_dns_tunneling(packet);
        self.detect_suspicious_port(packet);
        self.detect_high_rate(packet);
        self.cleanup_old_data();
    }

    /// Port scan detection
        fn detect_port_scan(&mut self, packet: &CapturedPacket) {
        if let Some(ref transport) = packet.layers.transport {
            if let TransportLayerInfo::Tcp(ref tcp) = transport {
                if tcp.flags.syn && !tcp.flags.ack {
                    let src = Self::extract_ip(&packet.source);
                    let entry = self.syn_tracker.entry(src.clone()).or_insert_with(HashSet::new);
                    entry.insert(tcp.dst_port);
                    self.syn_timestamps.entry(src.clone()).or_insert(packet.timestamp);

                    // Collect data BEFORE calling add_alert
                    let port_count = self.syn_tracker.get(&src).map(|s| s.len()).unwrap_or(0);
                    let already_alerted = self.alerted_scans.contains(&src);

                    if port_count > 15 && !already_alerted {
                        let ports: Vec<u16> = self.syn_tracker.get(&src)
                            .map(|s| s.iter().take(20).copied().collect())
                            .unwrap_or_default();
                        self.alerted_scans.insert(src.clone());
                        self.add_alert(
                            ThreatLevel::High,
                            "Port Scan",
                            &format!(
                                "Possible port scan from {} — {} unique ports targeted",
                                src, port_count
                            ),
                            &src,
                            &format!("Ports: {:?}", ports),
                        );
                    }
                }
            }
        }
    }

    /// ARP spoof detection
        fn detect_arp_spoof(&mut self, packet: &CapturedPacket) {
        if let Some(ref link) = packet.layers.link {
            if let LinkLayerInfo::Arp(ref arp) = link {
                if arp.operation == "Reply" {
                    let entry = self
                        .arp_table
                        .entry(arp.sender_ip.clone())
                        .or_insert_with(HashSet::new);
                    entry.insert(arp.sender_mac.clone());

                    // Collect data BEFORE calling add_alert
                    let mac_count = self.arp_table.get(&arp.sender_ip).map(|s| s.len()).unwrap_or(0);
                    let already_alerted = self.alerted_arp.contains(&arp.sender_ip);

                    if mac_count > 1 && !already_alerted {
                        let macs: Vec<String> = self.arp_table.get(&arp.sender_ip)
                            .map(|s| s.iter().cloned().collect())
                            .unwrap_or_default();
                        let ip = arp.sender_ip.clone();
                        self.alerted_arp.insert(ip.clone());
                        self.add_alert(
                            ThreatLevel::Critical,
                            "ARP Spoofing",
                            &format!(
                                "Multiple MACs claiming IP {} — possible ARP spoofing!",
                                ip
                            ),
                            &ip,
                            &format!("MACs: {:?}", macs),
                        );
                    }
                }
            }
        }
    }

    /// DNS tunneling detection (unusually long domain names)
    fn detect_dns_tunneling(&mut self, packet: &CapturedPacket) {
        if let Some(ref app) = packet.layers.application {
            if let AppLayerInfo::Dns(ref dns) = app {
                for question in &dns.questions {
                    // DNS tunneling often uses very long subdomain labels
                    let label_lengths: Vec<usize> =
                        question.name.split('.').map(|l| l.len()).collect();
                    let max_label = label_lengths.iter().max().unwrap_or(&0);
                    let total_len = question.name.len();

                    if *max_label > 40 || total_len > 100 {
                        self.add_alert(
                            ThreatLevel::Medium,
                            "DNS Tunneling",
                            &format!(
                                "Suspiciously long DNS query: {} (len: {})",
                                &question.name[..std::cmp::min(60, question.name.len())],
                                total_len,
                            ),
                            &packet.source,
                            &format!(
                                "Max label length: {}, Total: {}",
                                max_label, total_len
                            ),
                        );
                    }
                }
            }
        }
    }

    /// Detect traffic to known suspicious ports
    fn detect_suspicious_port(&mut self, packet: &CapturedPacket) {
        if let Some(ref transport) = packet.layers.transport {
            let dst_port = match transport {
                TransportLayerInfo::Tcp(tcp) => tcp.dst_port,
                TransportLayerInfo::Udp(udp) => udp.dst_port,
            };

            if self.suspicious_ports.contains(&dst_port) {
                self.add_alert(
                    ThreatLevel::Low,
                    "Suspicious Port",
                    &format!(
                        "Traffic to suspicious port {} from {}",
                        dst_port, packet.source
                    ),
                    &packet.source,
                    &format!("Destination: {} port {}", packet.destination, dst_port),
                );
            }
        }
    }

    /// Detect high packet rate from single source
        fn detect_high_rate(&mut self, packet: &CapturedPacket) {
        let src = Self::extract_ip(&packet.source);
        let entry = self.rate_tracker.entry(src.clone()).or_insert_with(Vec::new);
        entry.push(packet.timestamp);

        let cutoff = Local::now() - Duration::seconds(10);
        entry.retain(|t| *t > cutoff);

        // Collect data BEFORE calling add_alert
        let rate_count = self.rate_tracker.get(&src).map(|v| v.len()).unwrap_or(0);

        if rate_count > 500 {
            // Clear first to release the borrow
            if let Some(v) = self.rate_tracker.get_mut(&src) {
                v.clear();
            }
            self.add_alert(
                ThreatLevel::High,
                "High Traffic Rate",
                &format!(
                    "High packet rate from {}: {} packets in 10 seconds",
                    src, rate_count
                ),
                &src,
                &format!("{} pps", rate_count / 10),
            );
        }
    }

    fn add_alert(
        &mut self,
        level: ThreatLevel,
        category: &str,
        description: &str,
        source_ip: &str,
        details: &str,
    ) {
        self.alert_counter += 1;
        self.alerts.push(ThreatAlert {
            id: self.alert_counter,
            timestamp: Local::now(),
            level,
            category: category.to_string(),
            description: description.to_string(),
            source_ip: source_ip.to_string(),
            details: details.to_string(),
        });

        // Keep max 500 alerts
        if self.alerts.len() > 500 {
            self.alerts.remove(0);
        }
    }

    fn cleanup_old_data(&mut self) {
        let now = Local::now();

        // Clear SYN tracking older than 60 seconds
        let old_ips: Vec<String> = self
            .syn_timestamps
            .iter()
            .filter(|(_, ts)| now.signed_duration_since(**ts).num_seconds() > 60)
            .map(|(ip, _)| ip.clone())
            .collect();

        for ip in old_ips {
            self.syn_tracker.remove(&ip);
            self.syn_timestamps.remove(&ip);
            self.alerted_scans.remove(&ip);
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

    pub fn alert_count(&self) -> usize {
        self.alerts.len()
    }

    pub fn critical_count(&self) -> usize {
        self.alerts
            .iter()
            .filter(|a| matches!(a.level, ThreatLevel::Critical | ThreatLevel::High))
            .count()
    }
}