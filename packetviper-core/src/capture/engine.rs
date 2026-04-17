//! The main capture engine that sniffs packets from a network interface

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;

use crossbeam_channel::Sender;
use pnet::datalink::{self, Channel, Config, NetworkInterface};
use pnet::packet::arp::ArpPacket;
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::icmpv6::Icmpv6Packet;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::ipv6::Ipv6Packet;
use pnet::packet::tcp::TcpPacket;
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;

use chrono::Local;

use crate::packets::application::AppLayerInfo;
use crate::packets::link::{ArpInfo, EthernetInfo, LinkLayerInfo};
use crate::packets::network::{
    IcmpInfo, Icmpv6Info, IPv4Info, IPv6Info, NetworkLayerInfo,
};
use crate::packets::transport::{TcpFlags, TcpInfo, TransportLayerInfo, UdpInfo};
use crate::packets::{CapturedPacket, LayerInfo, PacketDirection};

/// The main capture engine
pub struct CaptureEngine {
    /// Name of the interface to capture on
    interface_name: String,
    /// Atomic counter for packet IDs
    packet_counter: Arc<AtomicU64>,
    /// Flag to stop capture
    running: Arc<AtomicBool>,
}

impl CaptureEngine {
    /// Create a new CaptureEngine for the given interface
    pub fn new(interface_name: &str) -> Self {
        Self {
            interface_name: interface_name.to_string(),
            packet_counter: Arc::new(AtomicU64::new(0)),
            running: Arc::new(AtomicBool::new(false)),
        }
    }

    /// Get a handle to the running flag (to stop capture from outside)
    pub fn get_running_flag(&self) -> Arc<AtomicBool> {
        self.running.clone()
    }

    /// Start capturing packets and send them through the channel
    pub fn start_capture(&self, tx: Sender<CapturedPacket>) -> Result<(), String> {
        let interface = datalink::interfaces()
            .into_iter()
            .find(|iface| iface.name == self.interface_name)
            .ok_or_else(|| format!("Interface '{}' not found", self.interface_name))?;

        let config = Config {
            promiscuous: true,
            ..Default::default()
        };

        let (_, mut rx) = match datalink::channel(&interface, config) {
            Ok(Channel::Ethernet(tx_chan, rx_chan)) => (tx_chan, rx_chan),
            Ok(_) => return Err("Unsupported channel type".to_string()),
            Err(e) => return Err(format!("Failed to open channel: {}", e)),
        };

        self.running.store(true, Ordering::SeqCst);

        let running = self.running.clone();
        let counter = self.packet_counter.clone();
        let iface_name = self.interface_name.clone();
        let local_ips = Self::get_local_ips(&interface);

        log::info!("Starting capture on interface: {}", iface_name);

        // Capture loop
        while running.load(Ordering::SeqCst) {
            match rx.next() {
                Ok(frame) => {
                    let id = counter.fetch_add(1, Ordering::SeqCst);
                    if let Some(packet) = Self::parse_ethernet_frame(
                        id,
                        frame,
                        &iface_name,
                        &local_ips,
                    ) {
                        if tx.send(packet).is_err() {
                            log::warn!("Receiver dropped, stopping capture");
                            break;
                        }
                    }
                }
                Err(e) => {
                    log::error!("Capture error: {}", e);
                    continue;
                }
            }
        }

        log::info!("Capture stopped on interface: {}", iface_name);
        Ok(())
    }

    /// Stop the capture
    pub fn stop(&self) {
        self.running.store(false, Ordering::SeqCst);
    }

    /// Get local IPs for direction detection
    fn get_local_ips(interface: &NetworkInterface) -> Vec<String> {
        interface.ips.iter().map(|ip| ip.ip().to_string()).collect()
    }

    /// Determine packet direction based on local IPs
    fn get_direction(src_ip: &str, dst_ip: &str, local_ips: &[String]) -> PacketDirection {
        if local_ips.contains(&src_ip.to_string()) {
            PacketDirection::Outgoing
        } else if local_ips.contains(&dst_ip.to_string()) {
            PacketDirection::Incoming
        } else {
            PacketDirection::Unknown
        }
    }

    /// Parse a raw Ethernet frame into a CapturedPacket
    fn parse_ethernet_frame(
        id: u64,
        frame: &[u8],
        interface: &str,
        local_ips: &[String],
    ) -> Option<CapturedPacket> {
        let ethernet = EthernetPacket::new(frame)?;
        let timestamp = Local::now();

        let src_mac = ethernet.get_source().to_string();
        let dst_mac = ethernet.get_destination().to_string();

        let ethertype = ethernet.get_ethertype();
        let ethertype_name = format!("{}", ethertype);

        let link_info = LinkLayerInfo::Ethernet(EthernetInfo {
            src_mac: src_mac.clone(),
            dst_mac: dst_mac.clone(),
            ethertype: ethertype.0,
            ethertype_name: ethertype_name.clone(),
        });

        let mut network_info = None;
        let mut transport_info = None;
        let mut app_info = None;
        let mut protocol = ethertype_name.clone();
        let mut source = src_mac.clone();
        let mut destination = dst_mac.clone();
        let mut summary;
        let mut direction = PacketDirection::Unknown;

        match ethertype {
            EtherTypes::Ipv4 => {
                if let Some(ipv4) = Ipv4Packet::new(ethernet.payload()) {
                    let src_ip = ipv4.get_source().to_string();
                    let dst_ip = ipv4.get_destination().to_string();
                    direction = Self::get_direction(&src_ip, &dst_ip, local_ips);

                    let proto = ipv4.get_next_level_protocol();
                    let proto_name = format!("{}", proto);

                    network_info = Some(NetworkLayerInfo::IPv4(IPv4Info {
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        ttl: ipv4.get_ttl(),
                        protocol: proto.0,
                        protocol_name: proto_name.clone(),
                        header_length: ipv4.get_header_length(),
                        total_length: ipv4.get_total_length(),
                        flags: ipv4.get_flags(),
                        dscp: ipv4.get_dscp(),
                        identification: ipv4.get_identification(),
                    }));

                    source = src_ip.clone();
                    destination = dst_ip.clone();

                    // Parse transport layer
                    match proto {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv4.payload()) {
                                let src_port = tcp.get_source();
                                let dst_port = tcp.get_destination();

                                transport_info =
                                    Some(TransportLayerInfo::Tcp(TcpInfo {
                                        src_port,
                                        dst_port,
                                        seq_number: tcp.get_sequence(),
                                        ack_number: tcp.get_acknowledgement(),
                                        flags: TcpFlags {
                                            syn: (tcp.get_flags() & 0x02) != 0,
                                            ack: (tcp.get_flags() & 0x10) != 0,
                                            fin: (tcp.get_flags() & 0x01) != 0,
                                            rst: (tcp.get_flags() & 0x04) != 0,
                                            psh: (tcp.get_flags() & 0x08) != 0,
                                            urg: (tcp.get_flags() & 0x20) != 0,
                                            ece: (tcp.get_flags() & 0x40) != 0,
                                            cwr: (tcp.get_flags() & 0x80) != 0,
                                        },
                                        window_size: tcp.get_window(),
                                        header_length: tcp.get_data_offset(),
                                        urgent_pointer: tcp.get_urgent_ptr(),
                                    }));

                                protocol = "TCP".to_string();
                                source = format!("{}:{}", src_ip, src_port);
                                destination = format!("{}:{}", dst_ip, dst_port);

                                // Detect application protocol
                                app_info = Self::detect_app_protocol(
                                    src_port,
                                    dst_port,
                                    tcp.payload(),
                                );
                                if let Some(ref app) = app_info {
                                    protocol = match app {
                                        AppLayerInfo::Http(_) => "HTTP".to_string(),
                                        AppLayerInfo::Tls(_) => "TLS".to_string(),
                                        AppLayerInfo::Ssh(_) => "SSH".to_string(),
                                        AppLayerInfo::Dns(_) => "DNS".to_string(),
                                        _ => "TCP".to_string(),
                                    };
                                }
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv4.payload()) {
                                let src_port = udp.get_source();
                                let dst_port = udp.get_destination();

                                transport_info =
                                    Some(TransportLayerInfo::Udp(UdpInfo {
                                        src_port,
                                        dst_port,
                                        length: udp.get_length(),
                                        checksum: udp.get_checksum(),
                                    }));

                                protocol = "UDP".to_string();
                                source = format!("{}:{}", src_ip, src_port);
                                destination = format!("{}:{}", dst_ip, dst_port);

                                // Detect application protocol (e.g., DNS on port 53)
                                app_info = Self::detect_app_protocol(
                                    src_port,
                                    dst_port,
                                    udp.payload(),
                                );
                                if let Some(ref app) = app_info {
                                    protocol = match app {
                                        AppLayerInfo::Dns(_) => "DNS".to_string(),
                                        AppLayerInfo::Dhcp(_) => "DHCP".to_string(),
                                        _ => "UDP".to_string(),
                                    };
                                }
                            }
                        }
                        IpNextHeaderProtocols::Icmp => {
                            if let Some(icmp) = IcmpPacket::new(ipv4.payload()) {
                                let icmp_type = icmp.get_icmp_type().0;
                                let type_name = match icmp_type {
                                    0 => "Echo Reply",
                                    3 => "Destination Unreachable",
                                    8 => "Echo Request",
                                    11 => "Time Exceeded",
                                    _ => "Other",
                                }
                                .to_string();

                                network_info = Some(NetworkLayerInfo::Icmp(IcmpInfo {
                                    icmp_type,
                                    icmp_code: icmp.get_icmp_code().0,
                                    type_name,
                                    src_ip: src_ip.clone(),
                                    dst_ip: dst_ip.clone(),
                                }));
                                protocol = "ICMP".to_string();
                            }
                        }
                        _ => {
                            protocol = proto_name;
                        }
                    }
                }
            }
            EtherTypes::Ipv6 => {
                if let Some(ipv6) = Ipv6Packet::new(ethernet.payload()) {
                    let src_ip = ipv6.get_source().to_string();
                    let dst_ip = ipv6.get_destination().to_string();
                    direction = Self::get_direction(&src_ip, &dst_ip, local_ips);

                    network_info = Some(NetworkLayerInfo::IPv6(IPv6Info {
                        src_ip: src_ip.clone(),
                        dst_ip: dst_ip.clone(),
                        hop_limit: ipv6.get_hop_limit(),
                        next_header: ipv6.get_next_header().0,
                        traffic_class: ipv6.get_traffic_class(),
                        flow_label: ipv6.get_flow_label(),
                        payload_length: ipv6.get_payload_length(),
                    }));

                    source = src_ip;
                    destination = dst_ip;
                    protocol = "IPv6".to_string();

                    // Parse IPv6 transport layer similarly...
                    let proto = ipv6.get_next_header();
                    match proto {
                        IpNextHeaderProtocols::Tcp => {
                            if let Some(tcp) = TcpPacket::new(ipv6.payload()) {
                                let src_port = tcp.get_source();
                                let dst_port = tcp.get_destination();
                                transport_info =
                                    Some(TransportLayerInfo::Tcp(TcpInfo {
                                        src_port,
                                        dst_port,
                                        seq_number: tcp.get_sequence(),
                                        ack_number: tcp.get_acknowledgement(),
                                        flags: TcpFlags {
                                            syn: (tcp.get_flags() & 0x02) != 0,
                                            ack: (tcp.get_flags() & 0x10) != 0,
                                            fin: (tcp.get_flags() & 0x01) != 0,
                                            rst: (tcp.get_flags() & 0x04) != 0,
                                            psh: (tcp.get_flags() & 0x08) != 0,
                                            urg: (tcp.get_flags() & 0x20) != 0,
                                            ece: (tcp.get_flags() & 0x40) != 0,
                                            cwr: (tcp.get_flags() & 0x80) != 0,
                                        },
                                        window_size: tcp.get_window(),
                                        header_length: tcp.get_data_offset(),
                                        urgent_pointer: tcp.get_urgent_ptr(),
                                    }));
                                protocol = "TCP".to_string();
                                source = format!("{}:{}", source, src_port);
                                destination = format!("{}:{}", destination, dst_port);
                            }
                        }
                        IpNextHeaderProtocols::Udp => {
                            if let Some(udp) = UdpPacket::new(ipv6.payload()) {
                                transport_info =
                                    Some(TransportLayerInfo::Udp(UdpInfo {
                                        src_port: udp.get_source(),
                                        dst_port: udp.get_destination(),
                                        length: udp.get_length(),
                                        checksum: udp.get_checksum(),
                                    }));
                                protocol = "UDP".to_string();
                                source = format!("{}:{}", source, udp.get_source());
                                destination = format!("{}:{}", destination, udp.get_destination());
                            }
                        }
                        IpNextHeaderProtocols::Icmpv6 => {
                            if let Some(icmpv6) = Icmpv6Packet::new(ipv6.payload()) {
                                let icmp_type = icmpv6.get_icmpv6_type().0;
                                let type_name = match icmp_type {
                                    128 => "Echo Request",
                                    129 => "Echo Reply",
                                    133 => "Router Solicitation",
                                    134 => "Router Advertisement",
                                    135 => "Neighbor Solicitation",
                                    136 => "Neighbor Advertisement",
                                    _ => "Other",
                                }
                                .to_string();

                                network_info = Some(NetworkLayerInfo::Icmpv6(Icmpv6Info {
                                    icmp_type,
                                    icmp_code: icmpv6.get_icmpv6_code().0,
                                    type_name,
                                    src_ip: source.clone(),
                                    dst_ip: destination.clone(),
                                }));
                                protocol = "ICMPv6".to_string();
                            }
                        }
                        _ => {}
                    }
                }
            }
            EtherTypes::Arp => {
                if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                    let operation = match arp.get_operation().0 {
                        1 => "Request",
                        2 => "Reply",
                        _ => "Unknown",
                    }
                    .to_string();

                    let arp_info = ArpInfo {
                        operation: operation.clone(),
                        sender_mac: arp.get_sender_hw_addr().to_string(),
                        sender_ip: arp.get_sender_proto_addr().to_string(),
                        target_mac: arp.get_target_hw_addr().to_string(),
                        target_ip: arp.get_target_proto_addr().to_string(),
                    };

                    source = arp.get_sender_proto_addr().to_string();
                    destination = arp.get_target_proto_addr().to_string();
                    protocol = "ARP".to_string();

                    // Override link info with ARP-specific info
                    return Some(CapturedPacket {
                        id,
                        timestamp,
                        length: frame.len(),
                        interface: interface.to_string(),
                        direction,
                        layers: LayerInfo {
                            link: Some(LinkLayerInfo::Arp(arp_info)),
                            network: None,
                            transport: None,
                            application: None,
                        },
                        raw_preview: frame[..std::cmp::min(128, frame.len())].to_vec(),
                        summary: format!("ARP {} {} -> {}", operation, source, destination),
                        protocol,
                        source,
                        destination,
                    });
                }
            }
            _ => {
                protocol = format!("0x{:04x}", ethertype.0);
            }
        }

        summary = format!("{} {} -> {}", protocol, source, destination);
        if let Some(ref transport) = transport_info {
            summary = format!("{} {}", summary, transport);
        }

        Some(CapturedPacket {
            id,
            timestamp,
            length: frame.len(),
            interface: interface.to_string(),
            direction,
            layers: LayerInfo {
                link: Some(link_info),
                network: network_info,
                transport: transport_info,
                application: app_info,
            },
            raw_preview: frame[..std::cmp::min(128, frame.len())].to_vec(),
            summary,
            protocol,
            source,
            destination,
        })
    }

    /// Try to detect the application-layer protocol based on port numbers and payload
        fn detect_app_protocol(
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
    ) -> Option<AppLayerInfo> {
        if payload.is_empty() {
            return None;
        }

        // DNS (port 53)
        if src_port == 53 || dst_port == 53 {
            return Self::parse_dns(payload);
        }

        // HTTP (port 80, 8080)
        if src_port == 80 || dst_port == 80 || src_port == 8080 || dst_port == 8080 {
            return Self::parse_http(payload);
        }

        // TLS (port 443)
        if src_port == 443 || dst_port == 443 {
            return Self::parse_tls(payload);
        }

        // SSH (port 22)
        if src_port == 22 || dst_port == 22 {
            return Self::parse_ssh(payload);
        }

        // DHCP (ports 67, 68)
        if src_port == 67 || dst_port == 67 || src_port == 68 || dst_port == 68 {
            return Some(AppLayerInfo::Dhcp(crate::packets::application::DhcpInfo {
                message_type: "DHCP".to_string(),
                client_ip: None,
                your_ip: None,
                server_ip: None,
                client_mac: String::new(),
            }));
        }

        // Use plugin system for FTP, SMTP, MQTT
        use crate::capture::plugins::PluginRegistry;
        // Create a thread-local registry to avoid recreating each time
        thread_local! {
            static REGISTRY: PluginRegistry = PluginRegistry::new();
        }

        REGISTRY.with(|registry| registry.try_parse(src_port, dst_port, payload))
    }

    /// Basic HTTP parser
    fn parse_http(payload: &[u8]) -> Option<AppLayerInfo> {
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?;

        let methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"];
        let is_request = methods.iter().any(|m| first_line.starts_with(m));

        if is_request {
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 3 {
                let mut host = None;
                let mut user_agent = None;
                let mut content_type = None;

                for line in text.lines().skip(1) {
                    if let Some(val) = line.strip_prefix("Host: ") {
                        host = Some(val.trim().to_string());
                    } else if let Some(val) = line.strip_prefix("User-Agent: ") {
                        user_agent = Some(val.trim().to_string());
                    } else if let Some(val) = line.strip_prefix("Content-Type: ") {
                        content_type = Some(val.trim().to_string());
                    }
                }

                return Some(AppLayerInfo::Http(crate::packets::application::HttpInfo {
                    method: Some(parts[0].to_string()),
                    uri: Some(parts[1].to_string()),
                    version: parts[2].to_string(),
                    status_code: None,
                    host,
                    user_agent,
                    content_type,
                    content_length: None,
                }));
            }
        } else if first_line.starts_with("HTTP/") {
            let parts: Vec<&str> = first_line.splitn(3, ' ').collect();
            if parts.len() >= 2 {
                return Some(AppLayerInfo::Http(crate::packets::application::HttpInfo {
                    method: None,
                    uri: None,
                    version: parts[0].to_string(),
                    status_code: parts[1].parse().ok(),
                    host: None,
                    user_agent: None,
                    content_type: None,
                    content_length: None,
                }));
            }
        }

        None
    }

    /// Basic DNS parser
    fn parse_dns(payload: &[u8]) -> Option<AppLayerInfo> {
        if payload.len() < 12 {
            return None;
        }

        let query_id = u16::from_be_bytes([payload[0], payload[1]]);
        let flags = u16::from_be_bytes([payload[2], payload[3]]);
        let is_response = (flags & 0x8000) != 0;
        let opcode = ((flags >> 11) & 0x0F) as u8;
        let response_code = (flags & 0x0F) as u8;
        let qd_count = u16::from_be_bytes([payload[4], payload[5]]);

        let mut questions = Vec::new();
        let mut offset = 12;

        // Parse question section
        for _ in 0..qd_count {
            if let Some((name, new_offset)) = Self::parse_dns_name(payload, offset) {
                offset = new_offset;
                if offset + 4 <= payload.len() {
                    let qtype = u16::from_be_bytes([payload[offset], payload[offset + 1]]);
                    let qclass = u16::from_be_bytes([payload[offset + 2], payload[offset + 3]]);
                    offset += 4;

                    let record_type = match qtype {
                        1 => "A", 2 => "NS", 5 => "CNAME", 6 => "SOA",
                        15 => "MX", 16 => "TXT", 28 => "AAAA", 33 => "SRV",
                        _ => "Unknown",
                    }
                    .to_string();

                    questions.push(crate::packets::application::DnsQuestion {
                        name,
                        record_type,
                        class: format!("{}", qclass),
                    });
                }
            } else {
                break;
            }
        }

        Some(AppLayerInfo::Dns(crate::packets::application::DnsInfo {
            query_id,
            is_response,
            opcode,
            questions,
            answers: Vec::new(), // Simplified — full answer parsing can be added later
            response_code,
        }))
    }

    /// Parse a DNS domain name from the payload
    fn parse_dns_name(payload: &[u8], mut offset: usize) -> Option<(String, usize)> {
        let mut name_parts = Vec::new();
        let mut jumped = false;
        let mut return_offset = 0;

        loop {
            if offset >= payload.len() {
                return None;
            }
            let len = payload[offset] as usize;

            if len == 0 {
                if !jumped {
                    return_offset = offset + 1;
                }
                break;
            }

            // DNS compression pointer
            if len & 0xC0 == 0xC0 {
                if offset + 1 >= payload.len() {
                    return None;
                }
                if !jumped {
                    return_offset = offset + 2;
                }
                offset = ((len & 0x3F) << 8 | payload[offset + 1] as usize) as usize;
                jumped = true;
                continue;
            }

            offset += 1;
            if offset + len > payload.len() {
                return None;
            }
            if let Ok(label) = std::str::from_utf8(&payload[offset..offset + len]) {
                name_parts.push(label.to_string());
            }
            offset += len;
        }

        Some((name_parts.join("."), return_offset))
    }

    /// Basic TLS parser (just record header + SNI extraction)
    fn parse_tls(payload: &[u8]) -> Option<AppLayerInfo> {
        if payload.len() < 5 {
            return None;
        }

        let content_type = match payload[0] {
            20 => "ChangeCipherSpec",
            21 => "Alert",
            22 => "Handshake",
            23 => "ApplicationData",
            _ => "Unknown",
        }
        .to_string();

        let version = match (payload[1], payload[2]) {
            (3, 0) => "SSL 3.0",
            (3, 1) => "TLS 1.0",
            (3, 2) => "TLS 1.1",
            (3, 3) => "TLS 1.2",
            (3, 4) => "TLS 1.3",
            _ => "Unknown",
        }
        .to_string();

        let mut handshake_type = None;
        let mut sni = None;

        // If it's a Handshake, try to extract more info
        if payload[0] == 22 && payload.len() > 5 {
            handshake_type = Some(
                match payload[5] {
                    1 => "ClientHello",
                    2 => "ServerHello",
                    11 => "Certificate",
                    12 => "ServerKeyExchange",
                    14 => "ServerHelloDone",
                    16 => "ClientKeyExchange",
                    _ => "Other",
                }
                .to_string(),
            );

            // Try to extract SNI from ClientHello
            if payload[5] == 1 {
                sni = Self::extract_tls_sni(payload);
            }
        }

        Some(AppLayerInfo::Tls(crate::packets::application::TlsInfo {
            version,
            content_type,
            handshake_type,
            sni,
            cipher_suite: None,
        }))
    }

    /// Extract Server Name Indication from TLS ClientHello
    fn extract_tls_sni(payload: &[u8]) -> Option<String> {
        // This is a simplified SNI extraction
        // Full implementation would parse all extensions properly
        if payload.len() < 44 {
            return None;
        }

        // Search for SNI extension (type 0x0000)
        let mut i = 43; // Skip past fixed ClientHello fields
        // Skip session ID
        if i >= payload.len() { return None; }
        let session_id_len = payload[i] as usize;
        i += 1 + session_id_len;

        // Skip cipher suites
        if i + 2 > payload.len() { return None; }
        let cs_len = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
        i += 2 + cs_len;

        // Skip compression methods
        if i >= payload.len() { return None; }
        let comp_len = payload[i] as usize;
        i += 1 + comp_len;

        // Extensions length
        if i + 2 > payload.len() { return None; }
        let _ext_len = u16::from_be_bytes([payload[i], payload[i + 1]]) as usize;
        i += 2;

        // Iterate extensions
        while i + 4 < payload.len() {
            let ext_type = u16::from_be_bytes([payload[i], payload[i + 1]]);
            let ext_len = u16::from_be_bytes([payload[i + 2], payload[i + 3]]) as usize;
            i += 4;

            if ext_type == 0 {
                // SNI extension
                if i + 5 < payload.len() && i + ext_len <= payload.len() {
                    let name_len =
                        u16::from_be_bytes([payload[i + 3], payload[i + 4]]) as usize;
                    if i + 5 + name_len <= payload.len() {
                        return std::str::from_utf8(&payload[i + 5..i + 5 + name_len])
                            .ok()
                            .map(String::from);
                    }
                }
                return None;
            }

            i += ext_len;
        }
        None
    }

    /// Basic SSH parser
    fn parse_ssh(payload: &[u8]) -> Option<AppLayerInfo> {
        let text = std::str::from_utf8(payload).ok()?;
        if text.starts_with("SSH-") {
            let version = text.lines().next().map(String::from);
            Some(AppLayerInfo::Ssh(crate::packets::application::SshInfo {
                version,
                message_type: "Version Exchange".to_string(),
            }))
        } else {
            Some(AppLayerInfo::Ssh(crate::packets::application::SshInfo {
                version: None,
                message_type: "Encrypted".to_string(),
            }))
        }
    }
}