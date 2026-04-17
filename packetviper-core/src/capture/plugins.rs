//! Plugin system for custom protocol parsers

use crate::packets::application::AppLayerInfo;

/// Trait that all protocol parser plugins must implement
pub trait ProtocolPlugin: Send + Sync {
    /// Name of the protocol
    fn name(&self) -> &str;

    /// Ports this plugin should be tried on (empty = try on all)
    fn ports(&self) -> Vec<u16>;

    /// Try to parse the payload. Return None if this plugin doesn't match.
    fn parse(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> Option<AppLayerInfo>;

    /// Short description of the plugin
    fn description(&self) -> &str;
}

/// Registry that holds all protocol parser plugins
pub struct PluginRegistry {
    plugins: Vec<Box<dyn ProtocolPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        let mut registry = Self {
            plugins: Vec::new(),
        };
        // Register built-in plugins
        registry.register(Box::new(FtpPlugin));
        registry.register(Box::new(SmtpPlugin));
        registry.register(Box::new(MqttPlugin));
        registry
    }

    pub fn register(&mut self, plugin: Box<dyn ProtocolPlugin>) {
        log::info!("Registered protocol plugin: {}", plugin.name());
        self.plugins.push(plugin);
    }

    /// Try all plugins on a payload
    pub fn try_parse(&self, src_port: u16, dst_port: u16, payload: &[u8]) -> Option<AppLayerInfo> {
        for plugin in &self.plugins {
            let ports = plugin.ports();
            if ports.is_empty() || ports.contains(&src_port) || ports.contains(&dst_port) {
                if let Some(info) = plugin.parse(src_port, dst_port, payload) {
                    return Some(info);
                }
            }
        }
        None
    }

    pub fn plugin_count(&self) -> usize {
        self.plugins.len()
    }

    pub fn plugin_names(&self) -> Vec<String> {
        self.plugins.iter().map(|p| p.name().to_string()).collect()
    }
}

// ==================== Built-in Plugins ====================

/// FTP Protocol Parser
struct FtpPlugin;

impl ProtocolPlugin for FtpPlugin {
    fn name(&self) -> &str { "FTP" }
    fn description(&self) -> &str { "File Transfer Protocol parser" }
    fn ports(&self) -> Vec<u16> { vec![21, 20] }

    fn parse(&self, src_port: u16, _dst_port: u16, payload: &[u8]) -> Option<AppLayerInfo> {
        if payload.is_empty() { return None; }
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?.trim();
        if first_line.is_empty() { return None; }

        // FTP Response (from server, port 21)
        if src_port == 21 {
            let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
            if let Some(code_str) = parts.first() {
                if let Ok(code) = code_str.parse::<u16>() {
                    if (100..600).contains(&code) {
                        return Some(AppLayerInfo::Ftp(crate::packets::application::FtpInfo {
                            command: None,
                            args: None,
                            response_code: Some(code),
                            response_message: parts.get(1).map(|s| s.to_string()),
                            is_response: true,
                        }));
                    }
                }
            }
        }

        // FTP Command (to server)
        let ftp_commands = [
            "USER", "PASS", "ACCT", "CWD", "CDUP", "SMNT", "QUIT", "REIN",
            "PORT", "PASV", "TYPE", "STRU", "MODE", "RETR", "STOR", "STOU",
            "APPE", "ALLO", "REST", "RNFR", "RNTO", "ABOR", "DELE", "RMD",
            "MKD", "PWD", "LIST", "NLST", "SITE", "SYST", "STAT", "HELP",
            "NOOP", "FEAT", "OPTS", "AUTH", "PBSZ", "PROT", "EPRT", "EPSV",
        ];

        let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();
        if ftp_commands.contains(&cmd.as_str()) {
            return Some(AppLayerInfo::Ftp(crate::packets::application::FtpInfo {
                command: Some(cmd),
                args: parts.get(1).map(|s| s.to_string()),
                response_code: None,
                response_message: None,
                is_response: false,
            }));
        }

        None
    }
}

/// SMTP Protocol Parser
struct SmtpPlugin;

impl ProtocolPlugin for SmtpPlugin {
    fn name(&self) -> &str { "SMTP" }
    fn description(&self) -> &str { "Simple Mail Transfer Protocol parser" }
    fn ports(&self) -> Vec<u16> { vec![25, 465, 587] }

    fn parse(&self, src_port: u16, _dst_port: u16, payload: &[u8]) -> Option<AppLayerInfo> {
        if payload.is_empty() { return None; }
        let text = std::str::from_utf8(payload).ok()?;
        let first_line = text.lines().next()?.trim();
        if first_line.is_empty() { return None; }

        // SMTP Response
        if src_port == 25 || src_port == 465 || src_port == 587 {
            let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
            if let Some(code_str) = parts.first() {
                if let Ok(code) = code_str.parse::<u16>() {
                    if (200..600).contains(&code) {
                        return Some(AppLayerInfo::Smtp(crate::packets::application::SmtpInfo {
                            command: None,
                            args: None,
                            response_code: Some(code),
                            response_message: parts.get(1).map(|s| s.to_string()),
                            is_response: true,
                            from: None,
                            to: None,
                        }));
                    }
                }
            }
        }

        // SMTP Commands
        let smtp_commands = [
            "HELO", "EHLO", "MAIL", "RCPT", "DATA", "RSET", "VRFY", "EXPN",
            "HELP", "NOOP", "QUIT", "STARTTLS", "AUTH",
        ];

        let parts: Vec<&str> = first_line.splitn(2, ' ').collect();
        let cmd = parts[0].to_uppercase();

        if smtp_commands.contains(&cmd.as_str()) {
            let args = parts.get(1).map(|s| s.to_string());
            let mut from = None;
            let mut to = None;

            // Extract email addresses
            if cmd == "MAIL" {
                from = args.as_ref().and_then(|a| {
                    a.find('<').and_then(|start| {
                        a.find('>').map(|end| a[start + 1..end].to_string())
                    })
                });
            } else if cmd == "RCPT" {
                to = args.as_ref().and_then(|a| {
                    a.find('<').and_then(|start| {
                        a.find('>').map(|end| a[start + 1..end].to_string())
                    })
                });
            }

            return Some(AppLayerInfo::Smtp(crate::packets::application::SmtpInfo {
                command: Some(cmd),
                args,
                response_code: None,
                response_message: None,
                is_response: false,
                from,
                to,
            }));
        }

        None
    }
}

/// MQTT Protocol Parser
struct MqttPlugin;

impl ProtocolPlugin for MqttPlugin {
    fn name(&self) -> &str { "MQTT" }
    fn description(&self) -> &str { "Message Queuing Telemetry Transport parser" }
    fn ports(&self) -> Vec<u16> { vec![1883, 8883] }

    fn parse(&self, _src_port: u16, _dst_port: u16, payload: &[u8]) -> Option<AppLayerInfo> {
        if payload.len() < 2 { return None; }

        let packet_type = (payload[0] >> 4) & 0x0F;
        let flags = payload[0] & 0x0F;

        let type_name = match packet_type {
            1 => "CONNECT",
            2 => "CONNACK",
            3 => "PUBLISH",
            4 => "PUBACK",
            5 => "PUBREC",
            6 => "PUBREL",
            7 => "PUBCOMP",
            8 => "SUBSCRIBE",
            9 => "SUBACK",
            10 => "UNSUBSCRIBE",
            11 => "UNSUBACK",
            12 => "PINGREQ",
            13 => "PINGRESP",
            14 => "DISCONNECT",
            _ => return None,
        };

        // Decode remaining length (variable-length encoding)
        let mut remaining_length: u32 = 0;
        let mut multiplier: u32 = 1;
        let mut i = 1;
        loop {
            if i >= payload.len() { return None; }
            remaining_length += ((payload[i] & 0x7F) as u32) * multiplier;
            if payload[i] & 0x80 == 0 { break; }
            multiplier *= 128;
            i += 1;
            if multiplier > 128 * 128 * 128 { return None; }
        }
        let header_len = i + 1;

        // Validate total length
        if payload.len() < header_len + remaining_length as usize {
            // Might be fragmented, still report what we know
        }

        let mut topic = None;
        let mut client_id = None;

        // Parse CONNECT
        if packet_type == 1 && payload.len() > header_len + 10 {
            let var_start = header_len;
            // Skip protocol name + version + flags + keepalive
            if payload.len() > var_start + 10 {
                let proto_len = u16::from_be_bytes([
                    payload[var_start],
                    payload[var_start + 1],
                ]) as usize;
                let client_id_offset = var_start + 2 + proto_len + 4; // +version+flags+keepalive
                if client_id_offset + 2 < payload.len() {
                    let cid_len = u16::from_be_bytes([
                        payload[client_id_offset],
                        payload[client_id_offset + 1],
                    ]) as usize;
                    if client_id_offset + 2 + cid_len <= payload.len() {
                        client_id = std::str::from_utf8(
                            &payload[client_id_offset + 2..client_id_offset + 2 + cid_len],
                        )
                        .ok()
                        .map(String::from);
                    }
                }
            }
        }

        // Parse PUBLISH — extract topic
        if packet_type == 3 && payload.len() > header_len + 2 {
            let topic_len = u16::from_be_bytes([
                payload[header_len],
                payload[header_len + 1],
            ]) as usize;
            if header_len + 2 + topic_len <= payload.len() {
                topic = std::str::from_utf8(&payload[header_len + 2..header_len + 2 + topic_len])
                    .ok()
                    .map(String::from);
            }
        }

        Some(AppLayerInfo::Mqtt(crate::packets::application::MqttInfo {
            message_type: type_name.to_string(),
            message_type_id: packet_type,
            flags,
            remaining_length,
            topic,
            client_id,
        }))
    }
}