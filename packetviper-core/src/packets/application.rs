//! Application Layer (Layer 7) packet structures

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppLayerInfo {
    Http(HttpInfo),
    Dns(DnsInfo),
    Tls(TlsInfo),
    Ssh(SshInfo),
    Dhcp(DhcpInfo),
    Ftp(FtpInfo),
    Smtp(SmtpInfo),
    Mqtt(MqttInfo),
    Unknown { port: u16 },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HttpInfo {
    pub method: Option<String>,
    pub uri: Option<String>,
    pub version: String,
    pub status_code: Option<u16>,
    pub host: Option<String>,
    pub user_agent: Option<String>,
    pub content_type: Option<String>,
    pub content_length: Option<usize>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsInfo {
    pub query_id: u16,
    pub is_response: bool,
    pub opcode: u8,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsAnswer>,
    pub response_code: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsQuestion {
    pub name: String,
    pub record_type: String,
    pub class: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub data: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub version: String,
    pub content_type: String,
    pub handshake_type: Option<String>,
    pub sni: Option<String>,
    pub cipher_suite: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshInfo {
    pub version: Option<String>,
    pub message_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpInfo {
    pub message_type: String,
    pub client_ip: Option<String>,
    pub your_ip: Option<String>,
    pub server_ip: Option<String>,
    pub client_mac: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FtpInfo {
    pub command: Option<String>,
    pub args: Option<String>,
    pub response_code: Option<u16>,
    pub response_message: Option<String>,
    pub is_response: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SmtpInfo {
    pub command: Option<String>,
    pub args: Option<String>,
    pub response_code: Option<u16>,
    pub response_message: Option<String>,
    pub is_response: bool,
    pub from: Option<String>,
    pub to: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MqttInfo {
    pub message_type: String,
    pub message_type_id: u8,
    pub flags: u8,
    pub remaining_length: u32,
    pub topic: Option<String>,
    pub client_id: Option<String>,
}

impl std::fmt::Display for AppLayerInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AppLayerInfo::Http(http) => {
                if let Some(method) = &http.method {
                    write!(f, "HTTP {} {}", method, http.uri.as_deref().unwrap_or(""))
                } else if let Some(code) = http.status_code {
                    write!(f, "HTTP {} {}", code, http.version)
                } else {
                    write!(f, "HTTP {}", http.version)
                }
            }
            AppLayerInfo::Dns(dns) => {
                if dns.is_response {
                    write!(f, "DNS Response (answers: {})", dns.answers.len())
                } else {
                    let names: Vec<&str> = dns.questions.iter().map(|q| q.name.as_str()).collect();
                    write!(f, "DNS Query: {}", names.join(", "))
                }
            }
            AppLayerInfo::Tls(tls) => {
                write!(f, "TLS {} {}", tls.version, tls.sni.as_deref().unwrap_or(""))
            }
            AppLayerInfo::Ssh(ssh) => {
                write!(f, "SSH {}", ssh.version.as_deref().unwrap_or(&ssh.message_type))
            }
            AppLayerInfo::Dhcp(dhcp) => write!(f, "DHCP {}", dhcp.message_type),
            AppLayerInfo::Ftp(ftp) => {
                if ftp.is_response {
                    write!(f, "FTP {} {}", 
                        ftp.response_code.unwrap_or(0),
                        ftp.response_message.as_deref().unwrap_or(""))
                } else {
                    write!(f, "FTP {} {}", 
                        ftp.command.as_deref().unwrap_or(""),
                        ftp.args.as_deref().unwrap_or(""))
                }
            }
            AppLayerInfo::Smtp(smtp) => {
                if smtp.is_response {
                    write!(f, "SMTP {} {}", 
                        smtp.response_code.unwrap_or(0),
                        smtp.response_message.as_deref().unwrap_or(""))
                } else {
                    write!(f, "SMTP {} {}", 
                        smtp.command.as_deref().unwrap_or(""),
                        smtp.args.as_deref().unwrap_or(""))
                }
            }
            AppLayerInfo::Mqtt(mqtt) => {
                if let Some(topic) = &mqtt.topic {
                    write!(f, "MQTT {} topic:{}", mqtt.message_type, topic)
                } else {
                    write!(f, "MQTT {}", mqtt.message_type)
                }
            }
            AppLayerInfo::Unknown { port } => write!(f, "Unknown (port: {})", port),
        }
    }
}