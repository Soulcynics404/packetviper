pub mod engine;
pub mod stream;
pub mod plugins;

pub fn list_interfaces() -> Vec<NetworkInterface> {
    pnet_datalink::interfaces()
        .into_iter()
        .map(|iface| NetworkInterface {
            name: iface.name.clone(),
            description: iface.description.clone(),
            mac: iface.mac.map(|m| m.to_string()),
            ips: iface.ips.iter().map(|ip| ip.to_string()).collect(),
            is_up: iface.is_up(),
            is_loopback: iface.is_loopback(),
            index: iface.index,
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct NetworkInterface {
    pub name: String,
    pub description: String,
    pub mac: Option<String>,
    pub ips: Vec<String>,
    pub is_up: bool,
    pub is_loopback: bool,
    pub index: u32,
}

impl std::fmt::Display for NetworkInterface {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let status = if self.is_up { "UP" } else { "DOWN" };
        let loopback = if self.is_loopback { " (loopback)" } else { "" };
        write!(f, "{} [{}{}] MAC:{} IPs:[{}]",
            self.name, status, loopback,
            self.mac.as_deref().unwrap_or("N/A"),
            self.ips.join(", "))
    }
}