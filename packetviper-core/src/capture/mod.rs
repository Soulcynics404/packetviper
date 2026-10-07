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

/// Default gateway (IP, MAC) for `iface`, from the kernel routing and ARP tables (Linux).
/// Read at startup so the baseline predates any ARP poisoning that starts later.
pub fn default_gateway(iface: &str) -> Option<(String, String)> {
    let routes = std::fs::read_to_string("/proc/net/route").ok()?;
    let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
    parse_default_gateway(iface, &routes, &arp)
}

fn parse_default_gateway(iface: &str, routes: &str, arp: &str) -> Option<(String, String)> {
    // Destination 00000000 = default route; Gateway is a little-endian hex IPv4.
    let gw_hex = routes.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 2 && f[0] == iface && f[1] == "00000000").then(|| f[2].to_string())
    })?;
    let ip = std::net::Ipv4Addr::from(u32::from_str_radix(&gw_hex, 16).ok()?.swap_bytes()).to_string();
    let mac = arp.lines().skip(1).find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() > 5 && f[0] == ip && f[5] == iface && f[3] != "00:00:00:00:00:00").then(|| f[3].to_lowercase())
    })?;
    Some((ip, mac))
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_default_gateway() {
        let routes = "Iface\tDestination\tGateway\nwlan0\t00000000\t0101A8C0\t0003\ndocker0\t000011AC\t00000000\t0001\n";
        let arp = "IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 B4:86:18:BA:6A:1E * wlan0\n";
        assert_eq!(super::parse_default_gateway("wlan0", routes, arp), Some(("192.168.1.1".into(), "b4:86:18:ba:6a:1e".into())));
        assert_eq!(super::parse_default_gateway("eth0", routes, arp), None);
    }
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