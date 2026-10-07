//! OS-specific system actions: firewall rules, neighbour (ARP) pinning, interface control and
//! default-gateway discovery. Each function has a Linux, Windows and macOS implementation.
//!
//! All commands run with stdio detached so nothing is written over the TUI. On Linux/macOS they go
//! through `sudo -n` (never prompts); on Windows the program itself must run as Administrator.

use std::io::Write;
use std::process::{Command, Stdio};

/// Name of the firewall backend, for display.
pub fn firewall_name() -> &'static str {
    if cfg!(target_os = "linux") { "iptables" } else if cfg!(windows) { "Windows Firewall" } else if cfg!(target_os = "macos") { "pf" } else { "none" }
}

/// What the user must do to give PacketViper the rights it needs.
pub fn privilege_hint() -> &'static str {
    if cfg!(windows) { "run PacketViper as Administrator" } else { "run with sudo (or allow passwordless sudo)" }
}

/// Whether firewall rules can be added right now (correct privileges and backend present).
pub fn firewall_available() -> bool {
    #[cfg(target_os = "linux")] { run(&["iptables", "-S", "INPUT"]) }
    // `net session` only succeeds in an elevated (Administrator) process.
    #[cfg(windows)] { run(&["net", "session"]) }
    #[cfg(target_os = "macos")] { run(&["pfctl", "-s", "info"]) }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { false }
}

/// Whether MAC-address blocking is supported (Linux only; Windows Firewall and pf can't match MACs).
pub fn mac_blocking_supported() -> bool { cfg!(target_os = "linux") }

/// Drops inbound traffic from `ip`.
pub fn block_ip(ip: &str) -> bool {
    #[cfg(target_os = "linux")] { run(&[iptables_for(ip), "-I", "INPUT", "-s", ip, "-j", "DROP"]) }
    #[cfg(windows)] {
        run(&["netsh", "advfirewall", "firewall", "add", "rule", &format!("name=PacketViper-{}", ip), "dir=in", "action=block", &format!("remoteip={}", ip)])
    }
    #[cfg(target_os = "macos")] { pf_ready() && run(&["pfctl", "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "add", ip]) }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { let _ = ip; false }
}

pub fn unblock_ip(ip: &str) -> bool {
    #[cfg(target_os = "linux")] { run(&[iptables_for(ip), "-D", "INPUT", "-s", ip, "-j", "DROP"]) }
    #[cfg(windows)] { run(&["netsh", "advfirewall", "firewall", "delete", "rule", &format!("name=PacketViper-{}", ip)]) }
    #[cfg(target_os = "macos")] { run(&["pfctl", "-a", PF_ANCHOR, "-t", PF_TABLE, "-T", "delete", ip]) }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { let _ = ip; false }
}

/// Drops inbound IPv4/IPv6 traffic from a MAC address. Linux only; returns false elsewhere.
pub fn block_mac(mac: &str) -> bool {
    #[cfg(target_os = "linux")] {
        let args = ["-I", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"];
        let ok = run(&[&["iptables"][..], &args].concat());
        if ok { run(&[&["ip6tables"][..], &args].concat()); }
        ok
    }
    #[cfg(not(target_os = "linux"))] { let _ = mac; false }
}

pub fn unblock_mac(mac: &str) -> bool {
    #[cfg(target_os = "linux")] {
        let args = ["-D", "INPUT", "-m", "mac", "--mac-source", mac, "-j", "DROP"];
        run(&[&["ip6tables"][..], &args].concat());
        run(&[&["iptables"][..], &args].concat())
    }
    #[cfg(not(target_os = "linux"))] { let _ = mac; false }
}

/// Pins `ip` to `mac` with a static neighbour (ARP) entry, so ARP poisoning can't redirect it.
pub fn pin_neighbor(iface: &str, ip: &str, mac: &str) -> bool {
    #[cfg(target_os = "linux")] { run(&["ip", "neigh", "replace", ip, "lladdr", mac, "nud", "permanent", "dev", iface]) }
    #[cfg(windows)] {
        let Some(idx) = interface_index(iface) else { return false };
        run(&["netsh", "interface", "ipv4", "set", "neighbors", &format!("interface={}", idx), &format!("address={}", ip), &format!("neighbor={}", mac.replace(':', "-")), "store=active"])
    }
    #[cfg(target_os = "macos")] { let _ = iface; run(&["arp", "-S", ip, mac]) }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { let _ = (iface, ip, mac); false }
}

pub fn unpin_neighbor(iface: &str, ip: &str) -> bool {
    #[cfg(target_os = "linux")] { run(&["ip", "neigh", "del", ip, "dev", iface]) }
    #[cfg(windows)] {
        let Some(idx) = interface_index(iface) else { return false };
        run(&["netsh", "interface", "ipv4", "delete", "neighbors", &format!("interface={}", idx), &format!("address={}", ip)])
    }
    #[cfg(target_os = "macos")] { let _ = iface; run(&["arp", "-d", ip]) }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { let _ = (iface, ip); false }
}

/// Takes the network interface down (emergency disconnect).
pub fn interface_down(iface: &str) -> bool {
    #[cfg(target_os = "linux")] { run(&["ip", "link", "set", "dev", iface, "down"]) }
    #[cfg(windows)] {
        let Some(idx) = interface_index(iface) else { return false };
        run(&["powershell", "-NoProfile", "-NonInteractive", "-Command", &format!("Disable-NetAdapter -InterfaceIndex {} -Confirm:$false", idx)])
    }
    #[cfg(target_os = "macos")] { run(&["ifconfig", iface, "down"]) }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { let _ = iface; false }
}

/// Command that brings the interface back up, shown to the user after `interface_down`.
pub fn interface_up_hint(iface: &str) -> String {
    if cfg!(target_os = "linux") { format!("sudo ip link set dev {} up", iface) }
    else if cfg!(windows) { "re-enable the adapter in Settings > Network (or Enable-NetAdapter as Administrator)".to_string() }
    else { format!("sudo ifconfig {} up", iface) }
}

/// Default gateway (IP, MAC) for `iface`, read from the OS routing and ARP tables.
pub fn default_gateway(iface: &str) -> Option<(String, String)> {
    #[cfg(target_os = "linux")] {
        let routes = std::fs::read_to_string("/proc/net/route").ok()?;
        let arp = std::fs::read_to_string("/proc/net/arp").ok()?;
        parse_linux_gateway(iface, &routes, &arp)
    }
    #[cfg(windows)] {
        // Match the default route by this interface's IPv4 address (route print shows IPs, not names).
        let ips = interface_ipv4s(iface);
        let routes = output(&["route", "print", "-4", "0.0.0.0"])?;
        let ip = parse_windows_gateway(&routes, &ips)?;
        let arp = output(&["arp", "-a", &ip])?;
        let mac = parse_windows_arp(&arp, &ip)?;
        Some((ip, mac))
    }
    #[cfg(target_os = "macos")] {
        let route = output(&["route", "-n", "get", "default"])?;
        let ip = parse_macos_gateway(&route, iface)?;
        let arp = output(&["arp", "-n", &ip])?;
        let mac = parse_macos_arp(&arp)?;
        Some((ip, mac))
    }
    #[cfg(not(any(target_os = "linux", windows, target_os = "macos")))] { let _ = iface; None }
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_gateway(iface: &str, routes: &str, arp: &str) -> Option<(String, String)> {
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

/// `route print -4 0.0.0.0` rows: "0.0.0.0  0.0.0.0  <gateway>  <interface ip>  <metric>".
#[cfg(any(windows, test))]
fn parse_windows_gateway(routes: &str, iface_ips: &[String]) -> Option<String> {
    routes.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        (f.len() >= 4 && f[0] == "0.0.0.0" && f[1] == "0.0.0.0" && f[2].parse::<std::net::Ipv4Addr>().is_ok()
            && (iface_ips.is_empty() || iface_ips.iter().any(|ip| ip == f[3]))).then(|| f[2].to_string())
    })
}

/// `arp -a <ip>` rows: "  192.168.1.1   b4-86-18-ba-6a-1e   dynamic".
#[cfg(any(windows, test))]
fn parse_windows_arp(arp: &str, ip: &str) -> Option<String> {
    arp.lines().find_map(|l| {
        let f: Vec<&str> = l.split_whitespace().collect();
        if f.len() >= 2 && f[0] == ip { normalize_mac(&f[1].replace('-', ":")) } else { None }
    })
}

/// `route -n get default` lines: "gateway: 192.168.1.1", "interface: en0".
#[cfg(any(target_os = "macos", test))]
fn parse_macos_gateway(route: &str, iface: &str) -> Option<String> {
    let field = |name: &str| route.lines().find_map(|l| l.trim().strip_prefix(name).map(|v| v.trim().to_string()));
    let gw = field("gateway:")?;
    if field("interface:").is_some_and(|i| i != iface) { return None; }
    gw.parse::<std::net::Ipv4Addr>().ok().map(|_| gw)
}

/// `arp -n <ip>`: "? (192.168.1.1) at b4:86:18:ba:6a:1e on en0 ifscope [ethernet]". macOS drops leading zeros.
#[cfg(any(target_os = "macos", test))]
fn parse_macos_arp(arp: &str) -> Option<String> {
    let mac = arp.split_whitespace().skip_while(|w| *w != "at").nth(1)?;
    normalize_mac(mac)
}

/// Lowercase, colon-separated, two hex digits per octet; None if not a MAC (e.g. "(incomplete)").
#[cfg(any(windows, target_os = "macos", test))]
fn normalize_mac(mac: &str) -> Option<String> {
    let parts: Vec<String> = mac.split(':').map(|p| format!("{:0>2}", p.to_lowercase())).collect();
    let valid = parts.len() == 6 && parts.iter().all(|p| p.len() == 2 && p.chars().all(|c| c.is_ascii_hexdigit()));
    (valid && parts.iter().any(|p| p != "00")).then(|| parts.join(":"))
}

#[cfg(target_os = "linux")]
fn iptables_for(ip: &str) -> &'static str {
    if ip.contains(':') { "ip6tables" } else { "iptables" }
}

#[cfg(windows)]
fn interface_index(name: &str) -> Option<u32> {
    pnet_datalink::interfaces().into_iter().find(|i| i.name == name).map(|i| i.index)
}

#[cfg(windows)]
fn interface_ipv4s(name: &str) -> Vec<String> {
    pnet_datalink::interfaces().into_iter().filter(|i| i.name == name)
        .flat_map(|i| i.ips).filter(|ip| ip.is_ipv4()).map(|ip| ip.ip().to_string()).collect()
}

#[cfg(target_os = "macos")]
const PF_ANCHOR: &str = "com.apple/packetviper";
#[cfg(target_os = "macos")]
const PF_TABLE: &str = "packetviper";

/// Loads PacketViper's pf rule (drop anything from the table) under an anchor the default macOS
/// ruleset already evaluates, and makes sure pf is enabled.
// ponytail: leaves pf enabled on exit (the table is emptied); track the `pfctl -E` token to restore exactly.
#[cfg(target_os = "macos")]
fn pf_ready() -> bool {
    use std::sync::OnceLock;
    static READY: OnceLock<bool> = OnceLock::new();
    *READY.get_or_init(|| {
        let rule = format!("table <{t}> persist\nblock drop in quick from <{t}>\n", t = PF_TABLE);
        let loaded = run_with_stdin(&["pfctl", "-a", PF_ANCHOR, "-f", "-"], rule.as_bytes());
        run(&["pfctl", "-e"]); // fails harmlessly when pf is already enabled
        loaded
    })
}

/// Runs a privileged command quietly. Returns true on success.
fn run(args: &[&str]) -> bool {
    run_with_stdin(args, &[])
}

fn run_with_stdin(args: &[&str], input: &[u8]) -> bool {
    let mut cmd = privileged(args);
    cmd.stdin(if input.is_empty() { Stdio::null() } else { Stdio::piped() }).stdout(Stdio::null()).stderr(Stdio::null());
    let Ok(mut child) = cmd.spawn() else { return false };
    if let Some(mut stdin) = child.stdin.take() {
        let _ = stdin.write_all(input);
    }
    child.wait().map(|s| s.success()).unwrap_or(false)
}

/// Runs a read-only command and returns its stdout.
#[cfg(any(windows, target_os = "macos"))]
fn output(args: &[&str]) -> Option<String> {
    let out = privileged(args).stdin(Stdio::null()).stderr(Stdio::null()).output().ok()?;
    out.status.success().then(|| String::from_utf8_lossy(&out.stdout).into_owned())
}

fn privileged(args: &[&str]) -> Command {
    #[cfg(unix)] {
        let mut c = Command::new("sudo");
        c.arg("-n").args(args);
        c
    }
    #[cfg(windows)] {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        let mut c = Command::new(args[0]);
        c.args(&args[1..]).creation_flags(CREATE_NO_WINDOW);
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_gateway() {
        let routes = "Iface\tDestination\tGateway\nwlan0\t00000000\t0101A8C0\t0003\ndocker0\t000011AC\t00000000\t0001\n";
        let arp = "IP address HW type Flags HW address Mask Device\n192.168.1.1 0x1 0x2 B4:86:18:BA:6A:1E * wlan0\n";
        assert_eq!(parse_linux_gateway("wlan0", routes, arp), Some(("192.168.1.1".into(), "b4:86:18:ba:6a:1e".into())));
        assert_eq!(parse_linux_gateway("eth0", routes, arp), None);
    }

    #[test]
    fn parses_windows_gateway_and_arp() {
        let routes = "IPv4 Route Table\n===\nActive Routes:\nNetwork Destination        Netmask          Gateway       Interface  Metric\n          0.0.0.0          0.0.0.0      192.168.1.1    192.168.1.41     35\n";
        assert_eq!(parse_windows_gateway(routes, &["192.168.1.41".into()]), Some("192.168.1.1".into()));
        assert_eq!(parse_windows_gateway(routes, &["10.0.0.5".into()]), None);
        let arp = "\nInterface: 192.168.1.41 --- 0x5\n  Internet Address      Physical Address      Type\n  192.168.1.1           b4-86-18-ba-6a-1e     dynamic\n";
        assert_eq!(parse_windows_arp(arp, "192.168.1.1"), Some("b4:86:18:ba:6a:1e".into()));
    }

    #[test]
    fn parses_macos_gateway_and_arp() {
        let route = "   route to: default\ndestination: default\n       mask: default\n    gateway: 192.168.1.1\n  interface: en0\n";
        assert_eq!(parse_macos_gateway(route, "en0"), Some("192.168.1.1".into()));
        assert_eq!(parse_macos_gateway(route, "en1"), None);
        assert_eq!(parse_macos_arp("? (192.168.1.1) at b4:86:18:ba:6a:1e on en0 ifscope [ethernet]"), Some("b4:86:18:ba:6a:1e".into()));
        assert_eq!(parse_macos_arp("? (192.168.1.1) at 0:1:2:a:b:c on en0"), Some("00:01:02:0a:0b:0c".into()));
        assert_eq!(parse_macos_arp("? (192.168.1.9) at (incomplete) on en0"), None);
    }
}
