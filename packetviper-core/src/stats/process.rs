//! Maps network traffic to the local process that owns it, so the UI can show *which app* is
//! uploading. Linux implementation parses /proc; other OSes return no attribution (stub) for now.
//!
//! Lookup is by local port: an outgoing packet's source port identifies the local socket, which
//! /proc/net/{tcp,udp}* ties to an inode, which /proc/<pid>/fd ties to a process.

use std::collections::HashMap;
use chrono::{DateTime, Duration, Local};

#[derive(Debug, Clone)]
pub struct ProcInfo {
    pub pid: u32,
    pub name: String,
}

/// Rolling outbound/inbound byte counters for one process, over the last window.
#[derive(Debug, Clone, Default)]
pub struct ProcTraffic {
    pub name: String,
    pub pid: u32,
    pub out_bytes: u64,
    pub in_bytes: u64,
    /// Public (internet) destinations this process sent to, for the exfiltration view.
    pub remote_ips: std::collections::HashSet<String>,
}

pub struct ProcessResolver {
    /// local port -> owning process.
    port_map: HashMap<u16, ProcInfo>,
    last_refresh: Option<DateTime<Local>>,
    /// How often the (expensive) /proc scan runs.
    refresh_secs: i64,
    available: bool,
}

impl Default for ProcessResolver {
    fn default() -> Self { Self::new() }
}

impl ProcessResolver {
    pub fn new() -> Self {
        Self { port_map: HashMap::new(), last_refresh: None, refresh_secs: 2, available: cfg!(target_os = "linux") }
    }

    /// Whether per-process attribution works on this OS.
    pub fn is_available(&self) -> bool { self.available }

    /// Rebuilds the port->process map if the refresh interval has passed. `now` is the latest
    /// packet timestamp so the throttle uses capture time, not wall clock.
    pub fn maybe_refresh(&mut self, now: DateTime<Local>) {
        if !self.available { return; }
        if self.last_refresh.is_some_and(|t| now.signed_duration_since(t) < Duration::seconds(self.refresh_secs)) {
            return;
        }
        self.last_refresh = Some(now);
        #[cfg(target_os = "linux")]
        { self.port_map = linux::build_port_map(); }
    }

    /// The process owning `local_port`, if known from the last refresh.
    pub fn lookup(&self, local_port: u16) -> Option<&ProcInfo> {
        self.port_map.get(&local_port)
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use super::ProcInfo;
    use std::collections::HashMap;
    use std::fs;

    /// Builds local-port -> process by joining /proc/net sockets (port->inode) with /proc/<pid>/fd (inode->pid).
    pub fn build_port_map() -> HashMap<u16, ProcInfo> {
        // inode -> local port (from all four socket tables).
        let mut inode_port: HashMap<u64, u16> = HashMap::new();
        for path in ["/proc/net/tcp", "/proc/net/tcp6", "/proc/net/udp", "/proc/net/udp6"] {
            if let Ok(data) = fs::read_to_string(path) {
                parse_net_table(&data, &mut inode_port);
            }
        }
        if inode_port.is_empty() { return HashMap::new(); }

        // Scan /proc/<pid>/fd for socket:[inode] links, mapping the inodes we care about to a pid.
        let mut port_map: HashMap<u16, ProcInfo> = HashMap::new();
        let Ok(entries) = fs::read_dir("/proc") else { return port_map };
        for entry in entries.flatten() {
            let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() else { continue };
            let fd_dir = format!("/proc/{}/fd", pid);
            let Ok(fds) = fs::read_dir(&fd_dir) else { continue };
            let mut name: Option<String> = None;
            for fd in fds.flatten() {
                let Ok(target) = fs::read_link(fd.path()) else { continue };
                let t = target.to_string_lossy();
                let Some(inode) = t.strip_prefix("socket:[").and_then(|r| r.strip_suffix(']')).and_then(|n| n.parse::<u64>().ok()) else { continue };
                let Some(&port) = inode_port.get(&inode) else { continue };
                let n = name.get_or_insert_with(|| proc_name(pid));
                port_map.entry(port).or_insert_with(|| ProcInfo { pid, name: n.clone() });
            }
        }
        port_map
    }

    /// Reads /proc/<pid>/comm (short name), falling back to the basename of the cmdline.
    /// A process can set its own name, so the result is sanitized (control chars stripped) before
    /// it ever reaches the TUI, and capped in length.
    fn proc_name(pid: u32) -> String {
        let raw = fs::read_to_string(format!("/proc/{}/comm", pid))
            .ok()
            .map(|c| c.trim().to_string())
            .filter(|s| !s.is_empty())
            .or_else(|| fs::read_to_string(format!("/proc/{}/cmdline", pid)).ok()
                .and_then(|c| c.split('\0').next().map(|s| s.rsplit('/').next().unwrap_or(s).to_string()))
                .filter(|s| !s.is_empty()))
            .unwrap_or_else(|| format!("pid {}", pid));
        crate::packets::sanitize(raw.chars().take(64).collect::<String>().as_str())
    }

    /// Each row after the header: "sl local_addr:port rem_addr:port st ... inode" with inode at field 9.
    fn parse_net_table(data: &str, out: &mut HashMap<u64, u16>) {
        for line in data.lines().skip(1) {
            let f: Vec<&str> = line.split_whitespace().collect();
            if f.len() < 10 { continue; }
            let Some(port_hex) = f[1].rsplit(':').next() else { continue };
            let Ok(port) = u16::from_str_radix(port_hex, 16) else { continue };
            let Ok(inode) = f[9].parse::<u64>() else { continue };
            if inode != 0 { out.insert(inode, port); }
        }
    }

    #[cfg(test)]
    pub(super) fn parse_net_table_test(data: &str) -> HashMap<u64, u16> {
        let mut m = HashMap::new();
        parse_net_table(data, &mut m);
        m
    }
}

use crate::packets::{CapturedPacket, PacketDirection};
use crate::packets::transport::TransportLayerInfo;

/// Tracks how many bytes each local process has sent/received this session, so the UI can answer
/// "which app is uploading?". Attribution is best-effort and Linux-only (see `ProcessResolver`).
/// Upper bound on tracked processes, so PID churn or spoofing can't grow memory without limit.
const MAX_PROCS: usize = 4096;

pub struct NetMonitor {
    resolver: ProcessResolver,
    by_pid: HashMap<u32, ProcTraffic>,
    /// Bytes we could not attribute to any process (e.g. refresh missed a short-lived socket).
    pub unattributed_out: u64,
}

impl Default for NetMonitor {
    fn default() -> Self { Self::new() }
}

impl NetMonitor {
    pub fn new() -> Self {
        Self { resolver: ProcessResolver::new(), by_pid: HashMap::new(), unattributed_out: 0 }
    }

    pub fn is_available(&self) -> bool { self.resolver.is_available() }

    pub fn record(&mut self, packet: &CapturedPacket) {
        if !self.resolver.is_available() { return; }
        self.resolver.maybe_refresh(packet.timestamp);
        let outgoing = packet.direction == PacketDirection::Outgoing;
        // The local port is our own side: source port when sending, destination port when receiving.
        let local_port = match &packet.layers.transport {
            Some(TransportLayerInfo::Tcp(t)) => if outgoing { t.src_port } else { t.dst_port },
            Some(TransportLayerInfo::Udp(u)) => if outgoing { u.src_port } else { u.dst_port },
            None => return,
        };
        let Some(proc) = self.resolver.lookup(local_port) else {
            if outgoing { self.unattributed_out += packet.length as u64; }
            return;
        };
        let (pid, name) = (proc.pid, proc.name.clone());
        let entry = self.by_pid.entry(pid).or_insert_with(|| ProcTraffic { name: name.clone(), pid, ..Default::default() });
        entry.name = name;
        if outgoing {
            entry.out_bytes += packet.length as u64;
            if let Some(dst) = packet.dst_ip() {
                if crate::threat::detector::is_public_addr(dst) { entry.remote_ips.insert(dst.to_string()); }
            }
        } else {
            entry.in_bytes += packet.length as u64;
        }
        // Normal systems have hundreds of processes; cap in case of PID churn/spoofing so the map
        // can't grow without bound. Drop the lowest-traffic entries when over the cap.
        if self.by_pid.len() > MAX_PROCS {
            let mut totals: Vec<(u32, u64)> = self.by_pid.iter().map(|(p, t)| (*p, t.out_bytes + t.in_bytes)).collect();
            totals.sort_by_key(|(_, b)| *b);
            for (pid, _) in totals.into_iter().take(self.by_pid.len() - MAX_PROCS) {
                self.by_pid.remove(&pid);
            }
        }
    }

    /// Processes sorted by bytes uploaded (most first), up to `n`.
    pub fn top_uploaders(&self, n: usize) -> Vec<&ProcTraffic> {
        let mut v: Vec<&ProcTraffic> = self.by_pid.values().collect();
        v.sort_by(|a, b| b.out_bytes.cmp(&a.out_bytes));
        v.truncate(n);
        v
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[test]
    fn parses_net_table() {
        let data = "  sl  local_address rem_address   st ... inode\n   0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 54321 1 ffff 100 0 0 10 0\n";
        let m = super::linux::parse_net_table_test(data);
        assert_eq!(m.get(&54321), Some(&0x1F90)); // 0x1F90 = 8080
    }
}
