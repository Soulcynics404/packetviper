//! Phone/web dashboard server. PacketViper (TUI or `serve` mode) runs a small HTTP server on the LAN;
//! a phone on the same Wi-Fi opens it to see live status and get danger alerts. Access needs a random
//! token (shown in the Connect screen / QR), so other devices on the network can't read your data.
//!
//! No framework: a std TcpListener serves a few routes. Live updates use Server-Sent Events (SSE),
//! which browsers consume with EventSource — no WebSocket handshake needed.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicBool, Ordering};

use serde::Serialize;

use crate::app::App;

/// Live snapshot the dashboard renders. Rebuilt from the App each tick and shared as JSON.
#[derive(Serialize, Clone, Default)]
pub struct Snapshot {
    pub interface: String,
    pub capturing: bool,
    pub autosave: bool,
    pub auto_block: bool,
    pub firewall_available: bool,
    pub total_packets: usize,
    pub total_bytes: u64,
    pub down_rate: u64,
    pub up_rate: u64,
    pub peak_up: u64,
    pub alert_count: usize,
    pub critical_count: usize,
    pub danger: bool,
    pub danger_critical: bool,
    pub danger_text: String,
    pub gateway: Option<String>,
    pub ring_mb: u64,
    pub alerts: Vec<AlertView>,
    pub uploaders: Vec<UploaderView>,
    pub blocks: Vec<BlockView>,
}

#[derive(Serialize, Clone)]
pub struct AlertView { pub level: String, pub time: String, pub category: String, pub description: String, pub source: String }
#[derive(Serialize, Clone)]
pub struct UploaderView { pub name: String, pub pid: u32, pub up: u64, pub down: u64, pub dests: usize }
#[derive(Serialize, Clone)]
pub struct BlockView { pub kind: String, pub target: String, pub reason: String }

impl Snapshot {
    /// Builds the dashboard snapshot from current app state.
    pub fn from_app(app: &App) -> Self {
        let td = &app.threat_detector;
        let alerts = td.alerts.iter().rev().take(50).map(|a| AlertView {
            level: a.level.to_string(),
            time: a.timestamp.format("%H:%M:%S").to_string(),
            category: a.category.clone(),
            description: a.description.clone(),
            source: a.source_ip.clone(),
        }).collect();
        let uploaders = app.net_monitor.top_uploaders(10).iter().map(|p| UploaderView {
            name: p.name.clone(), pid: p.pid, up: p.out_bytes, down: p.in_bytes, dests: p.remote_ips.len(),
        }).collect();
        let blocks = td.blocks_sorted().iter().map(|b| BlockView {
            kind: b.kind.to_string(), target: b.ip.clone(), reason: b.reason.clone(),
        }).collect();
        let (danger, danger_critical, danger_text) = match &app.alarm {
            Some(a) => (true, a.critical, format!("{}: {}", a.category, a.description)),
            None => (false, false, String::new()),
        };
        Snapshot {
            interface: app.interface.clone(),
            capturing: app.capturing,
            autosave: app.autosave_flag.load(Ordering::Relaxed),
            auto_block: td.auto_block,
            firewall_available: td.firewall_available,
            total_packets: app.packet_count(),
            total_bytes: app.total_bytes,
            down_rate: app.bandwidth_monitor.in_rate(),
            up_rate: app.bandwidth_monitor.out_rate(),
            peak_up: app.bandwidth_monitor.peak_out_rate(),
            alert_count: td.alert_count(),
            critical_count: td.critical_count(),
            danger, danger_critical, danger_text,
            gateway: td.gateway.as_ref().map(|(_, ip, _)| ip.clone()),
            ring_mb: app.config.ring_buffer_mb,
            alerts, uploaders, blocks,
        }
    }
}

/// Shared JSON snapshot the HTTP threads read; the main/serve loop refreshes it each tick.
pub type SharedJson = Arc<Mutex<String>>;

/// Handle to the running dashboard server (for the Connect screen).
#[derive(Clone)]
pub struct ServerHandle {
    pub url: String,
    pub running: Arc<AtomicBool>,
}

/// Starts the dashboard HTTP server on `port`, bound to all interfaces so the phone can reach it.
/// Returns a handle with the LAN URL + token to show in the Connect screen, or None if binding fails.
/// Max simultaneous dashboard connections, so a LAN peer can't exhaust threads by opening many
/// (especially long-lived SSE) sockets.
const MAX_CONN: usize = 48;
static ACTIVE_CONN: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Decrements the active-connection count when a handler ends (including SSE disconnects).
struct ConnGuard;
impl Drop for ConnGuard {
    fn drop(&mut self) { ACTIVE_CONN.fetch_sub(1, Ordering::Relaxed); }
}

pub fn start(port: u16, shared: SharedJson) -> Option<ServerHandle> {
    let Some(token) = random_token() else {
        log::error!("Dashboard not started: secure randomness unavailable for the access token");
        return None;
    };
    let listener = match TcpListener::bind(("0.0.0.0", port)) {
        Ok(l) => l,
        Err(e) => { log::warn!("Dashboard server could not bind port {}: {}", port, e); return None; }
    };
    let ip = lan_ip().unwrap_or_else(|| "127.0.0.1".to_string());
    let url = format!("http://{}:{}/?t={}", ip, port, token);
    let running = Arc::new(AtomicBool::new(true));
    log::info!("Dashboard server on {}", url);

    let token_srv = token.clone();
    let running_srv = running.clone();
    std::thread::spawn(move || {
        for stream in listener.incoming() {
            if !running_srv.load(Ordering::Relaxed) { break; }
            if let Ok(mut stream) = stream {
                // Cap concurrent connections; reject politely when at the limit.
                if ACTIVE_CONN.fetch_add(1, Ordering::Relaxed) >= MAX_CONN {
                    ACTIVE_CONN.fetch_sub(1, Ordering::Relaxed);
                    let _ = stream.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
                    continue;
                }
                // Timeouts stop a slow/idle client from pinning a thread forever.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));
                let token = token_srv.clone();
                let shared = shared.clone();
                // One thread per connection; SSE connections stay open, so don't block the accept loop.
                std::thread::spawn(move || {
                    let _guard = ConnGuard;
                    handle_conn(stream, &token, &shared);
                });
            }
        }
    });
    Some(ServerHandle { url, running })
}

fn handle_conn(mut stream: TcpStream, token: &str, shared: &SharedJson) {
    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) { Ok(n) => n, Err(_) => return };
    let req = String::from_utf8_lossy(&buf[..n]);
    let Some(line) = req.lines().next() else { return };
    let mut parts = line.split_whitespace();
    let (_method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let authed = query_token(query) == token;

    match path {
        "/" => send(&mut stream, "200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.as_bytes()),
        "/api/state" if authed => {
            let body = shared.lock().map(|s| s.clone()).unwrap_or_else(|_| "{}".into());
            send(&mut stream, "200 OK", "application/json", body.as_bytes());
        }
        "/api/events" if authed => stream_events(stream, shared),
        "/api/state" | "/api/events" => send(&mut stream, "401 Unauthorized", "text/plain", b"missing or wrong token"),
        _ => send(&mut stream, "404 Not Found", "text/plain", b"not found"),
    }
}

/// Server-Sent Events: push the current snapshot once a second until the client disconnects.
fn stream_events(mut stream: TcpStream, shared: &SharedJson) {
    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\nAccess-Control-Allow-Origin: *\r\n\r\n";
    if stream.write_all(headers.as_bytes()).is_err() { return; }
    loop {
        let body = shared.lock().map(|s| s.clone()).unwrap_or_default();
        let msg = format!("data: {}\n\n", body.replace('\n', " "));
        if stream.write_all(msg.as_bytes()).is_err() { break; }
        if stream.flush().is_err() { break; }
        std::thread::sleep(std::time::Duration::from_millis(1000));
    }
}

fn send(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let header = format!(
        "HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\nAccess-Control-Allow-Origin: *\r\n\r\n",
        status, ctype, body.len()
    );
    let _ = stream.write_all(header.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

/// Extracts the `t` token from a query string (`t=abc&x=y`).
fn query_token(query: &str) -> String {
    query.split('&').find_map(|kv| kv.strip_prefix("t=")).unwrap_or("").to_string()
}

/// A 128-bit URL-safe token from the OS cryptographic RNG. Returns None if secure randomness is
/// unavailable — we refuse to serve with a guessable token rather than fall back to a weak one.
fn random_token() -> Option<String> {
    let mut b = [0u8; 16];
    getrandom::getrandom(&mut b).ok()?;
    Some(b.iter().map(|x| format!("{:02x}", x)).collect())
}

/// This machine's primary LAN IPv4 (for the URL the phone connects to), discovered by opening a UDP
/// socket toward a public address — no packet is sent, it just picks the outbound interface.
fn lan_ip() -> Option<String> {
    let sock = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect("8.8.8.8:80").ok()?;
    sock.local_addr().ok().map(|a| a.ip().to_string())
}

const DASHBOARD_HTML: &str = include_str!("dashboard.html");

/// Renders `text` (the dashboard URL) as a scannable QR using half-block characters, so it fits in the
/// terminal Connect screen. Returns None if the text is too long to encode.
pub fn qr_text(text: &str) -> Option<String> {
    use qrcode::{QrCode, render::unicode};
    let code = QrCode::new(text.as_bytes()).ok()?;
    Some(code.render::<unicode::Dense1x2>().quiet_zone(true).build())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};

    fn http_get(port: u16, path_q: &str) -> String {
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        s.write_all(format!("GET {} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", path_q).as_bytes()).unwrap();
        let mut out = String::new();
        let _ = s.read_to_string(&mut out);
        out
    }

    #[test]
    fn serves_dashboard_and_guards_api() {
        let port = 39517; // fixed high port for the test
        let shared = Arc::new(Mutex::new("{\"ok\":true}".to_string()));
        let handle = start(port, shared).expect("server should bind");
        let token = handle.url.split("t=").nth(1).unwrap().to_string();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let home = http_get(port, "/");
        assert!(home.contains("200 OK") && home.contains("PacketViper"), "dashboard page served");

        let no_tok = http_get(port, "/api/state");
        assert!(no_tok.contains("401"), "API blocked without token");

        let ok = http_get(port, &format!("/api/state?t={}", token));
        assert!(ok.contains("200 OK") && ok.contains("\"ok\":true"), "API returns snapshot with token");

        handle.running.store(false, Ordering::SeqCst);
    }
}
