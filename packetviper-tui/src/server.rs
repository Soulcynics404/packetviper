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

/// A settings change requested from the phone dashboard, applied by the main/serve loop.
pub enum Command {
    SetAutosave(bool),
    SetAutoBlock(bool),
    SetRingMb(u64),
    Acknowledge,
    UnblockAll,
}

/// Channel the dashboard uses to send [`Command`]s to the main loop.
pub type CmdTx = crossbeam_channel::Sender<Command>;

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

pub fn start(port: u16, shared: SharedJson, cmd_tx: CmdTx, allow_control: bool) -> Option<ServerHandle> {
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
    // Never log the token (logs persist / go to journald). The tokenized URL is shown only in the
    // interactive Connect screen and TTY output.
    log::info!("Dashboard server on http://{}:{}/ (token required; see Connect screen)", ip, port);

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
                // Timeouts stop a slow/idle client from pinning a thread forever. The write timeout
                // matters for SSE: a client that stops reading would otherwise block write_all for good.
                let _ = stream.set_read_timeout(Some(std::time::Duration::from_secs(15)));
                let _ = stream.set_write_timeout(Some(std::time::Duration::from_secs(15)));
                let token = token_srv.clone();
                let shared = shared.clone();
                let cmd_tx = cmd_tx.clone();
                // One thread per connection; SSE connections stay open, so don't block the accept loop.
                std::thread::spawn(move || {
                    let _guard = ConnGuard;
                    handle_conn(stream, &token, &shared, &cmd_tx, allow_control);
                });
            }
        }
    });
    Some(ServerHandle { url, running })
}

fn handle_conn(mut stream: TcpStream, token: &str, shared: &SharedJson, cmd_tx: &CmdTx, allow_control: bool) {
    let mut buf = [0u8; 4096];
    let n = match stream.read(&mut buf) { Ok(n) => n, Err(_) => return };
    let req = String::from_utf8_lossy(&buf[..n]);
    let Some(line) = req.lines().next() else { return };
    let mut parts = line.split_whitespace();
    let (method, target) = (parts.next().unwrap_or(""), parts.next().unwrap_or("/"));
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    let authed = query_token(query) == token;

    match (method, path) {
        (_, "/") => send(&mut stream, "200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.as_bytes()),
        ("GET", "/api/state") if authed => {
            let body = shared.lock().map(|s| s.clone()).unwrap_or_else(|_| "{}".into());
            send(&mut stream, "200 OK", "application/json", body.as_bytes());
        }
        ("GET", "/api/events") if authed => return stream_events(stream, shared),
        ("POST", "/api/config") if authed && allow_control => {
            let body = req.split("\r\n\r\n").nth(1).unwrap_or("");
            apply_config(body, cmd_tx);
            send(&mut stream, "200 OK", "application/json", b"{\"ok\":true}");
        }
        ("POST", "/api/config") if authed => send(&mut stream, "403 Forbidden", "application/json", b"{\"error\":\"control disabled (read-only dashboard)\"}"),
        (_, "/api/state") | (_, "/api/events") | (_, "/api/config") =>
            send(&mut stream, "401 Unauthorized", "text/plain", b"missing or wrong token"),
        _ => send(&mut stream, "404 Not Found", "text/plain", b"not found"),
    }
}

/// Parses a small JSON settings body from the phone and forwards each known change as a Command.
fn apply_config(body: &str, cmd_tx: &CmdTx) {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(body) else { return };
    if let Some(b) = v.get("autosave").and_then(|x| x.as_bool()) { let _ = cmd_tx.send(Command::SetAutosave(b)); }
    if let Some(b) = v.get("auto_block").and_then(|x| x.as_bool()) { let _ = cmd_tx.send(Command::SetAutoBlock(b)); }
    if let Some(mb) = v.get("ring_mb").and_then(|x| x.as_u64()) { let _ = cmd_tx.send(Command::SetRingMb(mb)); }
    if v.get("acknowledge").and_then(|x| x.as_bool()) == Some(true) { let _ = cmd_tx.send(Command::Acknowledge); }
    if v.get("unblock_all").and_then(|x| x.as_bool()) == Some(true) { let _ = cmd_tx.send(Command::UnblockAll); }
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

/// A random secret (used as the relay push key) from the OS CSPRNG. None if unavailable.
pub fn gen_pair_code() -> Option<String> { random_token() }

/// The relay room/view code derived from the push key: first 16 bytes of SHA-256, hex. Must match the
/// relay's own derivation. The code is public (in the phone link); the key can't be recovered from it.
pub fn view_code(push_key: &str) -> String {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(push_key.as_bytes());
    h[..16].iter().map(|b| format!("{:02x}", b)).collect()
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

/// Pushes the live snapshot to a relay server (`relay_url/push/<code>`) every ~2s, so the phone can
/// see alerts off the LAN by opening `relay_url/r/<code>`. http:// only; one connection per push.
/// Returns false if the relay URL is unusable.
pub fn start_relay_push(relay_url: &str, code: &str, push_key: &str, shared: SharedJson) -> bool {
    let is_https = relay_url.starts_with("https://");
    if !is_https && !relay_url.starts_with("http://") {
        log::warn!("Relay disabled: relay_url must start with http:// or https:// (got '{}')", relay_url);
        return false;
    }
    // https is encrypted end to end; plain http to a non-loopback host sends the key/data in cleartext.
    if !is_https && !relay_url.contains("://127.0.0.1") && !relay_url.contains("://localhost") {
        log::warn!("Relay over plain HTTP — traffic is unencrypted. Use an https:// relay (front it with Caddy) or an SSH tunnel.");
    }
    let url = format!("{}/push/{}", relay_url.trim_end_matches('/'), code);
    let push_key = push_key.to_string();
    // Short timeouts so a dead relay never backs up the push loop; rustls verifies the server cert.
    let agent = ureq::AgentBuilder::new()
        .timeout_connect(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(8))
        .build();
    log::info!("Relay push enabled ({})", if is_https { "https, encrypted" } else { "http" });
    std::thread::spawn(move || loop {
        let body = shared.lock().map(|s| s.clone()).unwrap_or_default();
        if let Err(e) = agent.post(&url).set("X-Push-Key", &push_key).set("Content-Type", "application/json").send_string(&body) {
            log::debug!("Relay push failed: {}", e);
        }
        std::thread::sleep(std::time::Duration::from_secs(2));
    });
    true
}

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
    fn view_code_matches_relay_derivation() {
        // Must equal packetviper-relay's expected_code() for the same key, or the room won't line up.
        assert_eq!(super::view_code("test"), "9f86d081884c7d659a2feaa0c55ad015");
    }

    #[test]
    fn serves_dashboard_and_guards_api() {
        let port = 39517; // fixed high port for the test
        let shared = Arc::new(Mutex::new("{\"ok\":true}".to_string()));
        let (tx, rx) = crossbeam_channel::unbounded();
        let handle = start(port, shared, tx, true).expect("server should bind");
        let token = handle.url.split("t=").nth(1).unwrap().to_string();
        std::thread::sleep(std::time::Duration::from_millis(100));

        let home = http_get(port, "/");
        assert!(home.contains("200 OK") && home.contains("PacketViper"), "dashboard page served");

        let no_tok = http_get(port, "/api/state");
        assert!(no_tok.contains("401"), "API blocked without token");

        let ok = http_get(port, &format!("/api/state?t={}", token));
        assert!(ok.contains("200 OK") && ok.contains("\"ok\":true"), "API returns snapshot with token");

        // A POST config change must reach the command channel.
        let mut s = std::net::TcpStream::connect(("127.0.0.1", port)).unwrap();
        let body = "{\"autosave\":true}";
        s.write_all(format!("POST /api/config?t={} HTTP/1.1\r\nHost: x\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}", token, body.len(), body).as_bytes()).unwrap();
        let mut resp = String::new(); let _ = s.read_to_string(&mut resp);
        assert!(resp.contains("200 OK"), "config POST accepted");
        match rx.recv_timeout(std::time::Duration::from_secs(1)) {
            Ok(Command::SetAutosave(true)) => {}
            other => panic!("expected SetAutosave(true), got {}", matches!(other, Ok(_))),
        }

        // POST without token is rejected and sends no command.
        let unauth = http_get(port, "/api/config");
        assert!(unauth.contains("401"), "config POST blocked without token");

        handle.running.store(false, Ordering::SeqCst);
    }
}
