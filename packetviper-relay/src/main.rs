//! PacketViper relay. Deploy this on a small internet server (e.g. an AWS free-tier EC2 instance) so
//! your laptop's alerts reach your phone even when they're not on the same Wi-Fi.
//!
//! Flow: the laptop POSTs its status snapshot to `/push/<code>`; the phone opens `/r/<code>` and
//! receives live updates over Server-Sent Events. `<code>` is a shared secret (the pair code) that
//! both sides know — it both names the "room" and authorizes it. No packet contents are sent here,
//! only the summary snapshot. State is in memory only; nothing is written to disk.
//!
//! Security notes: traffic here is plain HTTP, so run it behind HTTPS (e.g. Caddy) for real use, and
//! treat the pair code as a password. Rooms, body size and connections are capped to limit abuse.

use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

const MAX_BODY: usize = 256 * 1024;       // a snapshot is a few KB; cap well above that
const MAX_ROOMS: usize = 500;             // distinct pair codes held at once
const ROOM_TTL: Duration = Duration::from_secs(120); // drop a room whose laptop stopped pushing
const MAX_CONN: usize = 256;
static ACTIVE: AtomicUsize = AtomicUsize::new(0);

/// `push_key` is set by the first laptop to push (trust-on-first-use) and required to match on every
/// later push, so a leaked view link (`/r/<code>`) cannot write/spoof data into the room.
struct Room { json: String, updated: Instant, push_key: String }
type Rooms = Arc<Mutex<HashMap<String, Room>>>;

const DASHBOARD_HTML: &str = include_str!("../../packetviper-tui/src/dashboard.html");

fn main() {
    let port: u16 = std::env::args().nth(1).and_then(|s| s.parse().ok())
        .or_else(|| std::env::var("PORT").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(9000);
    let rooms: Rooms = Arc::new(Mutex::new(HashMap::new()));
    let listener = TcpListener::bind(("0.0.0.0", port)).unwrap_or_else(|e| {
        eprintln!("packetviper-relay: cannot bind port {}: {}", port, e);
        std::process::exit(1);
    });
    println!("packetviper-relay listening on 0.0.0.0:{}", port);

    for stream in listener.incoming().flatten() {
        if ACTIVE.fetch_add(1, Ordering::Relaxed) >= MAX_CONN {
            ACTIVE.fetch_sub(1, Ordering::Relaxed);
            let mut s = stream;
            let _ = s.write_all(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n");
            continue;
        }
        let _ = stream.set_read_timeout(Some(Duration::from_secs(20)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(20)));
        let rooms = rooms.clone();
        std::thread::spawn(move || {
            struct Guard;
            impl Drop for Guard { fn drop(&mut self) { ACTIVE.fetch_sub(1, Ordering::Relaxed); } }
            let _g = Guard;
            handle(stream, rooms);
        });
    }
}

fn handle(mut stream: TcpStream, rooms: Rooms) {
    // Read headers (and small bodies) — enough for a snapshot POST.
    let mut buf = vec![0u8; 8192];
    let n = match stream.read(&mut buf) { Ok(n) if n > 0 => n, _ => return };
    let head = String::from_utf8_lossy(&buf[..n]).to_string();
    let Some(line) = head.lines().next() else { return };
    let mut it = line.split_whitespace();
    let (method, target) = (it.next().unwrap_or(""), it.next().unwrap_or("/"));
    let path = target.split('?').next().unwrap_or("/");

    if method == "GET" && (path == "/" || path == "/healthz") {
        return send(&mut stream, "200 OK", "text/plain", b"PacketViper relay OK");
    }

    // /push/<code>
    if let Some(code) = path.strip_prefix("/push/") {
        if method != "POST" || !valid_code(code) { return send(&mut stream, "400 Bad Request", "text/plain", b"bad"); }
        let push_key = header(&head, "x-push-key").unwrap_or_default();
        if push_key.len() < 8 { return send(&mut stream, "401 Unauthorized", "text/plain", b"missing X-Push-Key"); }
        let body = read_body(&mut stream, &head, &buf[..n]);
        if body.len() > MAX_BODY { return send(&mut stream, "413 Payload Too Large", "text/plain", b"too big"); }
        if let Ok(mut map) = rooms.lock() {
            prune(&mut map);
            match map.get(code) {
                // Existing room: the push key must match the one that created it.
                Some(r) if r.push_key != push_key => return send(&mut stream, "403 Forbidden", "text/plain", b"wrong push key"),
                None if map.len() >= MAX_ROOMS => return send(&mut stream, "503 Service Unavailable", "text/plain", b"relay full"),
                _ => {}
            }
            map.insert(code.to_string(), Room { json: body, updated: Instant::now(), push_key });
        }
        return send(&mut stream, "200 OK", "application/json", b"{\"ok\":true}");
    }

    // /r/<code> and /r/<code>/events
    if let Some(rest) = path.strip_prefix("/r/") {
        let (code, events) = match rest.strip_suffix("/events") { Some(c) => (c, true), None => (rest, false) };
        if !valid_code(code) { return send(&mut stream, "404 Not Found", "text/plain", b"not found"); }
        if !events {
            return send(&mut stream, "200 OK", "text/html; charset=utf-8", DASHBOARD_HTML.as_bytes());
        }
        return stream_events(stream, rooms, code);
    }

    send(&mut stream, "404 Not Found", "text/plain", b"not found");
}

/// Streams the room's latest snapshot to the phone once a second (SSE).
fn stream_events(mut stream: TcpStream, rooms: Rooms, code: &str) {
    let headers = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n\r\n";
    if stream.write_all(headers.as_bytes()).is_err() { return; }
    let mut missing = 0u32;
    loop {
        let body = rooms.lock().ok().and_then(|m| m.get(code).map(|r| r.json.clone()));
        // Don't let a client pin a slot by streaming a room that no laptop is pushing to.
        match &body {
            Some(_) => missing = 0,
            None => { missing += 1; if missing > 15 { break; } }
        }
        let msg = format!("data: {}\n\n", body.unwrap_or_else(|| "{}".into()).replace('\n', " "));
        if stream.write_all(msg.as_bytes()).is_err() || stream.flush().is_err() { break; }
        std::thread::sleep(Duration::from_millis(1000));
    }
}

/// Case-insensitive lookup of a request header value.
fn header(head: &str, name: &str) -> Option<String> {
    head.lines().skip(1).find_map(|l| {
        let (k, v) = l.split_once(':')?;
        (k.trim().eq_ignore_ascii_case(name)).then(|| v.trim().to_string())
    })
}

/// Reads the request body using Content-Length, continuing from what was already buffered.
fn read_body(stream: &mut TcpStream, head: &str, first: &[u8]) -> String {
    let len = head.lines()
        .find_map(|l| l.to_ascii_lowercase().strip_prefix("content-length:").map(|v| v.trim().parse::<usize>().ok()))
        .flatten().unwrap_or(0)
        .min(MAX_BODY);
    let sep = b"\r\n\r\n";
    let body_start = first.windows(4).position(|w| w == sep).map(|p| p + 4).unwrap_or(first.len());
    let mut body = first[body_start.min(first.len())..].to_vec();
    while body.len() < len {
        let mut chunk = vec![0u8; (len - body.len()).min(8192)];
        match stream.read(&mut chunk) { Ok(0) | Err(_) => break, Ok(k) => body.extend_from_slice(&chunk[..k]) }
    }
    body.truncate(len.max(body.len()).min(MAX_BODY));
    String::from_utf8_lossy(&body).into_owned()
}

/// Pair code: 8–64 URL-safe chars. Keeps room keys clean and unguessable (the laptop generates it).
fn valid_code(c: &str) -> bool {
    (8..=64).contains(&c.len()) && c.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// Drops rooms whose laptop stopped pushing (so memory doesn't grow and stale data isn't served).
fn prune(map: &mut HashMap<String, Room>) {
    let now = Instant::now();
    map.retain(|_, r| now.duration_since(r.updated) < ROOM_TTL);
}

fn send(stream: &mut TcpStream, status: &str, ctype: &str, body: &[u8]) {
    let h = format!("HTTP/1.1 {}\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", status, ctype, body.len());
    let _ = stream.write_all(h.as_bytes());
    let _ = stream.write_all(body);
    let _ = stream.flush();
}

#[cfg(test)]
mod tests {
    #[test]
    fn code_validation() {
        assert!(super::valid_code("abcd1234"));
        assert!(super::valid_code("A-Z_0123456789"));
        assert!(!super::valid_code("short"));
        assert!(!super::valid_code("has/slash1"));
        assert!(!super::valid_code("has space1"));
    }
}
