# PacketViper — Tech Stack & Architecture

## Language / build
- **Rust** (edition 2021), Cargo **workspace**. Toolchain tested: rustc 1.95.
- Build: `cargo build` / `cargo build --release`. Test: `cargo test`. Lint: `cargo clippy`.
- Version is `0.2.1` (workspace `Cargo.toml`); shown in the TUI title via `env!("CARGO_PKG_VERSION")`.

## Workspace members
| Crate | Kind | Purpose |
|-------|------|---------|
| `packetviper-core` | lib | capture, packet types, filters, stats, threat detection, exports, config, platform abstraction |
| `packetviper-tui`  | bin (`packetviper`) | the TUI + headless `serve` + autostart installer + phone dashboard server + relay push client |
| `packetviper-relay`| bin (`packetviper-relay`) | tiny HTTP relay to deploy on a VPS for off-LAN phone alerts |

## Key dependencies
- Capture/parse: `pnet`, `pnet_datalink`.
- TUI: `ratatui` 0.28, `crossterm` 0.28.
- Async plumbing: `crossbeam-channel` (capture thread -> UI; phone commands -> loop).
- Serde: `serde`, `serde_json` (packets, config, dashboard snapshot).
- GeoIP: `maxminddb` (optional DB in `data/`), `dns-lookup`.
- Time: `chrono`. Logging: `log` + `env_logger` (to `logs/` file, never stderr in TUI).
- Dashboard/relay: std TCP HTTP (no web framework), `getrandom` (token), `qrcode` (connect QR),
  `sha2` (relay room auth), `ureq` (HTTPS relay push, rustls).

## packetviper-core module map
- `capture/engine.rs` — capture loop, Ethernet frame parsing, app-protocol detection, ring-buffer write.
- `capture/ring.rs` — rolling pcap segments with size cap + oldest-delete (0600/0700).
- `capture/stream.rs` — TCP stream reassembly/tracking. `capture/plugins.rs` — FTP/SMTP/MQTT parsers.
- `capture/mod.rs` — `list_interfaces()`, `NetworkInterface`.
- `packets/` — `CapturedPacket`, layer structs (`link`/`network`/`transport`/`application`),
  `sanitize()` (strips control chars from packet-derived text), `strip_port()`, `src_ip()/dst_ip()`.
- `filters/parser.rs` + `filters/engine.rs` — filter DSL lexer/parser + evaluator.
- `stats/bandwidth.rs` — totals, per-direction live rate, protocol/talker stats (top-N, no full sort).
- `stats/connections.rs` — connection tracking (client = SYN initiator), capped+evicted.
- `stats/process.rs` — **per-app attribution** via `/proc` (Linux): `ProcessResolver`, `NetMonitor`
  (per-pid up/down bytes, `poll_exfil` for the exfiltration alarm).
- `threat/detector.rs` — all detections, the alarm levels, auto-defence, trusted list, smarter ARP,
  learning window. Public helpers: `is_public_addr`, `BlockKind`, `ThreatLevel::is_alarm`.
- `threat/geoip.rs` — GeoIP lookup + private/public classification.
- `platform.rs` — **OS abstraction**: firewall (iptables/netsh/pf), neighbor pin, interface down,
  `default_gateway()`. Per-OS via `cfg`. All privileged cmds run quiet, `sudo -n` on unix.
- `config.rs` — `Config` (JSON `packetviper-config.json`), `MIN/MAX_RING_MB`, `sanitized_capture_dir`.
- `export/` — json/csv/pcap/session; `create_private()` (0600, O_EXCL).

## packetviper-tui module map
- `main.rs` — arg dispatch (`serve`/`install-autostart`/`remove-autostart`/`<iface>`), run loop,
  logging init (per-run file in `logs/`), panic hook + terminal restore, `maybe_start_relay`.
- `app.rs` — `App` state, `add_packet`, `tick` (alarm check, exfil check, dashboard refresh),
  `Alarm`, command handling from phone, autosave/auto-defence/ring setters.
- `handler.rs` — keybindings. `events.rs` — input polling. `theme.rs` — 5 themes.
- `ui/` — `mod.rs` (layout, footer, alarm banner, connect/confirm popups) + one file per tab.
- `ui/dashboard.html` — the mobile dashboard page (served on LAN and via relay; path-adaptive, SSE).
- `server.rs` — LAN dashboard HTTP server (std TCP, SSE, token auth, connection caps), `Snapshot`
  (JSON for the phone), relay push client (`start_relay_push`, `ureq`), `view_code` (sha256).

## Data / config
- `packetviper-config.json` (owner-only): `autosave`, `capture_dir`, `ring_buffer_mb`, `auto_block`,
  `http_enabled`, `http_port` (7373), `http_allow_control`, `relay_enabled`, `relay_url`,
  `relay_push_key`, `exfil_alert`, `exfil_mb_per_s`, `trusted` (list of MAC/IP).
- Runtime dirs (gitignored): `logs/`, `captures/`, `data/` (GeoIP mmdb), `packetviper-connect.txt`.

## Dashboard API (token via `?t=<token>`; relay rooms keyed by `/r/<code>`)
- `GET /` dashboard HTML; `GET /api/state` snapshot JSON; `GET /api/events` SSE;
  `POST /api/config` apply settings (403 if `http_allow_control` false).
- Relay: `POST /push/<code>` (header `X-Push-Key`, must satisfy `sha256(key)==code`);
  `GET /r/<code>` page; `GET /r/<code>/events` SSE.

## CI / release
- `.github/workflows/ci.yml` — build on Linux/macOS/Windows, test on Linux/macOS (actions pinned to SHAs).
- `.github/workflows/release.yml` — on tag `v*`, build + attach archives for Linux, macOS (Intel +
  Apple Silicon), Windows. Windows needs the Npcap SDK (workflow downloads it).

## Testing
- 29 core + 3 relay + 2 tui tests. Cover: filters, address/port, sanitize, gateway parse (Linux/Win/mac),
  threat detections (gateway spoof, this-PC ARP, idle-MAC change, MITM, ICMP redirect, brute force,
  trusted), exfil (sustained/spike/no-dest), relay auth (code derivation, ct_eq), dashboard serve+POST.

## Conventions
- **No AI attribution** in commits/PRs/files (user rule — see MEMORY.md). Author is Harsshh.
- Runs as root -> every file write guards against symlinks and uses restrictive modes.
- Packet-derived text is always `sanitize()`d before display/log.
- `ponytail:` comments mark deliberate simplifications with their ceiling.
