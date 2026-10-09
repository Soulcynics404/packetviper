# PacketViper — Product Overview

PacketViper is a terminal (TUI) network traffic analyzer and **defensive monitor** written in Rust.
It captures live packets, parses them across OSI layers 2–7, detects active network attacks aimed at
the machine it runs on, can fight back (opt-in), and surfaces everything on a phone.

- Repo: https://github.com/Soulcynics404/packetviper (branch `main`)
- Author: Harsshh <harshraj0645@gmail.com>
- License: MIT
- Primary platform: Linux (Kali). Also compiles for Windows and macOS.

## Who it's for
Security-conscious users, pentesters, students — anyone who wants to know, in real time, if the
network they're on is being attacked, and whether an app on their machine is secretly uploading data.

## What it does today (all built and shipped)

### Capture & inspection
- Live capture (pnet) on a chosen interface; parses Ethernet/ARP, IPv4/IPv6, ICMP/ICMPv6, TCP/UDP,
  and app-layer HTTP, DNS, TLS (SNI), SSH, DHCP, FTP, SMTP, MQTT.
- TUI tabs: Dashboard, Inspection (hex view), Stats, Filters, Threats, Firewall, Help.
- Filter DSL: protocols, `ip/src/dst/port/sport/dport/len/ttl/mac/direction`, ranges, `&&`/`||`/`!`, `contains`.
- 5 color themes (cycle with `t`).

### Threat detection (raises alerts; High/Critical trigger the danger alarm)
- Gateway spoofing / MITM relay (Critical), ARP spoofing (High), ICMP redirect, rogue DHCP,
  rogue IPv6 router / DHCPv6 (mitm6), LLMNR/NetBIOS poisoning (Responder), MAC flooding.
- Access attempts + brute force on file-sharing/remote-access ports (SMB/SSH/RDP/VNC/FTP/NFS/Telnet/WinRM).
- Port scans, SYN/ICMP floods, DNS tunneling, known-backdoor ports.
- **Exfiltration alarm:** flags an app sustaining a high upload to the internet (names the app).

### The danger alarm
High/Critical alerts show a flashing **DANGER** banner on every tab, ring the terminal bell, and
send a desktop notification with sound (Linux `notify-send`+`paplay`, macOS Notification Center,
Windows PowerShell balloon). Press **Space** to acknowledge/silence. Phone dashboard mirrors this with
a flashing banner, beep and vibration.

### Defence (opt-in, key `A`)
Pins the real gateway MAC (defeats ARP poisoning of this host), blocks attacker MAC (Linux) and public
attacker IPs behind floods/scans/brute force. Never blocks this machine, the real gateway, or trusted
devices. All rules removed on exit. Firewall backends: iptables (Linux), Windows Firewall, pf (macOS);
MAC blocking is Linux-only.

### False-alarm reduction
- **Trusted-devices list** (config `trusted`): never alert on or block your own gear.
- **Smarter ARP:** only flags a MAC change as spoofing when the original MAC is still active.
- **Startup learning window (60s):** baselines existing routers/DHCP/IPv6 so mesh/ISP setups don't look rogue.

### Data handling
- Exports: JSON (`e`), CSV (`E`), PCAP (`p`) — created 0600, no symlink following; CSV formula-injection guarded.
- Session save/load (`s`): JSON of captured packets + bookmarks.
- **Autosave ring buffer** (`w`): rolling full-frame pcap capped at a **user-set size** (`[`/`]`);
  oldest segment auto-deleted past the cap. Capture dir 0700, files 0600.

### Run modes
- Interactive TUI: `sudo packetviper <iface>`.
- **Headless `serve`:** `sudo packetviper serve <iface>` — capture+detect+alerts+autosave, no UI.
- **Opt-in autostart:** `sudo packetviper install-autostart <iface>` installs a systemd service
  (root-owned binary in /usr/local/bin, state in /var/lib/packetviper); `remove-autostart` undoes it.

### Phone access (Phase 2 — done)
- **Web dashboard** served over the LAN; open the `o` screen's QR/link on your phone (same Wi-Fi).
  Token-gated. Shows live status, speed, top uploading apps, alerts, protections; flashing danger
  banner + beep + vibrate. Can toggle autosave/auto-defence/ring size (unless `http_allow_control`=false).
- **Relay (`packetviper-relay`)** for alerts anywhere (off the LAN): deploy on a small server
  (AWS free tier is plenty). Stateless room auth (room code = sha256(push_key)); laptop pushes over
  HTTPS when `relay_url` is https (front with Caddy) or plain http otherwise.

## What is NOT done / deferred
- **Native Android app** — the next major work. Plan in `docs/ANDROID_PLAN.md`.
- **Wi-Fi radio attack detection** (deauth/evil-twin/KARMA/handshake) — needs a monitor-mode USB
  adapter; the built-in RTL8852AE can't do it. **User has dropped this for now.**
- **Live end-to-end test** of serve/autostart/dashboard/relay on real hardware (needs a sudo run + the
  user's AWS box). Everything is unit-tested and build-verified; not yet run against a live attack.
- Encrypted content and purely passive sniffing are undetectable by design (documented in README).

## Known limitations
- Linux is the most tested; Windows/macOS are compile-tested only.
- Needs root (capture + firewall).
- Reading inside TLS is impossible; exfiltration is detected by behavior (volume/destination), not content.
