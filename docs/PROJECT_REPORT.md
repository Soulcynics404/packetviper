# PacketViper — Project Report

## 📋 Table of Contents
1. [Project Overview](#project-overview)
2. [Problem Statement](#problem-statement)
3. [Target Audience](#target-audience)
4. [Technical Architecture](#technical-architecture)
5. [Features & Capabilities](#features--capabilities)
6. [Threat Detection System](#threat-detection-system)
7. [Dependencies & Technology Stack](#dependencies--technology-stack)
8. [Known Limitations](#known-limitations)
9. [Security Considerations](#security-considerations)
10. [Testing & Validation](#testing--validation)
11. [Future Enhancements](#future-enhancements)
12. [Conclusion](#conclusion)

---

## 1. Project Overview

**PacketViper** is a terminal-based (TUI) network traffic analyzer built entirely in Rust. It provides real-time packet capture, deep protocol inspection across OSI layers 2–7, an integrated threat detection engine, and a custom filter domain-specific language (DSL) — all accessible through a rich, interactive terminal interface.

The project demonstrates proficiency in:
- **Systems programming** (Rust, raw sockets, multi-threading)
- **Network security** (protocol analysis, attack detection)
- **Language design** (custom filter DSL with tokenizer and parser)
- **UI/UX engineering** (interactive terminal application)
- **Software architecture** (modular multi-crate workspace design)

---

## 2. Problem Statement

Existing network analysis tools like Wireshark are powerful but:
- Require a graphical desktop environment
- Are heavyweight and resource-intensive
- Cannot be used over SSH sessions on remote servers
- Have a steep learning curve for beginners

PacketViper addresses these gaps by providing:
- A **terminal-based** interface that works over SSH
- **Lightweight** resource usage suitable for constrained environments
- **Built-in threat detection** that Wireshark does not offer natively
- A **custom filter language** that is simpler than Wireshark's display filters
- **Real-time visual statistics** without needing external tools

---

## 3. Target Audience

### Primary Audience

| Audience | Why PacketViper? |
|----------|-----------------|
| **Cybersecurity Students** | Hands-on learning of packet analysis, protocol headers, and network attacks. Visual representation of OSI layers makes learning intuitive. |
| **Penetration Testers** | Real-time monitoring during red team engagements. Verify if ARP spoofing, port scans, or DNS tunneling tools are working. Run over SSH on compromised hosts. |
| **Network Administrators** | Quick terminal-based troubleshooting without installing heavy GUI tools. Monitor bandwidth, identify rogue traffic, check for suspicious activity. |
| **SOC Analysts** | Lightweight first-response tool for investigating network anomalies on Linux servers that lack GUI access. |

### Secondary Audience

| Audience | Why PacketViper? |
|----------|-----------------|
| **Software Developers** | Debug HTTP/DNS/TLS traffic from applications. Verify API calls reach the correct endpoints. |
| **CTF Players** | Capture and analyze challenge traffic during Capture The Flag competitions. |
| **Home Lab Enthusiasts** | Monitor home network for unauthorized devices or suspicious traffic. |
| **Educators** | Demonstrate network concepts in terminal-based lab environments. |

---

## 4. Technical Architecture

### Multi-Crate Workspace Design

**packetviper (workspace)**
├── packetviper-core → Reusable library (capture, parsing, filters, stats, threats, export)
└── packetviper-tui → Terminal UI application (depends on core)


**Why this design?**
- The core library can be reused in other applications (e.g., a web UI, a CLI tool, or an API server)
- Clear separation of concerns between logic and presentation
- Independent testing of core functionality

### Threading Model

[Capture Thread] [Main Thread]
│                            │
├── Opens raw socket         ├── Polls keyboard events (50ms tick)
├── Sets promiscuous mode    ├── Drains packet channel
├── Reads Ethernet frames    ├── Runs filter engine
├── Parses L2 → L3 → L4 → L7 ├── Updates bandwidth monitor
├── Sends CapturedPacket ──────────▶├── Runs threat detector
│ via crossbeam channel      ├── Renders UI frame
│                            │
├── Controlled by AtomicBool ◀──────├── User presses 'c' to stop
└── Exits cleanly 

### Why Rust?
- **Memory safety without garbage collection** — critical for packet processing
- **Zero-cost abstractions** — high-level code with C-like performance
- **Fearless concurrency** — compiler prevents data races at compile time
- **Strong type system** — catches protocol parsing errors early
- **Growing ecosystem** — mature crates for networking and TUI

---

## 5. Features & Capabilities

### 5.1 Packet Capture Engine
- Uses `pnet` for raw socket access (no `libpcap` C dependency)
- Promiscuous mode captures ALL traffic on the network segment
- Lock-free channel (`crossbeam`) for zero-blocking communication
- Atomic flag for clean capture start/stop

### 5.2 Protocol Parsing (L2–L7)

**Link Layer (L2):**
- Ethernet frame parsing (source/destination MAC, EtherType)
- ARP request/reply parsing (sender/target MAC and IP, operation)

**Network Layer (L3):**
- IPv4: source/destination IP, TTL, protocol, flags, DSCP, identification, header/total length
- IPv6: source/destination IP, hop limit, next header, traffic class, flow label, payload length
- ICMP: type, code, type name (Echo Request/Reply, Destination Unreachable, Time Exceeded)
- ICMPv6: type, code (Echo, Router/Neighbor Solicitation/Advertisement)

**Transport Layer (L4):**
- TCP: source/destination port, sequence/ack numbers, all 8 flags (SYN, ACK, FIN, RST, PSH, URG, ECE, CWR), window size, header length
- UDP: source/destination port, length, checksum

**Application Layer (L7):**
- HTTP: method, URI, version, status code, Host, User-Agent, Content-Type headers
- DNS: query ID, questions (name, type, class), response flag, opcode, response code
- TLS: version (SSL 3.0 through TLS 1.3), content type, handshake type, **Server Name Indication (SNI) extraction**
- SSH: version string detection, encrypted traffic identification
- DHCP: message type, client/server IPs, client MAC

### 5.3 Custom Filter DSL

**Language Features:**
- Recursive descent parser with proper operator precedence
- Tokenizer supporting: protocols, fields, operators, numbers, strings, ranges, parentheses
- Logical operators: `&&` (AND), `||` (OR), `!` (NOT)
- Comparison operators: `==`, `!=`, `>`, `<`, `>=`, `<=`
- Port ranges: `port 80..443`
- Text search: `contains "keyword"`

### 5.4 Statistics Engine
- Per-second bandwidth tracking with 60-sample history (sparkline graph)
- Protocol distribution with packet count, byte count, and percentage
- TCP flag breakdown (SYN, ACK, FIN, RST, PSH counters)
- Top 10 sources, destinations, and conversations ranked by packet count
- Directional traffic analysis (incoming vs outgoing bytes)

### 5.5 Export System
- **JSON**: Full packet details including all parsed layers (for programmatic analysis)
- **CSV**: Summary table with key fields (for spreadsheet analysis)
- **PCAP**: Industry-standard binary format (for opening in Wireshark)

---

## 6. Threat Detection System

### How It Works

The threat detector maintains **stateful tracking tables** that accumulate data over time windows. Each incoming packet is analyzed against multiple detection rules simultaneously.

### Detection Rules

#### 6.1 Port Scanning Detection
- **Tracking**: HashMap of `source_ip → Set<destination_ports>`
- **Trigger**: Same source IP sends SYN packets to >15 unique ports within 60 seconds
- **Severity**: 🟠 HIGH
- **Rationale**: Legitimate traffic rarely contacts more than a few ports on a single host. Port scanning tools like `nmap` generate SYN packets to many ports rapidly.
- **Cleanup**: Tracking data expires after 60 seconds to reduce memory usage

#### 6.2 ARP Spoofing Detection
- **Tracking**: HashMap of `IP_address → Set<MAC_addresses>`
- **Trigger**: Two or more different MAC addresses claim the same IP via ARP Reply packets
- **Severity**: 🔴 CRITICAL
- **Rationale**: In normal operation, each IP has exactly one MAC. ARP spoofing tools (bettercap, arpspoof, ettercap) send fake ARP Replies to redirect traffic through the attacker's machine.
- **Tested**: Successfully detected attacks from `bettercap` in a live lab environment

#### 6.3 DNS Tunneling Detection
- **Tracking**: Inspects DNS question names in each DNS packet
- **Trigger**: Any DNS label >40 characters OR total query name >100 characters
- **Severity**: 🟡 MEDIUM
- **Rationale**: DNS tunneling tools (iodine, dns2tcp, dnscat2) encode data in DNS query names, resulting in abnormally long subdomain labels like `aGVsbG8gd29ybGQ.tunnel.evil.com`

#### 6.4 Suspicious Port Detection
- **Tracking**: Checks destination port against a known-bad port list
- **Ports Monitored**: 4444, 5555, 6666, 6667, 1337, 31337, 12345, 27374, 65535, 3389 (RDP), 9050/9051 (Tor), 5900/5901 (VNC), and others
- **Severity**: 🔵 LOW
- **Rationale**: Many malware families, backdoors, and C2 frameworks use well-known ports

#### 6.5 DDoS / High Rate Detection
- **Tracking**: HashMap of `source_ip → Vec<timestamps>` (last 10 seconds)
- **Trigger**: >500 packets in 10 seconds from a single source
- **Severity**: 🟠 HIGH
- **Rationale**: Normal traffic rarely exceeds 50 pps from a single source. Flooding tools, ARP spoof floods, and SYN floods generate hundreds of packets per second

---

## 7. Dependencies & Technology Stack

### Core Dependencies

| Category | Technology | Version | Why This Choice |
|----------|-----------|---------|-----------------|
| **Language** | Rust | 2021 Edition | Memory safety, performance, concurrency |
| **Packet Capture** | pnet | 0.35 | Pure Rust, no C dependency, cross-platform potential |
| **TUI Framework** | Ratatui | 0.28 | Most popular Rust TUI, actively maintained, rich widgets |
| **Terminal** | Crossterm | 0.28 | Cross-platform terminal manipulation |
| **Channels** | crossbeam-channel | 0.5 | Lock-free, bounded, better than std::mpsc |
| **Serialization** | serde + serde_json | 1.0 | Industry standard for Rust serialization |
| **CSV** | csv | 1.3 | Efficient CSV reading/writing |
| **Time** | chrono | 0.4 | Comprehensive date/time handling |
| **Errors** | thiserror | 1.0 | Ergonomic error type definitions |
| **Logging** | log + env_logger | 0.4/0.11 | Standard Rust logging facade |

### System Dependencies

| Package | Purpose |
|---------|---------|
| `build-essential` | C compiler toolchain (for linking) |
| `libpcap-dev` | pcap headers (used by pnet internally) |
| `pkg-config` | Library discovery |

### Runtime Requirements

| Requirement | Details |
|-------------|---------|
| **OS** | Linux (kernel 3.x+) |
| **Privileges** | Root or CAP_NET_RAW capability |
| **Terminal** | 80×24 minimum, Unicode support recommended |
| **Memory** | ~20-50 MB depending on packet volume |

---

## 8. Known Limitations

### Technical Limitations

| Limitation | Description | Planned Fix |
|-----------|-------------|-------------|
| **Linux Only** | Uses raw sockets that require Linux kernel | No cross-platform plans (use pnet's cross-platform features later) |
| **No TCP Reassembly** | Cannot reconstruct TCP streams (e.g., full HTTP conversations) | Planned for Phase 8 |
| **Limited App Parsers** | Only HTTP, DNS, TLS, SSH, DHCP — no FTP, SMTP, MQTT, etc. | Planned for Phase 9 |
| **No Packet Modification** | Read-only capture, cannot inject or modify packets | Out of scope (use scapy for this) |
| **No Encrypted Payload** | Cannot decrypt TLS/SSH encrypted data (only inspects headers + SNI) | By design — would require key material |
| **PCAP Export Limitation** | Only stores first 128 bytes of each packet (raw_preview) | Can be increased by modifying capture engine |
| **No IPv6 Extension Headers** | IPv6 extension header chain is not fully parsed | Planned improvement |
| **Single Interface** | Captures on one interface at a time | Can run multiple instances |

### Detection Limitations

| Limitation | Description |
|-----------|-------------|
| **False Positives** | High traffic rate detection may trigger for legitimate streaming/downloads |
| **Evasion** | Slow port scans (<15 ports/minute) evade detection |
| **Encrypted ARP** | 802.1X environments may prevent ARP monitoring |
| **DNS over HTTPS** | DoH traffic appears as normal TLS, DNS tunneling detection is bypassed |
| **No Signature Database** | Threat detection uses behavioral rules, not IDS signatures like Snort/Suricata |

---

## 9. Security Considerations

### Privileges
- PacketViper requires **root** or `CAP_NET_RAW` to capture raw packets
- This is a security-sensitive privilege — only run on trusted systems
- Use `setcap` instead of `sudo` for production deployments

### Data Privacy
- Captured packets may contain **sensitive data** (passwords, tokens, personal info)
- Exported files (JSON, CSV, PCAP) are **unencrypted** — handle with care
- PacketViper does **not** send any data to external servers

### Ethical Use
- Only use on networks you **own** or have **written authorization** to monitor
- Unauthorized packet capture is **illegal** in most jurisdictions
- The threat detection features are designed for **defensive** purposes

---

## 10. Testing & Validation

### Test Environment
- **OS**: Kali Linux 2024.x (kernel 6.x)
- **Hardware**: Laptop with Intel WiFi (wlan0)
- **Network**: Home WiFi network (192.168.29.0/24)

### Test Results

| Test Case | Method | Expected Result | Actual Result | Status |
|-----------|--------|-----------------|---------------|--------|
| Basic capture | Browse web | TCP, UDP, DNS packets captured | Captured correctly with all layers parsed | ✅ PASS |
| ARP detection | `bettercap --arp-spoof` | CRITICAL alert for multiple MACs | 7 CRITICAL alerts triggered | ✅ PASS |
| High rate detection | `bettercap` flooding | HIGH alert for >500 pps | 22+ HIGH alerts triggered | ✅ PASS |
| DNS tunneling | Long DNS queries from bettercap | MEDIUM alert for long queries | 32+ MEDIUM alerts triggered | ✅ PASS |
| Protocol filter | `tcp` filter applied | Only TCP packets shown | Correctly filtered | ✅ PASS |
| Port filter | `port == 443` | Only port 443 traffic | Correctly filtered | ✅ PASS |
| JSON export | Press `e` | JSON file created | File created with all packet data | ✅ PASS |
| CSV export | Press `E` | CSV file created | File created with summary data | ✅ PASS |
| PCAP export | Press `p` | PCAP file created | File created, opens in Wireshark | ✅ PASS |
| TLS SNI | Browse HTTPS site | SNI hostname extracted | Correctly shows server name | ✅ PASS |
| IPv6 traffic | Normal network | IPv6 packets parsed | Correctly parsed with all fields | ✅ PASS |

---

## 11. Future Enhancements

| Phase | Feature | Description |
|-------|---------|-------------|
| 4 | **GeoIP Integration** | Map IP addresses to physical locations using MaxMind database |
| 5 | **Packet Bookmarking** | Mark interesting packets for later review |
| 6 | **Color Themes** | Customizable color schemes (dark, light, solarized) |
| 7 | **Plugin System** | Load custom protocol parsers at runtime |
| 8 | **TCP Stream Reassembly** | Reconstruct full HTTP conversations, file transfers |
| 9 | **More Protocols** | FTP, SMTP, MQTT, gRPC, WebSocket parsers |
| 10 | **Performance** | Benchmarks, zero-copy optimization, SIMD parsing |

---

## 12. Conclusion

PacketViper demonstrates that a fully-featured network traffic analyzer can be built as a lightweight terminal application using modern systems programming in Rust. The project combines real-time packet capture, multi-layer protocol parsing, behavioral threat detection, a custom query language, and rich data visualization — all in approximately **3,500 lines of Rust code** with zero unsafe blocks.

The successful detection of ARP spoofing attacks performed with industry tools (bettercap) validates the practical applicability of the threat detection engine. The custom filter DSL provides an intuitive yet powerful way to slice through network traffic, and the multi-format export system enables integration with existing security toolchains.

**Key Technical Achievements:**
- Custom recursive descent parser for the filter DSL
- Lock-free multi-threaded architecture with clean shutdown
- Stateful threat detection with time-windowed analysis
- TLS Server Name Indication (SNI) extraction from ClientHello handshakes
- DNS query name parsing with compression pointer support
- Industry-standard PCAP export compatible with Wireshark

---

*Report prepared by Harsshh | GitHub: [@Soulcynics404](https://github.com/Soulcynics404)*