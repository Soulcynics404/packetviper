<div align="center">

# 🐍 PacketViper

**A blazing-fast TUI network traffic analyzer built with Rust**

[![Rust](https://img.shields.io/badge/Rust-000000?style=for-the-badge&logo=rust&logoColor=white)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)
[![GitHub](https://img.shields.io/badge/GitHub-Soulcynics404-blue?style=for-the-badge&logo=github)](https://github.com/Soulcynics404)

<img src="https://img.shields.io/badge/status-active_development-brightgreen" />

---

*Real-time packet capture, deep protocol inspection, threat detection, and traffic analysis — all from your terminal.*

</div>

---

## ✨ Features

- 🚀 **Real-time packet capture** using raw sockets via `pnet`
- 🔍 **Deep protocol inspection** — Link, Network, Transport, and Application layers
- 📊 **Live dashboard** with packet counters, bandwidth stats, and recent activity
- 🛡️ **Threat detection** — Port scanning, ARP spoofing, DNS tunneling detection
- 🌍 **GeoIP lookup** — See where traffic is coming from geographically
- 🔧 **Custom filter DSL** — Powerful filtering with expressions like `tcp && port 443`
- 📁 **Multi-format export** — JSON, CSV, and PCAP export
- 🎨 **Beautiful TUI** — Built with Ratatui, vim-style keybindings
- ⚡ **Blazing fast** — Zero-copy parsing, channel-based async architecture

## 🔧 Supported Protocols

| Layer | Protocols |
|-------|-----------|
| **Link** | Ethernet, ARP |
| **Network** | IPv4, IPv6, ICMP, ICMPv6 |
| **Transport** | TCP, UDP |
| **Application** | HTTP, DNS, TLS (with SNI), SSH, DHCP |

## 📋 Prerequisites

- **OS**: Linux (tested on Kali Linux)
- **Rust**: 1.75+ (install via [rustup](https://rustup.rs/))
- **Privileges**: Root or `CAP_NET_RAW` capability

## 🚀 Installation

### From Source
```bash
git clone https://github.com/Soulcynics404/packetviper.git
cd packetviper
cargo build --release


