# Features

## Implemented ✅

### Capture Engine
- Real-time packet capture via pnet (raw sockets)
- Promiscuous mode support
- Multi-interface support
- Direction detection (incoming/outgoing)
- Threaded capture with lock-free channel communication

### Protocol Support (L2-L7)
| Layer | Protocols |
|-------|-----------|
| Link (L2) | Ethernet, ARP |
| Network (L3) | IPv4, IPv6, ICMP, ICMPv6 |
| Transport (L4) | TCP (with full flag parsing), UDP |
| Application (L7) | HTTP, DNS (with query parsing), TLS (with SNI extraction), SSH, DHCP |

### Custom Filter DSL
- Protocol filters: `tcp`, `udp`, `dns`, `http`, `tls`, `arp`, `icmp`
- Field comparisons: `ip == x`, `port == x`, `len > x`, `ttl < x`
- Port ranges: `port 80..443`
- Logical operators: `&&`, `||`, `!`
- Parentheses for grouping: `(http || dns) && direction == out`
- Text search: `contains "google"`
- Direction filter: `direction == in`

### Statistics & Monitoring
- Live bandwidth sparkline graph
- Protocol distribution table
- TCP flag analysis (SYN, ACK, FIN, RST, PSH counts)
- Top sources / destinations / conversations
- Incoming vs outgoing byte counters
- Packets per second / bytes per second
- Average packet size

### Threat Detection
- **Port Scanning**: Detects >15 unique destination ports from single source
- **ARP Spoofing**: Detects multiple MACs claiming same IP address
- **DNS Tunneling**: Detects unusually long DNS query names (>40 char labels)
- **Suspicious Ports**: Alerts on traffic to known malware ports (4444, 31337, etc.)
- **DDoS Indicators**: Detects >500 packets/10s from single source
- Severity levels: Critical, High, Medium, Low, Info

### Export
- JSON export (full packet details)
- CSV export (summary table)
- PCAP export (compatible with Wireshark)

### TUI Interface
- 6 tabs: Dashboard, Inspection, Stats, Filters, Threats, Help
- Vim-style navigation (j/k, g/G)
- Auto-scroll with toggle
- Packet detail pane with hex dump
- Protocol-colored packet list
- Live status bar with capture info
- Threat badge on Threats tab

## Planned 🚧
- GeoIP lookup for IP geolocation
- TCP stream reassembly
- More app-layer protocols (FTP, SMTP, MQTT)
- Firewall rule generation
- Color themes
- Plugin system
- Packet bookmarking
- Session save/restore