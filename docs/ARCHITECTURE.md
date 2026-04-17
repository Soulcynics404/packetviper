# Architecture

## Overview

PacketViper uses a **multi-crate Rust workspace**:
```
┌──────────────────────────────────────────────────┐
│ packetviper-tui                                  │
│ (Terminal UI — Ratatui + Crossterm)              │
│                                                  │
│ ┌──────────────────────────────────────────┐     │
│ │ Main Loop (50ms tick)                    │     │
│ │ ├── Poll keyboard events                 │     │
│ │ ├── Drain packet channel                 │     │
│ │ ├── Update stats (tick)                  │     │
│ │ └── Render UI frame                      │     │
│ └──────────────────────────────────────────┘     │
└────────────────────┬─────────────────────────────┘
│ crossbeam-channel (lock-free)
┌────────────────────▼─────────────────────────────┐
│ packetviper-core                                 │
│ (Core Library)                                   │
│                                                  │
│ ┌──────────┐ ┌──────────┐ ┌──────────────────┐   │
│ │ Capture  │ │ Filter   │ │ Export           │   │
│ │ Engine   │ │ DSL      │ │ (JSON/CSV/PCAP)  │   │
│ └────┬─────┘ └──────────┘ └──────────────────┘   │
│      │                                           │
│ ┌────▼─────┐ ┌──────────┐ ┌──────────────────┐   │
│ │ Packet   │ │Bandwidth │ │ Threat           │   │
│ │ Parsers  │ │ Monitor  │ │ Detector         │   │
│ └──────────┘ └──────────┘ └──────────────────┘   │
└────────────────────┬─────────────────────────────┘
│ pnet (raw sockets)
┌─────────▼─────────┐
│ Linux Kernel      │
│ (Network Stack)   │
└───────────────────┘
```

## Data Flow

1. **Capture thread** reads raw Ethernet frames via `pnet`
2. Frames are parsed layer-by-layer into `CapturedPacket` structs
3. Packets are sent via **lock-free crossbeam channel** to main thread
4. Main thread:
   - Adds packet to storage
   - Runs it through **FilterEngine** to check visibility
   - Records in **BandwidthMonitor** for stats
   - Analyzes with **ThreatDetector** for security alerts
5. UI renders based on current `App` state

## Thread Model

[Capture Thread] ——packets——► [Main Thread (UI + Processing)]
│                               │
│ reads from NIC                ├── Updates App state
│ via pnet raw socket           ├── Renders TUI
│                               ├── Handles keyboard input
│ ◄──stop signal (AtomicBool)── └── Ticks stats

## Key Design Decisions

1. **pnet over libpcap**: Pure Rust, no C dependency, cross-compilation friendly
2. **crossbeam over std::mpsc**: Better performance, bounded channels prevent memory bloat
3. **Separate crates**: Core logic is reusable without TUI dependency
4. **Filter DSL**: Custom tokenizer + recursive descent parser for flexibility
5. **Threat detection**: Stateful analysis with time-windowed tracking