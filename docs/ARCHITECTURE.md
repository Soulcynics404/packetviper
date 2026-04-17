# Architecture

## Overview

PacketViper uses a **multi-crate workspace** architecture:
┌─────────────────────────────────────────────┐
│ packetviper-tui │
│ (Terminal UI — Ratatui + Crossterm) │
│ │
│ ┌──────────────────────────────────────┐ │
│ │ Event Loop (50ms tick) │ │
│ │ ├── Poll keyboard/mouse events │ │
│ │ ├── Drain packet channel │ │
│ │ └── Render UI frame │ │
│ └──────────────────────────────────────┘ │
└──────────────────┬──────────────────────────┘
│ crossbeam-channel
┌──────────────────▼──────────────────────────┐
│ packetviper-core │
│ (Core Library) │
│ │
│ ┌────────────┐ ┌─────────┐ ┌───────────┐ │
│ │ Capture │ │ Filters │ │ Export │ │
│ │ Engine │ │ Engine │ │ (JSON/CSV) │ │
│ └─────┬──────┘ └─────────┘ └───────────┘ │
│ │ │
│ ┌─────▼──────┐ ┌─────────┐ ┌───────────┐ │
│ │ Packet │ │ Stats │ │ Threat │ │
│ │ Parsers │ │ Monitor │ │ Detector │ │
│ └────────────┘ └─────────┘ └───────────┘ │
└──────────────────┬──────────────────────────┘
│ pnet (raw sockets)
┌─────────▼─────────┐
│ Linux Kernel │
│ (Network Stack) │
└───────────────────┘


## Data Flow

1. **Capture thread** reads raw frames from the NIC via `pnet`
2. Frames are parsed into `CapturedPacket` structs (L2 → L7)
3. Packets are sent via `crossbeam-channel` to the main thread
4. **Main thread** drains the channel, updates `App` state
5. **Ratatui** renders the UI based on current `App` state
6. **Keyboard events** are polled and dispatched to the handler

## Thread Safety

- Capture runs in a **separate OS thread**
- Communication uses **lock-free channels** (crossbeam)
- Capture can be stopped via **atomic flag** (`AtomicBool`)