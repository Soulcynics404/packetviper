//! # PacketViper Core
//!
//! Core library for the PacketViper network traffic analyzer.
//! Provides packet capture, parsing, filtering, threat detection, and export.

pub mod capture;
pub mod packets;
pub mod filters;
pub mod stats;
pub mod threat;
pub mod export;

/// Re-export commonly used types
pub mod prelude {
    pub use crate::capture::engine::CaptureEngine;
    pub use crate::packets::{
        CapturedPacket, PacketDirection, LayerInfo,
        link::LinkLayerInfo,
        network::NetworkLayerInfo,
        transport::TransportLayerInfo,
        application::AppLayerInfo,
    };
    pub use crate::filters::engine::FilterEngine;
    pub use crate::stats::bandwidth::BandwidthMonitor;
    pub use crate::threat::detector::ThreatDetector;
}