//! PCAP exporter — will be fully implemented in Phase 4

use super::{ExportError, Exporter};
use crate::packets::CapturedPacket;
use std::io::Write;

pub struct PcapExporter;

impl Exporter for PcapExporter {
    fn export(&self, packets: &[CapturedPacket], path: &str) -> Result<(), ExportError> {
        let mut file = super::create_private(path)?;

        // PCAP Global Header
        let global_header: [u8; 24] = [
            0xd4, 0xc3, 0xb2, 0xa1, // Magic number (little-endian)
            0x02, 0x00,             // Major version
            0x04, 0x00,             // Minor version
            0x00, 0x00, 0x00, 0x00, // Timezone (GMT)
            0x00, 0x00, 0x00, 0x00, // Sigfigs
            0x80, 0x00, 0x00, 0x00, // Snaplen (128): only the first 128 bytes of each frame are kept in memory
            0x01, 0x00, 0x00, 0x00, // Network (Ethernet)
        ];
        file.write_all(&global_header)?;

        for pkt in packets {
            let ts_secs = pkt.timestamp.timestamp() as u32;
            let ts_usecs = pkt.timestamp.timestamp_subsec_micros();
            let cap_len = pkt.raw_preview.len() as u32;
            let orig_len = u32::try_from(pkt.length).unwrap_or(u32::MAX);

            // Packet header (16 bytes)
            file.write_all(&ts_secs.to_le_bytes())?;
            file.write_all(&ts_usecs.to_le_bytes())?;
            file.write_all(&cap_len.to_le_bytes())?;
            file.write_all(&orig_len.to_le_bytes())?;

            // Packet data
            file.write_all(&pkt.raw_preview)?;
        }

        file.flush()?;
        Ok(())
    }
}