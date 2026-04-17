//! CSV exporter

use super::{ExportError, Exporter};
use crate::packets::CapturedPacket;
use std::fs::File;

pub struct CsvExporter;

impl Exporter for CsvExporter {
    fn export(&self, packets: &[CapturedPacket], path: &str) -> Result<(), ExportError> {
        let file = File::create(path)?;
        let mut wtr = csv::Writer::from_writer(file);

        // Write header
        wtr.write_record(&[
            "id", "timestamp", "protocol", "source", "destination",
            "length", "direction", "interface", "summary",
        ]).map_err(|e| ExportError::Serialization(e.to_string()))?;

        for pkt in packets {
            wtr.write_record(&[
                pkt.id.to_string(),
                pkt.timestamp.to_rfc3339(),
                pkt.protocol.clone(),
                pkt.source.clone(),
                pkt.destination.clone(),
                pkt.length.to_string(),
                pkt.direction.to_string(),
                pkt.interface.clone(),
                pkt.summary.clone(),
            ]).map_err(|e| ExportError::Serialization(e.to_string()))?;
        }

        wtr.flush()?;
        Ok(())
    }
}