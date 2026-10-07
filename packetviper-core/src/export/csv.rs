//! CSV exporter

use super::{ExportError, Exporter};
use crate::packets::CapturedPacket;

pub struct CsvExporter;

impl Exporter for CsvExporter {
    fn export(&self, packets: &[CapturedPacket], path: &str) -> Result<(), ExportError> {
        let file = super::create_private(path)?;
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
                neutralize_formula(&pkt.protocol),
                neutralize_formula(&pkt.source),
                neutralize_formula(&pkt.destination),
                pkt.length.to_string(),
                pkt.direction.to_string(),
                neutralize_formula(&pkt.interface),
                neutralize_formula(&pkt.summary),
            ]).map_err(|e| ExportError::Serialization(e.to_string()))?;
        }

        wtr.flush()?;
        Ok(())
    }
}

/// Prefixes a quote to text a spreadsheet would run as a formula (=, +, -, @, tab, CR).
/// Packet-derived text is attacker-controlled.
fn neutralize_formula(s: &str) -> String {
    if s.starts_with(['=', '+', '-', '@', '\t', '\r']) { format!("'{}", s) } else { s.to_string() }
}
