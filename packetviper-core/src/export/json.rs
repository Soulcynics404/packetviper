//! JSON exporter

use super::{ExportError, Exporter};
use crate::packets::CapturedPacket;
use std::fs::File;
use std::io::Write;

pub struct JsonExporter;

impl Exporter for JsonExporter {
    fn export(&self, packets: &[CapturedPacket], path: &str) -> Result<(), ExportError> {
        let json = serde_json::to_string_pretty(packets)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        let mut file = File::create(path)?;
        file.write_all(json.as_bytes())?;
        Ok(())
    }
}