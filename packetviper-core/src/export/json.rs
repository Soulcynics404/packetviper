//! JSON exporter

use super::{ExportError, Exporter};
use crate::packets::CapturedPacket;
use std::io::Write;

pub struct JsonExporter;

impl Exporter for JsonExporter {
    fn export(&self, packets: &[CapturedPacket], path: &str) -> Result<(), ExportError> {
        let mut file = super::create_private(path)?;
        serde_json::to_writer_pretty(&mut file, packets)
            .map_err(|e| ExportError::Serialization(e.to_string()))?;
        file.flush()?;
        Ok(())
    }
}