pub mod json;
pub mod csv;
pub mod pcap;
pub mod session;

use crate::packets::CapturedPacket;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ExportError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    #[error("Serialization error: {0}")]
    Serialization(String),
}

pub trait Exporter {
    fn export(&self, packets: &[CapturedPacket], path: &str) -> Result<(), ExportError>;
}