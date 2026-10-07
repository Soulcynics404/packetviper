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

/// Creates `path` readable only by the owner (0600 on Unix): exports can contain payloads and credentials.
/// Exports usually run as root via sudo, so default permissions would leave them world-readable.
pub(crate) fn create_private(path: &str) -> std::io::Result<std::io::BufWriter<std::fs::File>> {
    let mut opts = std::fs::OpenOptions::new();
    // create_new (O_EXCL) never follows or overwrites an existing file/symlink: we usually run as root,
    // and file names are predictable timestamps.
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    Ok(std::io::BufWriter::new(opts.open(path)?))
}
