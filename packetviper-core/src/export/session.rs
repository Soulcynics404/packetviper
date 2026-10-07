//! Session save and restore

use crate::packets::CapturedPacket;
use std::fs::File;
use std::io::Write;

const MAX_SESSION_BYTES: u64 = 1_000_000_000;

pub struct SessionManager;

impl SessionManager {
    /// Save packets to a session file
    pub fn save(packets: &[CapturedPacket], bookmarks: &[u64], path: &str) -> Result<String, String> {
        let session = SessionData {
            version: env!("CARGO_PKG_VERSION").to_string(),
            packet_count: packets.len(),
            bookmarks: bookmarks.to_vec(),
            packets: packets.to_vec(),
        };

        let mut file = super::create_private(path)
            .map_err(|e| format!("File error: {}", e))?;
        serde_json::to_writer(&mut file, &session)
            .map_err(|e| format!("Serialization error: {}", e))?;
        file.flush().map_err(|e| format!("Write error: {}", e))?;

        Ok(path.to_string())
    }

    /// Load packets from a session file
    pub fn load(path: &str) -> Result<SessionData, String> {
        let file = File::open(path)
            .map_err(|e| format!("File error: {}", e))?;
        let size = file.metadata().map_err(|e| format!("File error: {}", e))?.len();
        if size > MAX_SESSION_BYTES {
            return Err(format!("Session file too large ({} MB, max {} MB)", size / 1_000_000, MAX_SESSION_BYTES / 1_000_000));
        }
        let session: SessionData = serde_json::from_reader(std::io::BufReader::new(file))
            .map_err(|e| format!("Parse error: {}", e))?;

        Ok(session)
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SessionData {
    pub version: String,
    pub packet_count: usize,
    pub bookmarks: Vec<u64>,
    pub packets: Vec<CapturedPacket>,
}