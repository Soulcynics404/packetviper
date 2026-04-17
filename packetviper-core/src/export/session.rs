//! Session save and restore

use crate::packets::CapturedPacket;
use std::fs::File;
use std::io::{Read, Write};

pub struct SessionManager;

impl SessionManager {
    /// Save packets to a session file
    pub fn save(packets: &[CapturedPacket], bookmarks: &[u64], path: &str) -> Result<String, String> {
        let session = SessionData {
            version: "0.1.0".to_string(),
            packet_count: packets.len(),
            bookmarks: bookmarks.to_vec(),
            packets: packets.to_vec(),
        };

        let json = serde_json::to_string(&session)
            .map_err(|e| format!("Serialization error: {}", e))?;

        let mut file = File::create(path)
            .map_err(|e| format!("File error: {}", e))?;

        file.write_all(json.as_bytes())
            .map_err(|e| format!("Write error: {}", e))?;

        Ok(path.to_string())
    }

    /// Load packets from a session file
    pub fn load(path: &str) -> Result<SessionData, String> {
        let mut file = File::open(path)
            .map_err(|e| format!("File error: {}", e))?;

        let mut contents = String::new();
        file.read_to_string(&mut contents)
            .map_err(|e| format!("Read error: {}", e))?;

        let session: SessionData = serde_json::from_str(&contents)
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