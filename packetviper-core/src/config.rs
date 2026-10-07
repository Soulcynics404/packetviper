//! User settings, persisted as JSON so both the TUI and (later) the phone can read and change them.
//!
//! Stored at `$PACKETVIPER_CONFIG`, or `packetviper-config.json` in the working directory by default.
//! Loading never fails: a missing or broken file yields defaults, so the app always starts.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// How many bytes are in one megabyte, for the ring-buffer size setting.
pub const MB: u64 = 1024 * 1024;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// Write captured packets to disk (off by default).
    pub autosave: bool,
    /// Directory for the rolling capture files.
    pub capture_dir: String,
    /// Total size cap for saved captures, in MB. User-set; oldest data is deleted past this.
    pub ring_buffer_mb: u64,
    /// Automatically block/defend against detected attackers (off by default).
    pub auto_block: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            autosave: false,
            capture_dir: "captures".to_string(),
            ring_buffer_mb: 1024, // 1 GB default; the user can change it
            auto_block: false,
        }
    }
}

impl Config {
    /// The config file path: `$PACKETVIPER_CONFIG` or `packetviper-config.json` in the working dir.
    pub fn path() -> PathBuf {
        std::env::var_os("PACKETVIPER_CONFIG")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("packetviper-config.json"))
    }

    /// Loads the config, or defaults if the file is missing or unreadable.
    pub fn load() -> Self {
        match std::fs::read_to_string(Self::path()) {
            Ok(s) => serde_json::from_str(&s).unwrap_or_else(|e| {
                log::warn!("Config parse error ({}); using defaults", e);
                Config::default()
            }),
            Err(_) => Config::default(),
        }
    }

    /// Writes the config back to disk (pretty JSON).
    pub fn save(&self) -> std::io::Result<()> {
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(Self::path(), json)
    }

    /// Ring-buffer cap in bytes, never below 16 MB (a smaller ring can't hold even one segment).
    pub fn ring_bytes(&self) -> u64 {
        self.ring_buffer_mb.max(16) * MB
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_safe() {
        let c = Config::default();
        assert!(!c.autosave, "autosave must default off");
        assert!(!c.auto_block, "auto-block must default off");
        assert_eq!(c.ring_buffer_mb, 1024);
    }

    #[test]
    fn missing_fields_fall_back_to_defaults() {
        // A partial/old config file must still load, filling gaps with defaults.
        let c: Config = serde_json::from_str(r#"{"autosave":true}"#).unwrap();
        assert!(c.autosave);
        assert_eq!(c.ring_buffer_mb, 1024);
        assert_eq!(c.capture_dir, "captures");
    }

    #[test]
    fn ring_bytes_clamped() {
        let c = Config { ring_buffer_mb: 1, ..Default::default() };
        assert_eq!(c.ring_bytes(), 16 * MB);
        let c = Config { ring_buffer_mb: 2048, ..Default::default() };
        assert_eq!(c.ring_bytes(), 2048 * MB);
    }
}
