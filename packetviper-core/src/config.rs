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
    /// Serve the phone/web dashboard on the LAN (on by default; access needs the per-run token).
    pub http_enabled: bool,
    /// Port for the dashboard server.
    pub http_port: u16,
    /// Allow the phone dashboard to CHANGE settings (autosave, defence, ring size). When false the
    /// dashboard is read-only. On by default because remote control was requested; note the dashboard
    /// is plain HTTP on the LAN, so anyone who captures the token could change settings.
    pub http_allow_control: bool,
    /// Push status to a relay server so alerts reach your phone off the LAN (off by default).
    pub relay_enabled: bool,
    /// Relay base URL, e.g. "http://1.2.3.4:9000" (your AWS instance). http:// only in this version.
    pub relay_url: String,
    /// Push key: the single relay secret (laptop-only); generated if empty. The phone's view code is
    /// derived from it as sha256(key), so it is not stored separately.
    pub relay_push_key: String,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            autosave: false,
            capture_dir: "captures".to_string(),
            ring_buffer_mb: 1024, // 1 GB default; the user can change it
            auto_block: false,
            http_enabled: true,
            http_port: 7373,
            http_allow_control: true,
            relay_enabled: false,
            relay_url: String::new(),
            relay_push_key: String::new(),
        }
    }
}

impl Config {
    /// Clamp for the ring size in MB: at least 16 MB, at most 1 TB (guards overflow and nonsense input).
    pub const MIN_RING_MB: u64 = 16;
    pub const MAX_RING_MB: u64 = 1_048_576;

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

    /// Writes the config back to disk (pretty JSON), owner-readable only. Refuses to write through a
    /// symlink, since we may run as root and the file sits in the working directory.
    pub fn save(&self) -> std::io::Result<()> {
        let path = Self::path();
        if std::fs::symlink_metadata(&path).map(|m| m.file_type().is_symlink()).unwrap_or(false) {
            return Err(std::io::Error::new(std::io::ErrorKind::Other, "config path is a symlink; refusing to write"));
        }
        let json = serde_json::to_string_pretty(self).map_err(std::io::Error::other)?;
        std::fs::write(&path, json)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
        }
        Ok(())
    }

    /// Capture directory limited to a safe relative path. A planted config can't point captures at a
    /// system location (absolute or containing `..`); such values fall back to the default.
    pub fn sanitized_capture_dir(&self) -> String {
        let d = &self.capture_dir;
        let unsafe_path = d.is_empty()
            || std::path::Path::new(d).is_absolute()
            || d.split(['/', '\\']).any(|p| p == "..");
        if unsafe_path { "captures".to_string() } else { d.clone() }
    }

    /// Ring-buffer cap in bytes, clamped to [MIN_RING_MB, MAX_RING_MB] with saturating math so a huge
    /// configured/remote value can't overflow.
    pub fn ring_bytes(&self) -> u64 {
        self.ring_buffer_mb.clamp(Self::MIN_RING_MB, Self::MAX_RING_MB).saturating_mul(MB)
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
