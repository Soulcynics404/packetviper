//! Rolling ("ring buffer") packet capture to disk. Writes standard pcap files in segments; once the
//! total size passes the user-set cap, the oldest segment is deleted. So capture can run forever on a
//! fixed amount of disk, keeping only the most recent traffic — e.g. "keep the last 1 GB".
//!
//! Files are Wireshark-compatible pcap. Unlike the in-memory 128-byte preview, these hold full frames.

use std::collections::VecDeque;
use std::fs::File;
use std::io::{BufWriter, Write};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

/// Each segment grows to about this size before a new one starts. Smaller = finer pruning granularity.
const SEGMENT_BYTES: u64 = 64 * 1024 * 1024;
const PCAP_MAGIC: [u8; 24] = [
    0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // snaplen 65535, Ethernet
];

pub struct RingWriter {
    dir: PathBuf,
    max_bytes: u64,
    seq: u64,
    writer: BufWriter<File>,
    current_bytes: u64,
    /// (path, size) of every segment, oldest first; the last entry is the one being written.
    segments: VecDeque<(PathBuf, u64)>,
    total_bytes: u64,
}

impl RingWriter {
    /// Opens a fresh capture directory and first segment. `max_bytes` is the total on-disk cap.
    ///
    /// We may run as root, so the directory must not be a symlink (it could redirect writes to a
    /// system path), and each segment is created with O_EXCL so a pre-planted symlink is never followed.
    pub fn new(dir: &str, max_bytes: u64) -> std::io::Result<Self> {
        let dir = PathBuf::from(dir);
        match std::fs::symlink_metadata(&dir) {
            Ok(m) if m.file_type().is_symlink() =>
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "capture dir is a symlink; refusing")),
            Ok(m) if !m.is_dir() =>
                return Err(std::io::Error::new(std::io::ErrorKind::Other, "capture path exists and is not a directory")),
            Ok(_) => {}
            Err(_) => std::fs::create_dir_all(&dir)?,
        }
        let path = dir.join(format!("packetviper_capture_{:06}.pcap", 1));
        let writer = new_segment(&path)?;
        let mut segments = VecDeque::new();
        segments.push_back((path, PCAP_MAGIC.len() as u64));
        Ok(Self {
            dir,
            max_bytes,
            seq: 1,
            writer,
            current_bytes: PCAP_MAGIC.len() as u64,
            segments,
            total_bytes: PCAP_MAGIC.len() as u64,
        })
    }

    fn open_segment(&mut self) -> std::io::Result<()> {
        self.seq += 1;
        let path = self.dir.join(format!("packetviper_capture_{:06}.pcap", self.seq));
        self.writer = new_segment(&path)?;
        self.current_bytes = PCAP_MAGIC.len() as u64;
        self.segments.push_back((path, self.current_bytes));
        self.total_bytes += self.current_bytes;
        Ok(())
    }

    /// Appends one captured frame (full bytes). Rotates to a new segment and prunes oldest when over cap.
    pub fn write_frame(&mut self, frame: &[u8]) -> std::io::Result<()> {
        let (secs, usecs) = now_parts();
        let len = frame.len() as u32;
        self.writer.write_all(&secs.to_le_bytes())?;
        self.writer.write_all(&usecs.to_le_bytes())?;
        self.writer.write_all(&len.to_le_bytes())?; // captured length
        self.writer.write_all(&len.to_le_bytes())?; // original length
        self.writer.write_all(frame)?;
        let added = 16 + frame.len() as u64;
        self.current_bytes += added;
        self.total_bytes += added;
        if let Some(back) = self.segments.back_mut() { back.1 = self.current_bytes; }

        if self.current_bytes >= SEGMENT_BYTES {
            self.writer.flush()?;
            self.open_segment()?;
            self.prune();
        }
        Ok(())
    }

    /// Deletes oldest segments until the total is within the cap (never the segment being written).
    fn prune(&mut self) {
        while self.total_bytes > self.max_bytes && self.segments.len() > 1 {
            if let Some((path, size)) = self.segments.pop_front() {
                let _ = std::fs::remove_file(&path);
                self.total_bytes = self.total_bytes.saturating_sub(size);
                log::info!("Ring buffer: deleted oldest capture {}", path.display());
            }
        }
    }

    /// Flushes buffered data to disk (call before exit).
    pub fn flush(&mut self) {
        let _ = self.writer.flush();
    }

    pub fn total_bytes(&self) -> u64 { self.total_bytes }
    pub fn segment_count(&self) -> usize { self.segments.len() }
}

/// Creates a new pcap segment file with its global header written. `create_new` (O_EXCL) means an
/// existing file or symlink at this path is never opened/followed — important when running as root.
fn new_segment(path: &std::path::Path) -> std::io::Result<BufWriter<File>> {
    let mut f = BufWriter::new(std::fs::OpenOptions::new().write(true).create_new(true).open(path)?);
    f.write_all(&PCAP_MAGIC)?;
    f.flush()?;
    Ok(f)
}

/// Current time as (seconds, microseconds) since the Unix epoch, for the pcap record header.
fn now_parts() -> (u32, u32) {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(d) => (d.as_secs() as u32, d.subsec_micros()),
        Err(_) => (0, 0),
    }
}
