//! Output management for JSONL events and per-connection payloads.

use crate::util::safe_filename;
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    collections::HashMap,
    fs::{self, File, OpenOptions},
    io::Write,
    os::unix::fs::OpenOptionsExt,
    path::{Path, PathBuf},
};

/// Manages output files for events and payload streams.
pub struct OutputManager {
    out_dir: PathBuf,
    events: File,
    streams: HashMap<(String, String), File>, // (conn_id, direction) -> file
}

impl OutputManager {
    /// Creates (and opens) the output directory and event log file.
    pub fn new(out_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&out_dir).context("create out_dir")?;

        let events_path = out_dir.join("events.jsonl");
        let events = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&events_path)
            .with_context(|| format!("open {}", events_path.display()))?;

        Ok(Self {
            out_dir,
            events,
            streams: HashMap::new(),
        })
    }

    /// Appends a JSON event line to `events.jsonl`.
    pub fn write_event<T: Serialize>(&mut self, ev: &T) -> Result<()> {
        let line = serde_json::to_string(ev)? + "\n";
        self.events.write_all(line.as_bytes())?;
        Ok(())
    }

    /// Opens (or reuses) a payload stream for a `(conn_id, direction)` pair.
    fn open_stream(&mut self, conn_id: &str, direction: &str) -> Result<&mut File> {
        let key = (conn_id.to_string(), direction.to_string());
        if !self.streams.contains_key(&key) {
            let fname = format!(
                "{}.{}.bin",
                safe_filename(conn_id),
                if direction == "in" { "in" } else { "out" }
            );
            let fpath = self.out_dir.join(fname);

            let f = OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(&fpath)
                .with_context(|| format!("open {}", fpath.display()))?;

            self.streams.insert(key.clone(), f);
        }
        Ok(self.streams.get_mut(&key).unwrap())
    }

    /// Appends payload bytes to the appropriate per-connection file.
    pub fn write_data(&mut self, conn_id: &str, direction: &str, blob: &[u8]) -> Result<()> {
        let f = self.open_stream(conn_id, direction)?;
        f.write_all(blob)?;
        Ok(())
    }

    /// Flushes and closes payload streams for a connection.
    pub fn close_conn(&mut self, conn_id: &str) {
        for direction in ["in", "out"] {
            let key = (conn_id.to_string(), direction.to_string());
            if let Some(mut f) = self.streams.remove(&key) {
                let _ = f.flush();
            }
        }
    }

    /// Flushes all open files (event log and payload streams).
    pub fn close_all(&mut self) {
        for (_, mut f) in self.streams.drain() {
            let _ = f.flush();
        }
        let _ = self.events.flush();
    }

    /// Returns the output directory path.
    pub fn out_dir(&self) -> &Path {
        &self.out_dir
    }
}
