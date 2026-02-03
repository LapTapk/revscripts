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

pub struct OutputManager {
    out_dir: PathBuf,
    events: File,
    streams: HashMap<(String, String), File>, // (conn_id, direction) -> file
}

impl OutputManager {
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

    pub fn write_event<T: Serialize>(&mut self, ev: &T) -> Result<()> {
        let line = serde_json::to_string(ev)? + "\n";
        self.events.write_all(line.as_bytes())?;
        Ok(())
    }

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

    pub fn write_data(&mut self, conn_id: &str, direction: &str, blob: &[u8]) -> Result<()> {
        let f = self.open_stream(conn_id, direction)?;
        f.write_all(blob)?;
        Ok(())
    }

    pub fn close_conn(&mut self, conn_id: &str) {
        for direction in ["in", "out"] {
            let key = (conn_id.to_string(), direction.to_string());
            if let Some(mut f) = self.streams.remove(&key) {
                let _ = f.flush();
            }
        }
    }

    pub fn close_all(&mut self) {
        for (_, mut f) in self.streams.drain() {
            let _ = f.flush();
        }
        let _ = self.events.flush();
    }

    pub fn out_dir(&self) -> &Path {
        &self.out_dir
    }
}
