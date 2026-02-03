use crate::messages::{Envelope, parse_cf_items, parse_mod_message};
use crate::outman::OutputManager;
use anyhow::{Context, Result};
use nix::sys::stat::{fchmod, Mode};
use std::os::unix::io::AsRawFd;
use std::collections::HashMap;
use std::os::unix::net::UnixDatagram;
use std::path::{PathBuf};

pub struct Server {
    wl: Option<HashMap<String, Vec<u64>>>,
    address: PathBuf,
    out: PathBuf,
    outmans: HashMap<u32, OutputManager>,
    bufsize: usize,
}

impl Server {
    pub fn new(
        wl: Option<HashMap<String, Vec<u64>>>,
        address: PathBuf,
        out: PathBuf,
    ) -> Self {
        Self { wl, address, out, outmans: HashMap::new(), bufsize: 100_000_000 }
    }

    fn get_outman(&mut self, pid: u32) -> Result<&mut OutputManager> {
        if !self.outmans.contains_key(&pid) {
            let om = OutputManager::new(self.wl.clone(), &self.out)?;
            self.outmans.insert(pid, om);
        }
        Ok(self.outmans.get_mut(&pid).unwrap())
    }

    fn on_message(&mut self, env: Envelope) -> Result<()> {
        if env.ty != "send" {
            eprintln!("{env:?}");
            return Ok(());
        }

        let payload = env.payload;
        let mtype = payload.get("type").and_then(|v| v.as_str()).unwrap_or("");

        match mtype {
            "cf" => {
                if let Some((pid, items)) = parse_cf_items(&payload) {
                    self.get_outman(pid)?.write_edges(&items)?;
                }
            }
            "mod" => {
                if let Some((pid, mm)) = parse_mod_message(&payload) {
                    let om = self.get_outman(pid)?;
                    if mm.remove {
                        om.mods.rem_exact(mm.start, mm.end);
                        eprintln!("[+] removed mod {} pid: {}", mm.name, pid);
                    } else {
                        om.mods.add(mm.start, mm.end, mm.name.clone())?;
                        eprintln!("[+] added new mod {} pid: {}", mm.name, pid);
                    }
                }
            }
            "status" => {
                let msg = payload.get("msg").and_then(|v| v.as_str()).unwrap_or("");
                eprintln!("[+] {msg}");
            }
            "done" => {
                eprintln!("[+] done");
            }
            _ => {
                eprintln!("[?] {}", payload);
            }
        }

        Ok(())
    }

    pub fn serve(mut self) -> Result<()> {
        // unlink old socket path
        let _ = std::fs::remove_file(&self.address);

        let sock = UnixDatagram::bind(&self.address)
            .with_context(|| format!("binding unix dgram {:?}", self.address))?;

        // chmod 0666 like python
        fchmod(sock.as_raw_fd(), Mode::from_bits_truncate(0o666))
            .context("chmod socket")?;

        eprintln!("listening on {:?}", self.address);

        let mut buf = vec![0u8; self.bufsize];
        loop {
            let n = sock.recv(&mut buf).context("recv")?;
            if n == 0 {
                continue;
            }
            let raw = String::from_utf8_lossy(&buf[..n]);
            for line in raw.split('\n').map(|s| s.trim()).filter(|s| !s.is_empty()) {
                match serde_json::from_str::<Envelope>(line) {
                    Ok(env) => self.on_message(env)?,
                    Err(_) => {
                        eprintln!("JSON decode error");
                        eprintln!("{raw}");
                        return Ok(());
                    }
                }
            }
        }
    }
}
