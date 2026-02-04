//! Output management for writing traced control-flow edges to disk.

use crate::messages::CfItem;
use crate::mod_lookup::{ModLookup, ModRva};
use anyhow::Result;
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

/// Handles per-thread output files and module resolution.
pub struct OutputManager {
    opened: HashMap<u32, File>,
    wl: Option<HashMap<String, Vec<u64>>>,
    /// Module lookup table for translating addresses to module RVAs.
    pub mods: ModLookup,
    out_dir: PathBuf,
}

impl OutputManager {
    /// Create a new output manager rooted at `out_dir`.
    pub fn new(
        wl: Option<HashMap<String, Vec<u64>>>,
        out_dir: &Path,
    ) -> Result<Self> {
        create_dir_all(out_dir)?;
        Ok(Self {
            opened: HashMap::new(),
            wl,
            mods: ModLookup::new(),
            out_dir: out_dir.to_path_buf(),
        })
    }

    /// Check whether a module/RVA pair is allowed by the whitelist.
    fn is_whitelisted(&self, ma: &ModRva) -> bool {
        let Some(wl) = &self.wl else { return true; };
        let Some(list) = wl.get(&ma.module) else { return false; };
        list.iter().any(|&x| x == ma.rva)
    }

    /// Render a module/RVA as a `module!0xaddr` string.
    fn prettify_addr(&self, ma: &ModRva) -> String {
        format!("{}!{:#x}", ma.module, ma.rva)
    }

    /// Write a batch of control-flow edges to per-thread trace files.
    pub fn write_edges(&mut self, cfs: &[CfItem]) -> Result<()> {
        for cf in cfs {
            let Some(frm) = self.mods.lookup(cf.from) else { continue; };
            let Some(tgt) = self.mods.lookup(cf.target) else { continue; };
            if !self.is_whitelisted(&tgt) {
                continue;
            }

            let frm_s = self.prettify_addr(&frm);
            let tgt_s = self.prettify_addr(&tgt);

            let f = self.opened.entry(cf.tid).or_insert_with(|| {
                let p = self.out_dir.join(format!("trace-{}", cf.tid));
                // line buffering like python buffering=1: just flush after each line
                File::create(p).expect("create trace file")
            });

            writeln!(f, "{} ---> {}", frm_s, tgt_s)?;
            f.flush()?;
        }
        Ok(())
    }
}
