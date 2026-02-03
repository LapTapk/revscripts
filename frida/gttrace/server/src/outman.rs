use crate::messages::CfItem;
use crate::mod_lookup::{ModLookup, ModRva};
use anyhow::Result;
use std::collections::HashMap;
use std::fs::{create_dir_all, File};
use std::io::Write;
use std::path::{Path, PathBuf};

pub struct OutputManager {
    opened: HashMap<u32, File>,
    wl: Option<HashMap<String, Vec<u64>>>,
    pub mods: ModLookup,
    out_dir: PathBuf,
}

impl OutputManager {
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

    fn is_whitelisted(&self, ma: &ModRva) -> bool {
        let Some(wl) = &self.wl else { return true; };
        let Some(list) = wl.get(&ma.module) else { return false; };
        list.iter().any(|&x| x == ma.rva)
    }

    fn prettify_addr(&self, ma: &ModRva) -> String {
        format!("{}!{:#x}", ma.module, ma.rva)
    }

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
