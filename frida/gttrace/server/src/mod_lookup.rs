//! Module interval lookup helper for resolving addresses to module RVAs.

/// A resolved module name with its relative virtual address (RVA).
#[derive(Debug, Clone)]
pub struct ModRva {
    /// Module name the address belongs to.
    pub module: String,
    /// Address offset from module base.
    pub rva: u64,
}

/// Ordered module interval table for fast address-to-module lookups.
#[derive(Debug, Default, Clone)]
pub struct ModLookup {
    starts: Vec<u64>,
    ends: Vec<u64>,
    names: Vec<String>,
}

impl ModLookup {
    /// Create a new, empty lookup table.
    pub fn new() -> Self { Self::default() }

    /// Insert a non-overlapping module range.
    pub fn add(&mut self, start: u64, end: u64, name: String) -> anyhow::Result<()> {
        anyhow::ensure!(start < end);

        let i = self.starts.partition_point(|&x| x < start);

        if i > 0 && start < self.ends[i - 1] {
            anyhow::bail!("overlaps previous interval");
        }
        if i < self.starts.len() && end > self.starts[i] {
            anyhow::bail!("overlaps next interval");
        }

        self.starts.insert(i, start);
        self.ends.insert(i, end);
        self.names.insert(i, name);
        Ok(())
    }

    /// Remove a module range only if the start and end match exactly.
    pub fn rem_exact(&mut self, start: u64, end: u64) -> bool {
        let i = self.starts.partition_point(|&x| x < start);
        if i >= self.starts.len() || self.starts[i] != start || self.ends[i] != end {
            return false;
        }
        self.starts.remove(i);
        self.ends.remove(i);
        self.names.remove(i);
        true
    }

    /// Resolve an absolute address into a module name and RVA.
    pub fn lookup(&self, addr: u64) -> Option<ModRva> {
        let i = self.starts.partition_point(|&x| x <= addr);
        if i == 0 {
            return None;
        }
        let idx = i - 1;
        if addr < self.ends[idx] {
            Some(ModRva {
                module: self.names[idx].clone(),
                rva: addr - self.starts[idx],
            })
        } else {
            None
        }
    }
}
