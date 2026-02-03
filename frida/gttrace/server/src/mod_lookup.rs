#[derive(Debug, Clone)]
pub struct ModRva {
    pub module: String,
    pub rva: u64,
}

#[derive(Debug, Default, Clone)]
pub struct ModLookup {
    starts: Vec<u64>,
    ends: Vec<u64>,
    names: Vec<String>,
}

impl ModLookup {
    pub fn new() -> Self { Self::default() }

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
