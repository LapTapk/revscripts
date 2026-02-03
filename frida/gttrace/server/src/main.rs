mod server;
mod messages;
mod mod_lookup;
mod outman;

use anyhow::{Context, Result};
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(about = "Frida Stalker indirect calls tracer server (Rust port)")]
struct Args {
    /// AF_UNIX datagram socket path
    address: PathBuf,
    /// Output directory
    out: PathBuf,
    /// Optional whitelist JSON: { "mod": [rva_int, ...], ... }
    #[arg(long)]
    wl: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    let wl = if let Some(p) = args.wl.as_ref() {
        let data = std::fs::read_to_string(p).with_context(|| format!("reading whitelist {p:?}"))?;
        let map: std::collections::HashMap<String, Vec<u64>> =
            serde_json::from_str(&data).context("parsing whitelist json")?;
        Some(map)
    } else {
        None
    };

    let srv = server::Server::new(wl, args.address, args.out);
    srv.serve()
}
