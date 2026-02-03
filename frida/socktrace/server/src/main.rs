//! Collects GTTR frames over an AF_UNIX datagram socket and writes structured
//! JSONL events plus per-connection payload streams.
//!
//! This binary pairs with `frida/socktrace/agent.js`:
//! - The agent emits GTTR frames via a UNIX datagram socket.
//! - The server decodes frames, normalizes metadata, and persists output in
//!   `events.jsonl` plus `<conn_id>.(in|out).bin` payload files.
//! - `conn_id` values are shared with the agent, so sanitization matches
//!   `safe_filename()` in `util.rs`.
//!
//! The output format is intended to be easy to consume with tooling like
//! `jq`, text editors, or custom scripts.

mod event;
mod frame;
mod output;
mod util;

use anyhow::{Context, Result};
use clap::Parser;
use event::Event;
use frame::{
    dir_name, frame_type_name, parse_frame, T_CLOSE, T_DATA, T_ERROR, T_INIT, T_LISTEN, T_OPEN,
    T_READY,
};
use output::OutputManager;
use std::{fs, path::PathBuf};
use tokio::net::UnixDatagram;
use util::{bytes_to_lossy_ascii, host_ts_secs, split_conn_how, ts_u64};

#[derive(Parser, Debug)]
#[command(name = "socktrace-server", version, about = "Collect GTTR frames over AF_UNIX datagram and write events+payloads")]
struct Cli {
    /// UNIX datagram socket path to bind (will unlink if exists)
    socket: PathBuf,

    /// Output directory (events.jsonl + per-conn payload files)
    out_dir: PathBuf,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    if cli.socket.exists() {
        fs::remove_file(&cli.socket)
            .with_context(|| format!("remove {}", cli.socket.display()))?;
    }

    let sock = UnixDatagram::bind(&cli.socket)
        .with_context(|| format!("bind {}", cli.socket.display()))?;

    let mut om = OutputManager::new(cli.out_dir)?;

    // Host banner (matches your Python host-side bookkeeping) :contentReference[oaicite:0]{index=0}
    let banner = serde_json::json!({
        "type": "host_init",
        "sock": cli.socket.to_string_lossy(),
        "ts_host": host_ts_secs(),
        "out_dir": om.out_dir().to_string_lossy(),
    });
    let _ = om.write_event(&banner);

    let mut buf = vec![0u8; 64 * 1024];

    loop {
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {
                let ev = serde_json::json!({
                    "type": "host_shutdown",
                    "ts_host": host_ts_secs(),
                });
                let _ = om.write_event(&ev);
                om.close_all();
                let _ = fs::remove_file(&cli.socket);
                break;
            }

            r = sock.recv(&mut buf) => {
                let n = match r {
                    Ok(n) => n,
                    Err(e) => {
                        let ev = serde_json::json!({
                            "type": "recv_error",
                            "error": e.to_string(),
                            "ts_host": host_ts_secs(),
                        });
                        let _ = om.write_event(&ev);
                        continue;
                    }
                };

                let fr = match parse_frame(&buf[..n]) {
                    Ok(fr) => fr,
                    Err(e) => {
                        let ev = serde_json::json!({
                            "type": "bad_frame",
                            "error": e.to_string(),
                            "size": n,
                            "ts_host": host_ts_secs(),
                        });
                        let _ = om.write_event(&ev);
                        continue;
                    }
                };

                let ts = ts_u64(fr.ts_ms_lo, fr.ts_ms_hi);
                let typ = frame_type_name(fr.typ);

                let path_s = bytes_to_lossy_ascii(fr.path);
                let conn_s = bytes_to_lossy_ascii(fr.conn);

                match fr.typ {
                    T_DATA => {
                        let direction = dir_name(fr.dir).unwrap_or("none");
                        let ev = Event {
                            typ,
                            ts_ms: ts,
                            fd: fr.fd,
                            direction: Some(direction),
                            path: Some(path_s.as_str()),
                            conn_id: Some(conn_s.as_str()),
                            how: None,
                            size: Some(fr.payload.len()),
                            raw: None,
                        };
                        om.write_event(&ev)?;

                        if (direction == "in" || direction == "out")
                            && !conn_s.is_empty()
                            && !fr.payload.is_empty()
                        {
                            om.write_data(&conn_s, direction, fr.payload)?;
                        }
                    }

                    T_CLOSE => {
                        let ev = Event {
                            typ,
                            ts_ms: ts,
                            fd: fr.fd,
                            direction: None,
                            path: None,
                            conn_id: Some(conn_s.as_str()),
                            how: None,
                            size: None,
                            raw: None,
                        };
                        om.write_event(&ev)?;
                        if !conn_s.is_empty() {
                            om.close_conn(&conn_s);
                        }
                    }

                    T_OPEN => {
                        let (conn_id, how) = split_conn_how(&conn_s);
                        let ev = Event {
                            typ,
                            ts_ms: ts,
                            fd: fr.fd,
                            direction: None,
                            path: Some(path_s.as_str()),
                            conn_id: Some(conn_id),
                            how,
                            size: None,
                            raw: None,
                        };
                        om.write_event(&ev)?;
                    }

                    T_LISTEN => {
                        let ev = Event {
                            typ,
                            ts_ms: ts,
                            fd: fr.fd,
                            direction: None,
                            path: Some(path_s.as_str()),
                            conn_id: None,
                            how: Some(conn_s.as_str()),
                            size: None,
                            raw: None,
                        };
                        om.write_event(&ev)?;
                    }

                    T_INIT | T_READY | T_ERROR => {
                        let ev = Event {
                            typ,
                            ts_ms: ts,
                            fd: fr.fd,
                            direction: None,
                            path: None,
                            conn_id: None,
                            how: None,
                            size: None,
                            raw: Some(conn_s.as_str()),
                        };
                        om.write_event(&ev)?;
                    }

                    _ => {
                        let ev = Event {
                            typ: "unknown",
                            ts_ms: ts,
                            fd: fr.fd,
                            direction: dir_name(fr.dir),
                            path: if path_s.is_empty() { None } else { Some(path_s.as_str()) },
                            conn_id: if conn_s.is_empty() { None } else { Some(conn_s.as_str()) },
                            how: None,
                            size: Some(fr.payload.len()),
                            raw: None,
                        };
                        om.write_event(&ev)?;
                    }
                }
            }
        }
    }

    Ok(())
}
