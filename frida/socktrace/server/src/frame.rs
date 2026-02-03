//! GTTR frame parser shared between the Frida agent and this server.
//!
//! Frames are small binary datagrams with a fixed header and variable-length
//! path/conn/payload sections. See the comments in `agent.js` for the emitter
//! logic and framing layout.

use anyhow::{bail, Result};

/// Magic constant for GTTR frames ('GTTR' in little-endian).
pub const MAGIC_GTTR: u32 = 0x5254_5447; // 'GTTR' as little-endian u32
/// Supported wire format version.
pub const VER: u8 = 1;

/// Frame type: connection open.
pub const T_OPEN: u8 = 1;
/// Frame type: connection close.
pub const T_CLOSE: u8 = 2;
/// Frame type: listener announcement.
pub const T_LISTEN: u8 = 3;
/// Frame type: payload data.
pub const T_DATA: u8 = 4;
/// Frame type: agent ready.
pub const T_READY: u8 = 5;
/// Frame type: agent init banner.
pub const T_INIT: u8 = 6;
/// Frame type: agent error.
pub const T_ERROR: u8 = 7;

/// Parsed view into a single GTTR frame.
#[derive(Debug)]
pub struct Frame<'a> {
    /// Frame version (must be `VER`).
    pub ver: u8,
    /// Frame type.
    pub typ: u8,
    /// Flags bitfield (bit0 = payload present).
    pub flags: u16,
    /// Timestamp low 32 bits (milliseconds).
    pub ts_ms_lo: u32,
    /// Timestamp high 32 bits (milliseconds).
    pub ts_ms_hi: u32,
    /// File descriptor associated with the event.
    pub fd: i32,
    /// Direction (0 none, 1 in, 2 out).
    pub dir: u8, // 0 none, 1 in, 2 out
    /// Path bytes (ASCII-ish, as sent by the agent).
    pub path: &'a [u8],
    /// Connection identifier bytes.
    pub conn: &'a [u8],
    /// Payload bytes.
    pub payload: &'a [u8],
}

fn read_u8(b: &[u8], off: &mut usize) -> Result<u8> {
    if *off + 1 > b.len() { bail!("short read u8"); }
    let v = b[*off];
    *off += 1;
    Ok(v)
}

fn read_u16_le(b: &[u8], off: &mut usize) -> Result<u16> {
    if *off + 2 > b.len() { bail!("short read u16"); }
    let v = u16::from_le_bytes([b[*off], b[*off + 1]]);
    *off += 2;
    Ok(v)
}

fn read_u32_le(b: &[u8], off: &mut usize) -> Result<u32> {
    if *off + 4 > b.len() { bail!("short read u32"); }
    let v = u32::from_le_bytes([b[*off], b[*off + 1], b[*off + 2], b[*off + 3]]);
    *off += 4;
    Ok(v)
}

fn read_i32_le(b: &[u8], off: &mut usize) -> Result<i32> {
    Ok(read_u32_le(b, off)? as i32)
}

/// Parses a GTTR datagram into a [`Frame`].
pub fn parse_frame(buf: &[u8]) -> Result<Frame<'_>> {
    let mut off = 0;

    let magic = read_u32_le(buf, &mut off)?;
    if magic != MAGIC_GTTR {
        bail!("bad magic: 0x{magic:08x}");
    }

    let ver = read_u8(buf, &mut off)?;
    if ver != VER {
        bail!("unsupported ver: {ver}");
    }

    let typ = read_u8(buf, &mut off)?;
    let flags = read_u16_le(buf, &mut off)?;
    let ts_ms_lo = read_u32_le(buf, &mut off)?;
    let ts_ms_hi = read_u32_le(buf, &mut off)?;
    let fd = read_i32_le(buf, &mut off)?;
    let dir = read_u8(buf, &mut off)?;

    // reserved(3)
    if off + 3 > buf.len() { bail!("short read reserved"); }
    off += 3;

    let path_len = read_u16_le(buf, &mut off)? as usize;
    let conn_len = read_u16_le(buf, &mut off)? as usize;
    let payload_len = read_u32_le(buf, &mut off)? as usize;

    if off + path_len + conn_len + payload_len > buf.len() {
        bail!(
            "lengths exceed packet: off={} path={} conn={} payload={} total={}",
            off, path_len, conn_len, payload_len, buf.len()
        );
    }

    let path = &buf[off..off + path_len];
    off += path_len;

    let conn = &buf[off..off + conn_len];
    off += conn_len;

    let payload = &buf[off..off + payload_len];

    Ok(Frame { ver, typ, flags, ts_ms_lo, ts_ms_hi, fd, dir, path, conn, payload })
}

/// Returns a human-readable type name for a GTTR frame type.
pub fn frame_type_name(t: u8) -> &'static str {
    match t {
        T_OPEN => "open",
        T_CLOSE => "close",
        T_LISTEN => "listen",
        T_DATA => "data",
        T_READY => "ready",
        T_INIT => "init",
        T_ERROR => "error",
        _ => "unknown",
    }
}

/// Returns a human-readable direction name.
pub fn dir_name(d: u8) -> Option<&'static str> {
    match d {
        1 => Some("in"),
        2 => Some("out"),
        _ => None,
    }
}
