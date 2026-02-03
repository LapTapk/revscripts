//! JSON message parsing helpers for the gttrace server.

use serde::Deserialize;

/// A single control-flow edge captured by Frida Stalker.
#[derive(Debug, Clone)]
pub struct CfItem {
    /// Source address of the indirect call.
    pub from: u64,
    /// Target address of the indirect call.
    pub target: u64,
    /// Thread id that emitted the edge.
    pub tid: u32,
}

/// Module metadata announcement from the Frida script.
#[derive(Debug, Clone)]
pub struct ModMessage {
    /// Module name (e.g., basename of the image).
    pub name: String,
    /// Module start address.
    pub start: u64,
    /// Module end address.
    pub end: u64,
    /// Full path to the module on disk.
    pub path: String,
    /// Whether this is a removal notification.
    pub remove: bool,
}

/// Envelope used by Frida's `send()` API.
#[derive(Debug, Deserialize)]
pub struct Envelope {
    /// Message type tag from Frida (typically "send").
    #[serde(rename = "type")]
    pub ty: String,
    /// Message payload value (shape depends on the message type).
    #[serde(default)]
    pub payload: serde_json::Value,
}

/// Parse a hexadecimal string (with or without `0x`) into a `u64`.
fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

/// Parse a control-flow payload into a PID and its list of edges.
pub fn parse_cf_items(payload: &serde_json::Value) -> Option<(u32, Vec<CfItem>)> {
    let pid = payload.get("pid")?.as_u64()? as u32;
    let items = payload.get("items")?.as_array()?;

    let mut out = Vec::with_capacity(items.len());
    for it in items {
        let from_s = it.get("from")?.as_str()?;
        let target_s = it.get("target")?.as_str()?;
        let tid = it.get("tid")?.as_u64()? as u32;

        let from = parse_hex_u64(from_s)?;
        let target = parse_hex_u64(target_s)?;
        out.push(CfItem { from, target, tid });
    }
    Some((pid, out))
}

/// Parse a module announcement payload into a PID and module message.
pub fn parse_mod_message(payload: &serde_json::Value) -> Option<(u32, ModMessage)> {
    let pid = payload.get("pid")?.as_u64()? as u32;
    let name = payload.get("name")?.as_str()?.to_string();
    let start_s = payload.get("start")?.as_str()?;
    let end_s = payload.get("end")?.as_str()?;
    let path = payload.get("path")?.as_str()?.to_string();
    let remove = payload.get("remove")?.as_bool()?;

    let start = parse_hex_u64(start_s)?;
    let end = parse_hex_u64(end_s)?;

    Some((
        pid,
        ModMessage {
            name,
            start,
            end,
            path,
            remove,
        },
    ))
}
