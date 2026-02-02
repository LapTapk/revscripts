use serde::Deserialize;

#[derive(Debug, Clone)]
pub struct CfItem {
    pub from: u64,
    pub target: u64,
    pub tid: u32,
}

#[derive(Debug, Clone)]
pub struct ModMessage {
    pub name: String,
    pub start: u64,
    pub end: u64,
    pub path: String,
    pub remove: bool,
}

#[derive(Debug, Deserialize)]
pub struct Envelope {
    #[serde(rename = "type")]
    pub ty: String,
    #[serde(default)]
    pub payload: serde_json::Value,
}

fn parse_hex_u64(s: &str) -> Option<u64> {
    let s = s.strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(s, 16).ok()
}

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
