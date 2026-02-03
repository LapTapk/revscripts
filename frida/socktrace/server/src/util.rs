use std::time::{SystemTime, UNIX_EPOCH};

pub fn bytes_to_lossy_ascii(b: &[u8]) -> String {
    // Agent writes mostly ASCII; for non-printable, use replacement char.
    b.iter()
        .map(|&c| if (32..=126).contains(&c) { c as char } else { '\u{FFFD}' })
        .collect()
}

pub fn safe_filename(s: &str) -> String {
    // Mirrors Python regex: [^a-zA-Z0-9_.:@=\-+] => '_'  (see your OutputManager) :contentReference[oaicite:0]{index=0}
    s.chars()
        .map(|ch| match ch {
            'a'..='z'
            | 'A'..='Z'
            | '0'..='9'
            | '_'
            | '.'
            | ':'
            | '@'
            | '='
            | '-'
            | '+'
            => ch,
            _ => '_',
        })
        .collect()
}

pub fn ts_u64(lo: u32, hi: u32) -> u64 {
    ((hi as u64) << 32) | (lo as u64)
}

pub fn host_ts_secs() -> f64 {
    let dur = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default();
    (dur.as_secs() as f64) + (dur.subsec_nanos() as f64) * 1e-9
}

pub fn split_conn_how(s: &str) -> (&str, Option<&str>) {
    // JS open: `${connId}|${how}`
    if let Some(pos) = s.find('|') {
        let (a, b) = s.split_at(pos);
        let how = &b[1..];
        (a, if how.is_empty() { None } else { Some(how) })
    } else {
        (s, None)
    }
}
