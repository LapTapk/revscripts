use serde::Serialize;

#[derive(Serialize)]
pub struct Event<'a> {
    #[serde(rename = "type")]
    pub typ: &'a str,
    pub ts_ms: u64,
    pub fd: i32,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_id: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub how: Option<&'a str>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<&'a str>,
}
