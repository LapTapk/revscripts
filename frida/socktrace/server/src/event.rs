//! JSON-serializable event model written to `events.jsonl`.

use serde::Serialize;

/// Represents a single event derived from a GTTR frame.
///
/// Fields are optional to keep the JSONL schema compact; absent fields are
/// omitted via `skip_serializing_if`.
#[derive(Serialize)]
pub struct Event<'a> {
    /// Event type (e.g., "open", "data", "close").
    #[serde(rename = "type")]
    pub typ: &'a str,
    /// Timestamp in milliseconds since the agent's epoch (as sent by the agent).
    pub ts_ms: u64,
    /// File descriptor associated with the event.
    pub fd: i32,

    /// Direction for payload events ("in" or "out").
    #[serde(skip_serializing_if = "Option::is_none")]
    pub direction: Option<&'a str>,

    /// UNIX socket path for listeners or connections.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<&'a str>,

    /// Connection identifier emitted by the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub conn_id: Option<&'a str>,

    /// Additional metadata ("how") emitted by the agent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub how: Option<&'a str>,

    /// Payload size in bytes (if applicable).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<usize>,

    /// Free-form raw field used for init/error messages.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raw: Option<&'a str>,
}
