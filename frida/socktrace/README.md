# socktrace

`socktrace` is a Frida-based AF_UNIX socket tracer. It consists of two pieces:

- **Agent**: `frida/socktrace/agent.js` hooks libc socket syscalls inside a target
  process and emits compact binary frames (GTTR) over a UNIX socket.
- **Server**: `frida/socktrace/server` receives those frames, decodes them, and
  writes JSONL events plus per-connection payload files for analysis.

This README focuses on how to run the tracer and how to interpret the output so
contributors can extend or troubleshoot the pipeline.

## Limitations

This utility was tested only on Linux x86_64

## Quick start

### 1) Build the server

From the repo root:

```bash
cd frida/socktrace/server
make
```

### 2) Run the server

Pick a UNIX datagram socket path and an output directory:

```bash
./target/release/socktrace-server /tmp/socktrace.sock /tmp/socktrace-out
```

The server will create the socket (unlinking it first if it exists) and write
output into `/tmp/socktrace-out`.

### 3) Load the agent
Load the agent with Frida Gadget in script or script-directory mode. 
In Gadget config provide following paramaters to script:

- `out_socket_path` (string): socket for traces transfer

Optional parameters:

- `max_fds` (int): maximum fd to scan for pre-existing sockets (default 4096).
- `max_bytes` (int): max payload bytes captured per event (default 4096).
- `socket_paths` (array): whitelist of UNIX socket paths to trace.
- `out_sock_type` (string): `"dgram"` (default) or `"stream"`.

## Output format

The server writes two kinds of files into the output directory:

1. **`events.jsonl`**: newline-delimited JSON with metadata for every event.
2. **`<conn_id>.(in|out).bin`**: raw payload bytes for each connection and
   direction.

Event objects typically include:

- `type`: one of `open`, `close`, `listen`, `data`, `init`, `ready`, `error`.
- `ts_ms`: agent-side timestamp (milliseconds).
- `fd`: file descriptor (when applicable).
- `path`: UNIX socket path (for listen/open/data).
- `conn_id`: connection identifier (for open/data/close).
- `direction`: `in` or `out` (for data).
- `size`: payload size (for data).
- `raw`: textual metadata (for init/ready/error).

### Example workflow

```bash
# Show event stream
jq -c . /tmp/socktrace-out/events.jsonl | head

# Extract outbound payloads for a connection
ls /tmp/socktrace-out/*out.bin
```

## Notes for contributors

- The GTTR frame layout is documented inline in `agent.js` and mirrored in the
  Rust parser (`server/src/frame.rs`). If you change framing or add new types,
  update both sides.
- Connection IDs are sanitized in the agent and used as filenames by the
  server. Keep the sanitization logic compatible (`safe_filename()` in
  `server/src/util.rs`).
- The agent suppresses tracing while it emits frames to avoid recursion. If you
  add new hooks, be sure to honor the suppression guard and exclude the output
  socket fd.

## Troubleshooting

- **No output files**: confirm the server is running and the agent is sending to
  the same `out_socket_path`.
- **Missing payloads**: verify `max_bytes` is not set too low and that the agent
  isn't filtering via `socket_paths`.
- **Errors in events**: look for `error` or `bad_frame` entries in
  `events.jsonl`.
