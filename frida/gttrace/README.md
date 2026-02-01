# gttrace

`gttrace` is a Frida Stalker-based tracer for capturing indirect call and jump
edges from a running process. It resolves module RVAs, optionally symbolicates
with debug info, and writes per-thread trace logs that are easy to post-process.

## Features

- Trace indirect `call` and `j*` edges per thread using Frida Stalker.
- Optional whitelist filtering by module + RVA to focus on relevant functions.
- Entry-point gating to start/stop coverage within a specific function.
- Per-thread trace files with resolved symbols when available.

## Target restrictions
- Debug symbols are only avalible for ELF files for now

## Requirements

- Python 3
- Frida (Python bindings and a compatible Frida server for remote/USB targets)
- Optional: debug symbols for richer output

## Usage

Run the tracer against a binary (spawn) or PID (attach):

```bash
python3 gttrace.py /path/to/target -- arg1 arg2
python3 gttrace.py 1234 --pid
```

Select a device or remote Frida server:

```bash
python3 gttrace.py /path/to/target --device usb
python3 gttrace.py /path/to/target --device remote --remote-host 192.168.1.10:27042
```

Specify an output prefix (defaults to `trace`):

```bash
python3 gttrace.py /path/to/target --out /tmp/trace
```

### Whitelisting via Ghidra

To focus on specific functions, pass a whitelist JSON file with `--wl`. The
expected JSON format maps module names to a list of RVAs. You can generate this
file in Ghidra with `ghidra/DumpFuncRVAs.py`, which exports filtered function
RVAs that are directly compatible with `gttrace`.

```bash
python3 gttrace.py /path/to/target --wl /path/to/functions.json
```

### Entrypoint gating

Use `--entry` to start coverage only when a specific function is entered and
stop when it returns. The format is `<MOD>!0x<RVA>`:

```bash
python3 gttrace.py /path/to/target --entry libfoo.so!0x1234
```

## Output format

Each traced thread writes to its own file named `<out>-<tid>`, with one edge per
line:

```
<module>!<symbol_or_rva> ---> <module>!<symbol_or_rva>
```

## Notes

- The tracer resolves module ranges dynamically; make sure the target's modules
  are loaded before expecting coverage results.
- Provide debug symbols for more readable output names.
