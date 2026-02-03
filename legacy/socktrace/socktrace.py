#!/usr/bin/env python3
# frida_unix_socket_trace.py
#
# Traces UNIX-domain client socket traffic for a whitelist of socket paths.
# - Attaches to PID or spawns a target program
# - Maps already-open UNIX sockets to paths (via getpeername)
# - Hooks connect() to discover new UNIX client connections
# - Hooks send/recv/read/write, filters by tracked fds, streams payloads to host
# - Hooks close() and dup/dup2/dup3 to maintain fd tracking
#
# Output:
#   <output_dir>/<conn_id>.in.bin
#   <output_dir>/<conn_id>.out.bin
#   <output_dir>/events.jsonl   (metadata, open/close)
#
# Notes / limitations:
# - Only AF_UNIX sockets are tracked.
# - connect() asynchronous EINPROGRESS is treated as "pending" but may not resolve
#   to a path if never becomes connected (best effort).
# - recv() payload is captured onLeave using return value.
# - For very large buffers, payloads are capped (see --max-bytes).

import argparse
import time
import sys
import signal
from pathlib import Path
import frida
from lib.outman import OutputManager
from lib.tracer import Tracer


def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Trace UNIX-domain socket traffic via Frida.")
    p.add_argument("target", type=str, help="Spawn and attach to program path or PID")
    p.add_argument("libc", help="libc module name (e.g. libc.so.6)")
    p.add_argument("sockets", help="UNIX socket path to whitelist")
    p.add_argument("out", help="Output directory")
    p.add_argument("--pid", action="store_true", help="Attach to an existing PID")
    p.add_argument("--max-fds", type=int, default=4096, help="FD scan range for preexisting sockets")
    p.add_argument("--max-bytes", type=int, default=4096, help="Max bytes captured per call")
    p.add_argument("--pending-ttl-ms", type=int, default=5000, help="TTL for pending connect sweep")
    p.add_argument("--pending-sweep-ms", type=int, default=250, help="Sweep interval for pending connects")
    p.add_argument("--env", help="Enironment file for spawning process")
    p.add_argument(dest="argv", nargs=argparse.REMAINDER, help="Arguments for target")
    return p.parse_args()

def main() -> int:
    args = _parse_args()
    out_dir = Path(args.out).resolve()
    om = OutputManager(out_dir)

    with open(args.sockets, 'r') as f:
        sockets = f.read()
    sockets = [s.strip() for s in sockets.split('\n') if s.strip()]

    cfg = {
        "libc_name": args.libc,
        "socket_paths": sockets,
        "max_fds": int(args.max_fds),
        "max_bytes": int(args.max_bytes),
        "pending_ttl_ms": int(args.pending_ttl_ms),
        "pending_sweep_ms": int(args.pending_sweep_ms),
    }

    if args.env:
        with open(args.env, 'r') as f:
            envs_file = f.read()

        envs = dict(map(lambda x: x.split('=', 1), filter(str.strip, filter(None, envs_file.split('\n')))))
    else:
        envs = None 


    device = frida.get_local_device()
    tracer = Tracer(cfg, device, om, args.pid, args.target, args.argv, envs)

    def sigint_handler(_sig, _frame):
        tracer.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, sigint_handler)

    try:
        tracer.start()

        while True:
            time.sleep(0.25)
    except Exception as e:
        print(e)
    finally:
        tracer.stop()
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
