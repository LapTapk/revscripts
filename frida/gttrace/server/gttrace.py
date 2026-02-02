#!/bin/env python3
"""CLI entrypoint for the gttrace Frida Stalker tracer.

This script orchestrates argument parsing, device selection, and tracer
startup/shutdown. It wires CLI flags into the TracerConf used by the
lower-level tracing pipeline.
"""

import argparse
import json
from pathlib import Path
from lib.server import Server

def parse_args() -> argparse.Namespace:
    """Define and parse CLI arguments for the tracer.

    Returns:
        Parsed CLI arguments matching TracerConf inputs.
    """
    p = argparse.ArgumentParser(
        description="Frida Stalker indirect calls tracer"
    )
    p.add_argument("address", help="Address of a gadget service")
    p.add_argument(
        "out",
        help="Output trace dir",
    )
    p.add_argument(
        "--wl",
        help="Whitelist of function to be traced"
    )
    return p.parse_args()



def main():
    """Configure tracing, run until interrupted, then detach cleanly."""
    args = parse_args()

    if args.wl:
        wl_path = Path(args.wl)
        if not wl_path.exists():
            print(f"[!] Whitelist file does not exist: {wl_path}")
            return 1

        with wl_path.open() as f:
            wl = json.load(f)
    else:
        wl = None

    server = Server(wl, args.address, args.out, 100000000)
    server.serve()
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
