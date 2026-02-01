#!/bin/env python3
"""CLI entrypoint for the gttrace Frida Stalker tracer.

This script orchestrates argument parsing, device selection, and tracer
startup/shutdown. It wires CLI flags into the TracerConf used by the
lower-level tracing pipeline.
"""

import frida
import argparse
import json
import threading
import time
from yaspin import yaspin
from lib.tracer import Tracer, TracerConf
from lib.common import ModRVA

def get_device(device, remote):
    """Resolve a Frida device handle from CLI arguments.

    Args:
        device: Device selector ("local", "usb", or "remote").
        remote: Remote host string used when device == "remote".

    Returns:
        A Frida device object ready for attach/spawn operations.
    """
    if device == "local":
        return frida.get_local_device()
    if device == "usb":
        return frida.get_usb_device(timeout=5)
    if device == "remote":
        return frida.get_device_manager().add_remote_device(remote)
    raise ValueError("Invalid device type")

def parse_entry(entry):
    """Parse <MOD>!0x<RVA> entrypoint strings into a ModRVA.

    The entrypoint is used by the Frida agent to start/stop coverage collection.
    """
    [mod, rva] = entry.split('!')
    return ModRVA(mod, int(rva, 16))

def parse_args() -> argparse.Namespace:
    """Define and parse CLI arguments for the tracer.

    Returns:
        Parsed CLI arguments matching TracerConf inputs.
    """
    p = argparse.ArgumentParser(
        description="Frida Stalker indirect calls tracer"
    )
    
    p.add_argument("target", help="Path to target binary or PID")
    p.add_argument(
           "--env",
           default=None,
           help="Env file for target",
    )
    p.add_argument(
        "--out",
        default="trace",
        help="Output trace file template. Output files will be named as </path/to/out>-<tid>. Default: %(default)s",
    )
    p.add_argument(
        "--device",
        default="local",
        choices=["local", "usb", "remote"],
        help="Frida device selection. Default: %(default)s",
    )
    p.add_argument(
        "--remote-host",
        default="127.0.0.1:27042",
        help='Remote Frida server address for --device remote (e.g. "192.168.1.10:27042")',
    )
    p.add_argument(
        "--pid",
        action="store_true",
        help="Attach to target pid instead of spawning it",
    )
    p.add_argument(
        "--wl",
        help="Whitelist of function to be traced"
    )
    p.add_argument(
        "--entry",
        help="Entrypoint which defines when to collect trace. Must be in format <MOD>!0x<HEX_RVA>. Coverage stops at ret."
    )
    p.add_argument(
        dest="passthrough",
        nargs=argparse.REMAINDER,
        help="Arguments passed to target. Example: script.py ./bin 0x401080 -- arg1 arg2",
    )

    return p.parse_args()



def main():
    """Configure tracing, run until interrupted, then detach cleanly."""
    args = parse_args()
    if args.wl:
        with open(args.wl, 'r') as f:
            wl = json.load(f)
    else:
        wl = None

    if args.env:
        with open(args.env, 'r') as f:
            envs_file = f.read()

        envs = dict(map(lambda x: x.split('=', 1), filter(str.strip, filter(None, envs_file.split('\n')))))
    else:
        envs = None 
        
    device = get_device(args.device, args.remote_host)
    if args.entry:
        entry = parse_entry(args.entry)
    else:
        entry = None

    conf = TracerConf(device, wl, args.out, envs, args.pid, args.target, args.passthrough, entry)
    tracer = Tracer(conf)

    tracer.start()

    try:
        while True:
            time.sleep(50)
    finally:
        with yaspin(text="Detaching", color="cyan"):
            t = threading.Thread(target=tracer.stop)
            t.start()
            t.join()


if __name__ == "__main__":
    main()
