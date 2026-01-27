#!/usr/bin/env python3

'''
This script logs every call or jump address and
destination address. Separates addresses by
threads.

Helpful when code contains many indirect calls.

author: LapTapk
'''

import argparse
import frida
import threading
import time
import os

JS_TEMPLATE = r"""
'use strict';

let followed = new Set();
const symCache = new Map(); 
let buf = [];
const MAX = 2000;

function flush() {
  if (buf.length === 0) return;
  send({ type: "cf", items: buf });
  buf = [];
}

function emitCf(cf, tid) {
  buf.push({cf, tid});
  if (buf.length >= MAX) flush();
}

function getNearestSymbol(addr) {
  const m = Process.findModuleByAddress(addr);
  if (!m) return DebugSymbol.fromAddress(addr);

  let syms = symCache.get(m.name);
  if (!syms) {
    syms = m.enumerateSymbols()
      .filter(s => s.address && s.name)
      .sort((a, b) => a.address.compare(b.address));
    symCache.set(m.name, syms);
  }

  let lo = 0, hi = syms.length - 1, best = -1;
  while (lo <= hi) {
    const mid = (lo + hi) >> 1;
    const c = syms[mid].address.compare(addr);
    if (c <= 0) { best = mid; lo = mid + 1; }
    else { hi = mid - 1; }
  }
  if (best === -1) return `${m.name}!+${addr.sub(m.base)}`;

  const s = syms[best];
  const off = addr.sub(s.address);
  return `${m.name}!${s.name}+${off}`;
}

function startFollow(tidToFollow) {
  followed.add(tidToFollow);
  Stalker.follow(tidToFollow, {
    transform(iterator) {
      let insn;

      while ((insn = iterator.next()) !== null) {
        const mn = insn.mnemonic;
        if (mn === 'call' || mn.startsWith('j')) {
            const op0 = insn.operands[0];
            if (op0?.type === "reg") {
                const regName = op0.value;   
                const addr = insn.address;

                iterator.putCallout(ctx => {
                  const target = ptr(ctx[regName]);
                  const sym = getNearestSymbol(target);
                  const res = `${addr} ---> ${sym.toString()}`;
                  emitCf(res, Process.getCurrentThreadId());
                }); 
            } else if (op0?.type === "mem") {
                const v = op0.value;
                const baseName = v.base;
                const indexName = v.index;
                const scale = v.scale;
                const disp = v.disp;
                const addr = insn.address;

                iterator.putCallout(ctx => {
                  const base = ptr(baseName ? ctx[baseName] : 0);
                  const index = ptr(indexName ? ctx[indexName] : 0);
                  const target = ptr(base.add(index * scale).add(disp));
                  const sym = getNearestSymbol(target);
                  const res = `${addr} ---> ${sym.toString()}`;
                  emitCf(res, Process.getCurrentThreadId());
                }); 
            } else {
                const addr = insn.address;
                iterator.putCallout(() => {
                  const target = ptr(op0.value);
                  const sym = getNearestSymbol(target);
                  const res = `${addr} ---> ${sym.toString()}`;
                  emitCf(res, Process.getCurrentThreadId());
                }); 
            }
        }

        iterator.keep();
      }
    }
  });

  send({ type: "status", msg: `stalker_started tid: ${tidToFollow}` });
}

function stopFollow(tid) {
  if (!followed.has(tid)) return;
  Stalker.unfollow(tid);
  Stalker.flush();
  followed.delete(tid);
  send({ type: 'status', msg: 'unfollow', tid });
}

function shutdown() {
    const tids = Array.from(followed);
    for(const tid of tids) {
        stopFollow(tid);
    }
    Stalker.flush();
    Stalker.garbageCollect();

    Interceptor.detachAll();
    send({ type: 'done' });
}

Process.attachThreadObserver({
    onAdded(thread) {
        startFollow(thread.id);
    }
});

setInterval(flush, 50); 

rpc.exports = {
  cleanup() {
    shutdown();
    return true;
  }
}
"""

def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(
        description="Frida Stalker basic-block trace until entering a function address (host-side file I/O)."
    )
    
    p.add_argument("target", help="Path to target binary or PID")
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
        help="PID to attach to if --no-spawn is used",
    )
    p.add_argument(
        "--",
        dest="passthrough",
        nargs=argparse.REMAINDER,
        help="Arguments passed to target. Example: script.py ./bin 0x401080 -- arg1 arg2",
    )
    p.add_argument(
           "--env",
           default=None,
           help="Env file for target",
    )

    return p.parse_args()

def set_env(env_file):
    with open(env_file, 'r') as f:
        envs = f.read()

    envs_conc = list(filter(str.strip, filter(None, envs.split('\n'))))
    for s in envs_conc:
        [k, v] = s.split('=')

        os.environ[k] = v

def get_device(args: argparse.Namespace):
    if args.device == "local":
        return frida.get_local_device()
    if args.device == "usb":
        return frida.get_usb_device(timeout=5)
    if args.device == "remote":
        return frida.get_device_manager().add_remote_device(args.remote_host)
    raise ValueError("Invalid device type")

def write_traces(opened, out, cfs):
    for cf in cfs:
        tid = cf.get('tid', -1);
        if tid not in opened:
            opened[tid] = open(f"{out}-{tid}", 'w')
        opened[tid].write(f'{cf.get("cf", "NOT SEND")}\n')

def close_traces(opened):
    for f in opened.values():
        f.close()

def main() -> int:
    exitcode = 0
    args = parse_args()
    js_src = JS_TEMPLATE 
    done_evt = threading.Event()
    device = get_device(args)
    opened = dict()

    if args.env:
        set_env(args.env)

    def on_message(message, _):
        nonlocal done_evt, args
        if message["type"] == "send":
            payload = message["payload"]
            mtype = payload.get("type")

            if mtype == "cf":
                cfs = payload.get("items", None)
                if not cfs:
                    print("[-] invalid message from frida script")
                    return
                write_traces(opened, args.out, cfs)
            elif mtype == "status":
                print(f"[+] {payload.get('msg')}", flush=True)
            elif mtype == "done":
                print(f"[+] done", flush=True)
                done_evt.set()
            else:
                print(f"[?] {payload}", flush=True)
        else:
            print(message, flush=True)

    if args.pid:
        pid = args.target
        session = device.attach(pid)
    else:
        target_args = [args.target]
        if args.passthrough:
            rest = args.passthrough
            if rest and rest[0] == "--":
                rest = rest[1:]
            target_args += rest

        pid = device.spawn(target_args)
        session = device.attach(pid)

    script = session.create_script(js_src)
    script.on("message", on_message)
    script.load()

    if not args.pid:
        device.resume(pid)

    try:
        while True:
            time.sleep(50)
    finally:
        script.exports_sync.cleanup();
        device.kill(pid)
        close_traces(opened)
        return exitcode

if __name__ == "__main__":
    raise SystemExit(main())

