"""Tracer orchestration for gttrace.

This module loads the Frida agent, streams messages, and writes trace output
using helper components that manage module lookups and symbol resolution.
"""

import os
import socket
import json
import sys
from lib.mod_lookup import ModLookup
from lib.dbgsym import DebugSymbol
from lib.outman import OutputManager
from lib.common import ModRVA
from dataclasses import dataclass
from lib.messages import *
from typing import Any, Optional
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent.parent
JS_TEMPLATE_PATH = f'{SCRIPT_DIR}/js/agent.js'

class Server:
    """Run Frida Stalker with lifecycle management and trace handling."""
    def __init__(self, wl: Optional[dict[str, list[int]]], address: str, out: str, bufsize: int = 1000):
        self.wl = wl
        self.address = address
        self.out = out
        self.outmans: dict[int, OutputManager] = {} 
        self.bufsize = bufsize

    def _get_outman(self, pid):
        if pid not in self.outmans:
            mods = ModLookup()
            dbg = DebugSymbol()
            outman = OutputManager(self.wl, mods, dbg, self.out)
            self.outmans[pid] = outman
        return self.outmans[pid]

    def _on_message(self, message):
        """Handle messages emitted by the Frida script.

        The agent sends control-flow batches, module load/unload events, and
        status messages. Each type is routed to the appropriate handler.
        """
        if message["type"] == "send":
            payload = message["payload"]
            mtype = payload.get("type")

            if mtype == "cf":
                pid = payload.get("pid")
                outman = self._get_outman(pid)
                cfs = decompose_cf_mes(payload)
                if not cfs:
                    return
                
                outman.write(cfs.items)
            elif mtype == "mod":
                pid = payload.get("pid")
                outman = self._get_outman(pid)

                mes = decompose_mod_mes(payload)
                if not mes:
                    return

                if mes.remove:
                    outman.mods.rem(mes.start, mes.end)
                    outman.dbg.rem_mod(mes.name)
                    print(f"[+] removed mod {mes.name} pid: {pid}")
                else:
                    outman.mods.add(mes.start, mes.end, mes.name)
                    outman.dbg.add_mod(mes.name, mes.path)
                    print(f"[+] added new mod {mes.name} pid: {pid}")
            elif mtype == "status":
                print(f"[+] {payload.get('msg')}", flush=True)
            elif mtype == "done":
                print(f"[+] done", flush=True)
            else:
                print(f"[?] {payload}", flush=True)
        else:
            print(message, flush=True)

    def serve(self) -> None:
        # Ensure old socket file is removed
        try:
            os.unlink(self.address)
        except FileNotFoundError:
            pass

        s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
        s.bind(self.address)

        # Optional: restrict access
        os.chmod(self.address, 0o666)

        print(f"listening on {self.address}", file=sys.stderr)

        try:
            while True:
                data, _ = s.recvfrom(self.bufsize)
                if not data:
                    continue

                # agent sends JSON + "\n"
                raw = data.decode("utf-8", errors="replace").strip()
                splitted = raw.split('\n')

                for j in splitted:
                    try:
                        obj: dict[str, Any] = json.loads(j)
                        self._on_message(obj) 
                    except json.JSONDecodeError:
                        print("JSON decode error");
                        print(raw);
                        return 
        finally:
            s.close()
            try:
                os.unlink(self.address)
            except FileNotFoundError:
                pass
    
    
