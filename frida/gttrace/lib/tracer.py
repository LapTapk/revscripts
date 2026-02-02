"""Tracer orchestration for gttrace.

This module loads the Frida agent, streams messages, and writes trace output
using helper components that manage module lookups and symbol resolution.
"""

import os
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

@dataclass(frozen=True)
class TracerConf:
    """Configuration bundle for a tracing session.

    Attributes:
        device: Frida device used to attach/spawn targets.
        wl: Optional whitelist of module RVAs to include in output.
        out: Output file prefix for per-thread traces.
        env: Optional environment overrides for spawned targets.
        attach: When True, attach to a PID instead of spawning.
        target: Path to binary or PID string depending on attach.
        args: Extra arguments passed to the spawned target.
        entry: Optional module+RVA entrypoint for coverage start/stop.
    """
    device: Any
    wl: Optional[dict[str, list[int]]]
    env: Optional[dict[str, str]]
    attach: bool
    target: str
    args: list[str]
    dbg: DebugSymbol
    mods: ModLookup
    outman: OutputManager
    entry: Optional[ModRVA]

class Tracer:
    """Run Frida Stalker with lifecycle management and trace handling."""
    def __init__(self, conf: TracerConf):
        self.conf = conf
        # TODO
        with open(JS_TEMPLATE_PATH, 'r') as f:
            script_src = f.read()

        if conf.entry:
            self.script_src = script_src % {"entry_mod": conf.entry.mod, "entry_rva": conf.entry.rva }
        else:
            self.script_src = script_src % {"entry_mod": 'undefined', "entry_rva": 'undefined' }

        self.pid = None
        self.session = None
        self.script = None

    def _set_env(self):
        """Apply environment overrides to the current process.

        These variables affect the target process when it is spawned.
        """
        assert self.conf.env is not None, "[!!! dev exception] tracers envs are None"

        for (k, v) in self.conf.env.items():
            os.environ[k] = v

    def _on_message(self, message):
        """Handle messages emitted by the Frida script.

        The agent sends control-flow batches, module load/unload events, and
        status messages. Each type is routed to the appropriate handler.
        """
        if message["type"] == "send":
            payload = message["payload"]
            mtype = payload.get("type")

            if mtype == "cf":
                cfs = decompose_cf_mes(payload)
                if not cfs:
                    return
                
                self.traces.write(cfs.items)
            elif mtype == "mod":
                if not self.conf.wl:
                    return

                mes = decompose_mod_mes(payload)
                if not mes:
                    return

                if mes.remove:
                    self.mods.rem(mes.start, mes.end)
                    self.dbg.rem_mod(mes.name)
                else:
                    self.mods.add(mes.start, mes.end, mes.name)
                    self.dbg.add_mod(mes.name, mes.path)
            elif mtype == "status":
                print(f"[+] {payload.get('msg')}", flush=True)
            elif mtype == "done":
                print(f"[+] done", flush=True)
            else:
                print(f"[?] {payload}", flush=True)
        else:
            print(message, flush=True)

    def start(self):
        """Attach or spawn the target and start the tracing script."""
        if self.conf.env:
            self._set_env()

        if self.conf.attach:
            self.pid = int(self.conf.target)
            self.session = self.conf.device.attach(self.pid)
        else:
            target_args = [self.conf.target]
            if self.conf.args:
                rest = self.conf.args
                if rest and rest[0] == "--":
                    rest = rest[1:]
                target_args += rest

            self.pid = self.conf.device.spawn(target_args)
            self.session = self.conf.device.attach(self.pid)

        def on_message(message, _):
            self._on_message(message)

        self.script = self.session.create_script(self.script_src)
        self.script.on("message", on_message)
        self.script.load()

        if not self.conf.attach:
            self.conf.device.resume(self.pid)

    def stop(self):
        """Cleanup Frida state and flush trace files."""
        if not self.session or not self.pid or not self.script:
            return

        self.script.exports_sync.cleanup();

        if self.conf.attach:
            self.script.unload()
            self.session.detach()
        else:
            self.conf.device.kill(self.pid)

        self.traces.close()
