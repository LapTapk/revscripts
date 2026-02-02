"""Trace formatting and file management for control-flow edges."""

from pathlib import Path
from typing import Optional
from lib.messages import CfItem
from lib.mod_lookup import ModLookup
from lib.dbgsym import DebugSymbol

class OutputManager:
    """Manage trace output files and format call edges.

    Each thread id (TID) receives its own trace file, created on demand.
    """
    def __init__(self, wl: Optional[dict[str, list[int]]], mods: ModLookup, dbg: DebugSymbol, out: str):
        self.opened = {}
        self.wl = wl
        self.mods = mods
        self.dbg = dbg

        out_path = Path(out);
        out_path.mkdir(exist_ok=True, parents=True);
            
        self.out = out

    def _is_whitelisted(self, mod_addr):
        """Check whether a module RVA is in the whitelist."""
        if not self.wl:
            return True

        if mod_addr.mod not in self.wl:
            return False

        wl_addrs = self.wl[mod_addr.mod]
        if mod_addr.rva not in wl_addrs:
            return False

        return True

    def _prettify_addr(self, mod_addr):
        """Render a module address as a symbol name or RVA string."""
        res = self.dbg.resolve(mod_addr.mod, mod_addr.rva)
        if res:
            (_, _, func, _) = res
            if func:
                return f'{mod_addr.mod}!{func.name}!{mod_addr.rva}'

        return f'{mod_addr.mod}!{hex(mod_addr.rva)}'


    def write(self, cfs: list[CfItem]):
        """Write resolved call edges to per-thread trace files."""
        for cf in cfs:
            frm_mod_addr = self.mods.lookup(cf.frm)
            target_mod_addr = self.mods.lookup(cf.target)

            if not frm_mod_addr or not target_mod_addr or not self._is_whitelisted(target_mod_addr):
                continue

            frm_pretty = self._prettify_addr(frm_mod_addr)
            target_pretty = self._prettify_addr(target_mod_addr)

            tid = cf.tid
            if tid not in self.opened:
                self.opened[tid] = open(f"{self.out}/trace-{tid}", 'w', buffering=1, encoding="utf-8", errors="replace")

            res = f'{frm_pretty} ---> {target_pretty}\n'
            self.opened[tid].write(res)


    def close(self):
        """Close any opened trace files."""
        for f in self.opened.values():
            f.close()
