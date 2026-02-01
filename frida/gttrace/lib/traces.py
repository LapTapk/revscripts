from dataclasses import dataclass
from lib.messages import CfItem
from lib.mod_lookup import ModLookup
from lib.dbgsym import DebugSymbol

class Traces:
    def __init__(self, wl: dict[str, list[int]], mods: ModLookup, dbg: DebugSymbol, out: str):
        self.opened = {}
        self.wl = wl
        self.mods = mods
        self.out = out
        self.dbg = dbg

    def _is_whitelisted(self, mod_addr):
        if not self.wl:
            return True

        if mod_addr.mod not in self.wl:
            return False

        wl_addrs = self.wl[mod_addr.mod]
        if mod_addr.rva not in wl_addrs:
            return False

        return True

    def _prettify_addr(self, mod_addr):
        res = self.dbg.resolve(mod_addr.mod, mod_addr.rva)
        if res:
            (_, _, func, _) = res
            if func:
                return f'{mod_addr.mod}!{func.name}'

        return f'{mod_addr.mod}!{hex(mod_addr.rva)}'


    def write(self, cfs: list[CfItem]):
        for cf in cfs:
            frm_mod_addr = self.mods.lookup(cf.frm)
            target_mod_addr = self.mods.lookup(cf.target)

            if not frm_mod_addr or not target_mod_addr or not self._is_whitelisted(target_mod_addr):
                continue

            frm_pretty = self._prettify_addr(frm_mod_addr)
            target_pretty = self._prettify_addr(target_mod_addr)

            tid = cf.tid
            if tid not in self.opened:
                self.opened[tid] = open(f"{self.out}-{tid}", 'w', buffering=1, encoding="utf-8", errors="replace")

            res = f'{frm_pretty} ---> {target_pretty}\n'
            self.opened[tid].write(res)


    def close(self):
        for f in self.opened.values():
            f.close()
