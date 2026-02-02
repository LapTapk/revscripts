"""ELF/DWARF symbol resolution for gttrace output."""

from elftools.elf.elffile import ELFFile
from elftools.elf.constants import SHN_INDICES
from pathlib import Path
from bisect import bisect_right
from dataclasses import dataclass

@dataclass(frozen=True)
class FuncSym:
    """Resolved function symbol with a virtual address range."""
    start: int
    end: int
    name: str

@dataclass(frozen=True)
class SrcLoc:
    """Source location resolved from DWARF line tables."""
    file: str
    line: int
    col: int

def _image_base_vaddr(elf: ELFFile) -> int:
    """Return the lowest PT_LOAD p_vaddr, used as the image base."""
    bases = []
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_LOAD":
            bases.append(int(seg.header.p_vaddr))
    return min(bases) if bases else 0


class ElfResolver:
    """Resolve function names and optional source locations from RVAs.

    Addressing model:
        * Input is an RVA relative to the runtime load base.
        * We map RVA -> ELF virtual address used by symbols/line tables:
              vaddr = rva + image_base
          where image_base = min PT_LOAD p_vaddr.
        * For ET_DYN shared libs, image_base is typically 0, so vaddr ~= rva.
          For ET_EXEC non-PIE binaries, image_base is often 0x400000.
    """

    def __init__(self, path: str, build_dwarf_index: bool = True):
        self.path = path
        with open(path, "rb") as f:
            self._elf = ELFFile(f)
            self._etype = self._elf.header["e_type"]
            self._img_base = _image_base_vaddr(self._elf)

            self._funcs = self._build_func_index(self._elf)

            # DWARF line table index (optional; can be heavy for large binaries)
            self._line_addrs = []
            self._line_locs = []
            if build_dwarf_index and self._elf.has_dwarf_info():
                self._build_line_index(self._elf)

    def rva_to_vaddr(self, rva: int) -> int:
        """Translate an RVA to the ELF virtual address space."""
        return int(rva) + int(self._img_base)

    @staticmethod
    def _iter_symbol_sections(elf: ELFFile):
        """Yield relevant symbol sections from the ELF."""
        symtab = elf.get_section_by_name(".symtab")
        if symtab is not None:
            yield symtab
        dynsym = elf.get_section_by_name(".dynsym")
        if dynsym is not None:
            yield dynsym

    def _build_func_index(self, elf: ELFFile):
        """Build a sorted list of function symbol ranges."""
        items = []

        for sec in self._iter_symbol_sections(elf):
            for sym in sec.iter_symbols():
                shndx = sym["st_shndx"]
                if shndx in (SHN_INDICES.SHN_UNDEF, "SHN_UNDEF"):
                    continue

                st_type = sym["st_info"]["type"]
                if st_type != "STT_FUNC":
                    continue

                name = sym.name
                if not name:
                    continue

                start = int(sym["st_value"])
                if start == 0:
                    continue

                size = int(sym["st_size"])
                end = start + size if size > 0 else 0  # fill later if 0
                items.append((start, end, name))

        if not items:
            return []

        # Sort and fill missing ends using next symbol start
        items.sort(key=lambda t: t[0])

        funcs = []
        for i, (start, end, name) in enumerate(items):
            if end == 0:
                # If size missing, approximate end by next start
                if i + 1 < len(items):
                    end = items[i + 1][0]
                else:
                    end = start + 1  # last symbol, minimal range
            if end <= start:
                end = start + 1
            funcs.append(FuncSym(start=start, end=end, name=name))

        return funcs

    def _build_line_index(self, elf: ELFFile) -> None:
        """Index DWARF line table entries for RVA-to-source lookup."""
        dwarf = elf.get_dwarf_info()
        addrs = []
        locs = []

        for cu in dwarf.iter_CUs():
            lp = dwarf.line_program_for_CU(cu)
            if lp is None:
                continue

            # file name table for CU
            # file_entry.name is bytes; directory is in lp.header['include_directory']
            include_dirs = [d.decode("utf-8", "replace") for d in lp.header.get("include_directory", [])]
            file_entries = lp.header.get("file_entry", [])

            def file_name(file_idx: int) -> str:
                if file_idx == 0 or file_idx > len(file_entries):
                    return "??"
                fe = file_entries[file_idx - 1]
                fn = fe.name.decode("utf-8", "replace")
                dir_idx = int(getattr(fe, "dir_index", 0))  # 0 means current compilation dir
                if dir_idx == 0 or dir_idx > len(include_dirs):
                    return fn
                return include_dirs[dir_idx - 1].rstrip("/") + "/" + fn

            state = None
            for entry in lp.get_entries():
                if entry.state is None:
                    continue
                state = entry.state
                if state.end_sequence:
                    continue
                a = int(state.address)
                addrs.append(a)
                locs.append(SrcLoc(
                    file=file_name(int(state.file)),
                    line=int(state.line or 0),
                    col=int(state.column or 0),
                ))

        # Sort by address; keep stable mapping
        if addrs:
            paired = sorted(zip(addrs, locs), key=lambda t: t[0])
            self._line_addrs = [a for a, _ in paired]
            self._line_locs = [l for _, l in paired]

    def resolve_func_by_rva(self, rva: int):
        """Resolve a function symbol by RVA."""
        if not self._funcs:
            return None
        vaddr = self.rva_to_vaddr(rva)
        starts = [f.start for f in self._funcs]  # could cache if you want max speed
        i = bisect_right(starts, vaddr) - 1
        if i < 0:
            return None
        f = self._funcs[i]
        if f.start <= vaddr < f.end:
            return f
        return None

    def resolve_line_by_rva(self, rva: int):
        """Resolve a source line by RVA."""
        if not self._line_addrs:
            return None
        vaddr = self.rva_to_vaddr(rva)
        i = bisect_right(self._line_addrs, vaddr) - 1
        if i < 0:
            return None
        return self._line_locs[i]

    def resolve(self, rva: int):
        """Resolve both function and source line metadata by RVA."""
        return self.resolve_func_by_rva(rva), self.resolve_line_by_rva(rva)


class DebugSymbol:
    """Track loaded modules and resolve RVAs to symbols/lines.

    Modules are registered by name and filesystem path, enabling lookups
    from (module, rva) tuples during trace formatting.
    """
    def __init__(self):
        self._mods = {}

    def add_mod(self, name: str, elf_path: str, *, build_dwarf_index: bool = True):
        """Register an ELF module for symbol resolution."""
        if not Path(elf_path).exists():
            return
        self._mods[name] = ElfResolver(elf_path, build_dwarf_index=build_dwarf_index)

    def rem_mod(self, name: str):
        """Remove a module from the resolver cache."""
        self._mods.pop(name, None)

    def resolve(self, module_name: str, rva: int):
        """Resolve symbols for a module/RVA pair."""
        r = self._mods.get(module_name)
        if r is None:
            return None
        func, loc = r.resolve(rva)
        return module_name, rva, func, loc
