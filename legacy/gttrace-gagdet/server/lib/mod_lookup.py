"""Module range indexing for address-to-module resolution."""

from bisect import bisect_left, bisect_right
from dataclasses import dataclass

@dataclass(frozen=True)
class ModRVA:
    """Identify an address by module name and relative virtual address (RVA)."""
    mod: str
    rva: int

class ModLookup:
    """Interval map for mapping absolute addresses to module RVAs.

    The lookup table keeps parallel sorted lists for module start/end
    addresses, enabling O(log n) lookups via bisect.
    """
    def __init__(self):
        self.starts = []
        self.ends = []
        self.names = []

    def add(self, start: int, end: int, name: str):
        """Register a new module range by address.

        Raises:
            ValueError: If the new range overlaps existing ranges.
        """
        assert start < end
        i = bisect_left(self.starts, start)

        if i > 0 and start < self.ends[i-1]:
            raise ValueError("overlaps previous interval")

        if i < len(self.starts) and end > self.starts[i]:
            raise ValueError("overlaps next interval")

        self.starts.insert(i, start)
        self.ends.insert(i, end)
        self.names.insert(i, name)

    def rem(self, start: int, end: int):
        """Remove a module range if it matches exactly."""
        i = bisect_left(self.starts, start)
        if i >= len(self.starts) or self.starts[i] != start or self.ends[i] != end:
            return False
        self.starts.pop(i); self.ends.pop(i); self.names.pop(i)
        return True

    def lookup(self, addr: int):
        """Lookup an address and return a ModRVA if it falls within a module."""
        i = bisect_right(self.starts, addr) - 1
        if i >= 0 and addr < self.ends[i]:
            rva = addr - self.starts[i]
            return ModRVA(self.names[i], rva)
        return None
