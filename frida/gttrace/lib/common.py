"""Shared value objects for gttrace."""

from dataclasses import dataclass

@dataclass(frozen=True)
class ModRVA:
    """Identify an address by module name and relative virtual address (RVA)."""
    mod: str
    rva: int
