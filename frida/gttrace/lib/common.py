from dataclasses import dataclass

@dataclass(frozen=True)
class ModRVA:
    mod: str
    rva: int

