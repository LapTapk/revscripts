"""Message datatypes and parsing helpers for the Frida agent protocol."""

from dataclasses import dataclass

@dataclass(frozen=True)
class CfItem:
    """Single control-flow edge captured by the agent.

    Attributes:
        frm: Source address (absolute).
        target: Destination address (absolute).
        tid: Thread id of the control-flow edge.
    """
    frm: int
    target: int
    tid: int

@dataclass(frozen=True)
class CfMessage:
    """Batch of control-flow items sent from the agent."""
    items: list[CfItem]

@dataclass(frozen=True)
class ModMessage:
    """Module load/unload event payload."""
    name: str
    start: int
    end: int
    path: str
    remove: bool

def decompose_cf_item(payload) -> CfItem | None:
    """Convert a CF payload dict into a CfItem.

    Returns None when the payload is missing required fields.
    """
    frm = payload.get("from")
    target = payload.get("target")
    tid = payload.get("tid")
    if not frm or not target or not tid:
        print("[-] invalid message when decomposing cf message")
        return None

    return CfItem(int(frm, 16), int(target, 16), tid)

def decompose_cf_mes(payload) -> CfMessage | None:
    """Convert a CF message payload into a CfMessage."""
    cfs = payload.get("items")
    if not cfs:
        return None

    items = list(filter(lambda x: x is not None, map(lambda cf: decompose_cf_item(cf), cfs))) 
    return CfMessage(items)

def decompose_mod_mes(payload) -> ModMessage | None:
    """Convert a module payload into a ModMessage."""
    name = payload.get("name");
    start = payload.get("start")
    end = payload.get("end");
    path = payload.get("path");
    remove = payload.get("remove");
    if not name or not start or not end or not path:
        print("[-] invalid message when decomposing mod message")
        return None

    start = int(start, 16)
    end = int(end, 16)

    return ModMessage(name, start, end, path, remove)
