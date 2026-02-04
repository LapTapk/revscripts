import re
from typing import Dict, Tuple, Any
from pathlib import Path
import json

def _safe_filename(s: str) -> str:
    # used only on host for file naming; agent already sanitizes conn_id but keep safe
    return re.sub(r"[^a-zA-Z0-9_.:@=\-+]", "_", s)

class OutputManager:
    def __init__(self, out_dir: Path):
        self.out_dir = out_dir
        self.out_dir.mkdir(parents=True, exist_ok=True)
        self.events_path = self.out_dir / "events.jsonl"
        self.events_f = self.events_path.open("ab", buffering=0)
        self.files: Dict[Tuple[str, str], Any] = {}  # (conn_id, direction) -> file object

    def _open_stream(self, conn_id: str, direction: str):
        key = (conn_id, direction)
        if key in self.files:
            return self.files[key]
        fname = _safe_filename(conn_id) + (".in.bin" if direction == "in" else ".out.bin")
        fpath = self.out_dir / fname
        f = fpath.open("ab", buffering=0)
        self.files[key] = f
        return f

    def write_event(self, ev: dict):
        line = (json.dumps(ev, ensure_ascii=False) + "\n").encode("utf-8")
        self.events_f.write(line)

    def write_data(self, conn_id: str, direction: str, blob: bytes):
        f = self._open_stream(conn_id, direction)
        f.write(blob)

    def close_conn(self, conn_id: str):
        for direction in ("in", "out"):
            key = (conn_id, direction)
            f = self.files.pop(key, None)
            if f is not None:
                try:
                    f.flush()
                    f.close()
                except Exception:
                    pass

    def close_all(self):
        for f in list(self.files.values()):
            try:
                f.flush()
                f.close()
            except Exception:
                pass
        self.files.clear()
        try:
            self.events_f.flush()
            self.events_f.close()
        except Exception:
            pass

