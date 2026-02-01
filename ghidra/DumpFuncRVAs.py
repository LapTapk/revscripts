# DumpFuncRVAs.py
# ================
#
# Export all function RVAs from the current Ghidra program, while filtering out
# noisy/irrelevant symbols (e.g., libc and C++ stdlib helpers).
#
# The script writes a JSON file that maps module name -> list[int] (RVA values).
# It will *merge* into an existing JSON file if one is chosen, preserving other
# module keys already present. This makes it safe to aggregate multiple binaries
# in a single output file.
#
# Typical usage:
#  - Ghidra: Tools -> Export -> All Function RVAs
#   - Pick a JSON file to write or update.
#   - Use output with frida/gttrace for targeted control-flow analysis.
#
# Notes:
#   - Blacklist configuration is centralized below.
#
# author: LapTapk

#@category Export
#@menupath Tools.Export.All Function RVAs

import json
from pathlib import Path

fm = currentProgram.getFunctionManager()
base = currentProgram.getImageBase()

# ---------------- BLACKLIST CONFIG ----------------

BLACKLIST_NAMES = set([
    "malloc", "free", "calloc", "realloc",
    "memcpy", "memmove", "memset",
    "strlen", "strcmp", "strncmp",
    "strchr", "strrchr", "strstr",
    "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar",
    "atoi", "atol", "strtol", "strtoul",
    "exit", "_exit", "abort",
])

BLACKLIST_NAME_PREFIXES = (
    "__libc_",
    "__GI__",          # glibc internal
    "std::"
)

BLACKLIST_NAMESPACES_EXACT = set([
    "plt", "External", "EXTERNAL",
])

BLACKLIST_NAME_SUBSTRINGS = (
    "boost::",         # demangled
    "boost/",          # sometimes appears in paths/symbols,
)

BLACKLIST_MANGLED_PREFIXES = (
    "_ZN5boost",       # Itanium C++ ABI mangling for boost::
)

BLACKLIST_NAMESPACE_SUBSTRINGS = (
    "boost",
)

def is_blacklisted(func):
    """Return True when a function should be ignored in the dump."""
    if func is None:
        return True

    # Skip thunks (PLT stubs, import wrappers, etc.)
    try:
        if func.isThunk():
            return True
    except Exception:
        # Some function implementations may not expose isThunk safely.
        # If in doubt, keep the function (do not blacklist).
        return False

    name = func.getSymbol().getName(True) or ""

    if name in BLACKLIST_NAMES:
        return True

    for p in BLACKLIST_NAME_PREFIXES:
        if name.startswith(p):
            return True


    for p in BLACKLIST_MANGLED_PREFIXES:
        if name.startswith(p):
            return True

    for s in BLACKLIST_NAME_SUBSTRINGS:
        if s in name:
            return True

    ns = func.getParentNamespace()
    if ns is not None:
        nsname = ns.getName() or ""

        if nsname in BLACKLIST_NAMESPACES_EXACT:
            return True

        lns = nsname.lower()
        for s in BLACKLIST_NAMESPACE_SUBSTRINGS:
            if s in lns:
                return True

    return False

# ---------------- DUMP ALL FUNCTIONS ----------------

def collect_function_rvas():
    """Return a sorted, unique list of RVAs for non-blacklisted functions."""
    rvas = []
    it = fm.getFunctions(True)  # forward iterator

    while it.hasNext():
        fn = it.next()
        if is_blacklisted(fn):
            continue
        rva = fn.getEntryPoint().subtract(base)
        rvas.append(int(rva))

    # Deterministic, unique output for repeatable results.
    return sorted(set(rvas))

# ---------------- WRITE JSON ----------------
def load_existing_output(path):
    """Load existing JSON output or return an empty mapping."""
    if Path(path).exists():
        with open(path, "r") as f:
            return json.load(f)
    return {}


def write_output(path, module_name, rvas):
    """Merge the module's RVAs into the JSON output file."""
    prev_rvas = load_existing_output(path)
    prev_rvas[module_name] = rvas
    with open(path, "w") as f:
        f.write(json.dumps(prev_rvas))


rvas = collect_function_rvas()
out = askFile("Save all function RVAs (JSON numbers)", "Save")
absPath = out.getAbsolutePath()
mod = currentProgram.getName()
write_output(absPath, mod, rvas)

print("Exported functions:", len(rvas))
print("Saved to:", out.getAbsolutePath())
