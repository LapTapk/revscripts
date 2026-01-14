# Export RVAs of a function tree which forms
# out of function under the cursor.
# It has blacklists of noisy functions.
#
# Output is json file with array which contains RVAs as numbers.
#
# Useful when performing control flow analysis of 
# a specific program functionality using Frida
# 
# author: LapTapk

#@category Export
#@menupath Tools.Export.Call Tree RVAs 

import json

fm = currentProgram.getFunctionManager()
rm = currentProgram.getReferenceManager()
base = currentProgram.getImageBase()

# ---------------- BLACKLIST CONFIG ----------------

# Exact names (typical libc / common runtime)
BLACKLIST_NAMES = set([
    "malloc", "free", "calloc", "realloc",
    "memcpy", "memmove", "memset",
    "strlen", "strcmp", "strncmp",
    "strchr", "strrchr", "strstr",
    "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar",
    "atoi", "atol", "strtol", "strtoul",
    "exit", "_exit", "abort",
])

# Prefixes (libc internals, etc.)
BLACKLIST_NAME_PREFIXES = (
    "__libc_",
    "__GI__",          # glibc internal
)

# Skip whole namespaces (Ghidra namespaces)
BLACKLIST_NAMESPACES_EXACT = set([
    "plt", "External", "EXTERNAL",
])

# Boost-related filters (demangled, mangled, namespace)
BLACKLIST_NAME_SUBSTRINGS = (
    "boost::",         # demangled
    "boost/",          # sometimes appears in paths/symbols
)

BLACKLIST_MANGLED_PREFIXES = (
    "_ZN5boost",       # Itanium C++ ABI mangling for boost::
)

BLACKLIST_NAMESPACE_SUBSTRINGS = (
    "boost",           # namespace contains boost
)

def is_blacklisted(func):
    if func is None:
        return True

    # Skip thunks (PLT stubs, import wrappers, etc.)
    try:
        if func.isThunk():
            return True
    except:
        pass

    name = func.getName() or ""

    # Exact name blacklist
    if name in BLACKLIST_NAMES:
        return True

    # Prefix blacklist
    for p in BLACKLIST_NAME_PREFIXES:
        if name.startswith(p):
            return True

    # Boost mangled prefix blacklist
    for p in BLACKLIST_MANGLED_PREFIXES:
        if name.startswith(p):
            return True

    # Substring blacklist (demangled boost etc.)
    for s in BLACKLIST_NAME_SUBSTRINGS:
        if s in name:
            return True

    # Namespace blacklist
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

# ---------------- ROOT SELECTION ----------------

root = fm.getFunctionContaining(currentAddress)
if root is None:
    raise Exception("Cursor is not inside a function")

if is_blacklisted(root):
    raise Exception("Root function is blacklisted: " + root.getName())

# ---------------- CALL GRAPH WALK ----------------

visited = set()   # set of entrypoint Address
rvas = []         # list of int RVAs (decimal)

def walk(func):
    entry = func.getEntryPoint()
    if entry in visited:
        return
    visited.add(entry)

    # Record RVA as JSON number (decimal)
    rvas.append(int(entry.subtract(base)))

    # Iterate all addresses in the function body; collect CALL refs
    ait = func.getBody().getAddresses(True)
    while ait.hasNext():
        a = ait.next()
        refs = rm.getReferencesFrom(a)
        for ref in refs:
            if not ref.getReferenceType().isCall():
                continue

            callee = fm.getFunctionContaining(ref.getToAddress())
            if callee is None:
                continue

            if is_blacklisted(callee):
                continue

            walk(callee)

walk(root)

# Optional: make output deterministic
rvas = sorted(set(rvas))

# ---------------- WRITE JSON ----------------

out = askFile("Save call-tree RVAs (JSON numbers)", "Save")
f = open(out.getAbsolutePath(), "w")
f.write(json.dumps(rvas))
f.close()

print("Root:", root.getName(), "@", root.getEntryPoint())
print("Exported functions:", len(rvas))
print("Saved to:", out.getAbsolutePath())
