# Export all RVAs of a program.
# It has blacklists for noisy functions.
#
# Output is json file with array which contains RVAs as numbers.
#
# Useful when performing control flow analysis of 
# a specific program functionality using Frida.
# 
# author: LapTapk

#@category Export
#@menupath Tools.Export.All Function RVAs

import json

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
)

BLACKLIST_NAMESPACES_EXACT = set([
    "plt", "External", "EXTERNAL",
])

BLACKLIST_NAME_SUBSTRINGS = (
    "boost::",         # demangled
    "boost/",          # sometimes appears in paths/symbols
)

BLACKLIST_MANGLED_PREFIXES = (
    "_ZN5boost",       # Itanium C++ ABI mangling for boost::
)

BLACKLIST_NAMESPACE_SUBSTRINGS = (
    "boost",
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

rvas = []
it = fm.getFunctions(True)  # forward

while it.hasNext():
    fn = it.next()
    if is_blacklisted(fn):
        continue
    rva = fn.getEntryPoint().subtract(base)
    rvas.append(int(rva))

# Optional: deterministic, unique
rvas = sorted(set(rvas))

# ---------------- WRITE JSON ----------------

out = askFile("Save all function RVAs (JSON numbers)", "Save")
f = open(out.getAbsolutePath(), "w")
f.write(json.dumps(rvas))
f.close()

print("Exported functions:", len(rvas))
print("Saved to:", out.getAbsolutePath())
