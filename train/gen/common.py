"""Shared snippet registry for the ratel synthetic corpus generator.

Every snippet is a C fragment that defines `int @F(int argc, char **argv)`
(plus optional helpers named `@F_<something>`). `@F` is replaced by a unique
identifier per sample, so snippets can be freely combined into one program.

Snippets are only ever COMPILED. Nothing in this package runs a generated
binary.
"""
from dataclasses import dataclass, field

CAPS = ("anti_debug", "anti_vm", "obfuscation", "packed", "crypto", "network")


@dataclass
class Snip:
    id: str                 # unique variant id, e.g. antidbg.linux.ptrace_traceme.v1
    family: str             # group id for leave-family-out CV, e.g. antidbg.ptrace
    labels: dict            # caps this snippet makes statically observable -> 1
    plat: str               # 'linux' | 'windows' | 'any'
    code: str               # C source using @F placeholders
    inc: tuple = ()         # headers
    libs: tuple = ()        # windows import libs (-l...) / linux libs
    arch: str = None        # None | 'x86_64' | 'x86'
    cflags: tuple = ()
    tags: tuple = ()        # mutual-exclusion tags (e.g. 'wininet' vs 'winhttp')
    kind: str = "tech"      # 'tech' | 'benign' | 'hardneg'

    def cap_list(self):
        return [c for c in CAPS if self.labels.get(c)]


REGISTRY: list = []


def T(id, family, labels, plat, code, **kw):
    """Register a technique snippet. `labels` may be a str (single cap) or dict."""
    if isinstance(labels, str):
        labels = {labels: 1}
    elif isinstance(labels, (list, tuple)):
        labels = {c: 1 for c in labels}
    for k in labels:
        assert k in CAPS, k
    s = Snip(id=id, family=family, labels=labels, plat=plat, code=code, **kw)
    REGISTRY.append(s)
    return s


def B(id, plat, code, **kw):
    """Register a benign filler snippet."""
    return T("benign." + id, "benign." + id.split(".")[0], {}, plat, code, kind="benign", **kw)


def H(id, plat, code, **kw):
    """Register a hard negative: benign code that resembles a technique. All labels 0."""
    return T("hardneg." + id, "hardneg." + id.split(".")[0], {}, plat, code, kind="hardneg", **kw)


# Include ordering: windows headers have ordering constraints.
INCLUDE_ORDER = [
    "winsock2.h", "ws2tcpip.h", "windows.h", "winternl.h", "intrin.h",
    "tlhelp32.h", "iphlpapi.h", "wininet.h", "winhttp.h", "urlmon.h",
    "windns.h", "bcrypt.h", "wincrypt.h", "shlobj.h", "psapi.h",
]


def order_includes(incs):
    incs = list(dict.fromkeys(incs))
    def key(h):
        return (0, INCLUDE_ORDER.index(h)) if h in INCLUDE_ORDER else (1, h)
    # windows-specific must come after the windows base headers; std headers first is fine
    std = [h for h in incs if h not in INCLUDE_ORDER]
    win = sorted([h for h in incs if h in INCLUDE_ORDER], key=key)
    return sorted(std) + win


def c_bytes(data, per_line=20):
    """Render bytes as a C initializer body."""
    out = []
    for i in range(0, len(data), per_line):
        out.append(",".join(str(b) for b in data[i:i + per_line]))
    return ",\n".join(out)


def c_str(s):
    """Escape a python str/bytes as a C string literal."""
    if isinstance(s, str):
        s = s.encode()
    r = []
    for b in s:
        if b == 0x5c:
            r.append("\\\\")
        elif b == 0x22:
            r.append('\\"')
        elif 32 <= b < 127 and b != 0x3f:  # avoid ?? trigraphs
            r.append(chr(b))
        else:
            r.append("\\%03o" % b)
    return '"' + "".join(r) + '"'
