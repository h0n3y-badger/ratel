"""Obfuscation technique variants. Most are generated per sample from an RNG so
keys, strings and control-flow shapes differ between samples."""
import base64
from common import T, c_bytes, c_str

OB = "obfuscation"

# Strings the obfuscated code decodes. Deliberately NOT network-related
# (no URLs/hosts) so the network label stays clean.
POOL = [
    "/etc/passwd", "/bin/sh", "cmd.exe /c whoami", "kernel32.dll", "ntdll.dll",
    "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", "~/.bashrc", "crontab -l",
    "config.dat", "/tmp/.cache_session", "%APPDATA%\\svchost.exe", "schtasks /create /sc onlogon",
    "powershell -nop -w hidden -enc", "/etc/shadow", "id_rsa", "wallet.dat", "Login Data",
    "/var/log/auth.log", "vssadmin delete shadows /all", "HKCU\\Software\\Classes", "rundll32.exe",
    ".ssh/authorized_keys", "/proc/self/exe", "LD_LIBRARY_PATH", "user32.dll", "advapi32.dll",
    "libc.so.6", "/dev/shm/.x", "persist", "secret_token", "license_key", "MainWindowClass",
    "C:\\ProgramData\\updater", "systemctl --user enable", "/etc/rc.local", "bcdedit /set",
]

_SINK = r'''
static __attribute__((noinline)) int @F_use(const char *s) {
    volatile size_t n = strlen(s);
    FILE *f = fopen(s, "r");
    if (f) fclose(f);
    return (int)n;
}'''


def _pick(rng, k):
    return rng.sample(POOL, k)


def _xor1(rng):
    strs = _pick(rng, rng.randint(2, 5))
    key = rng.randint(1, 255)
    parts, calls = [], []
    for i, s in enumerate(strs):
        enc = bytes(b ^ key for b in s.encode()) + bytes([key])  # NUL ^ key terminator
        parts.append(f"static volatile unsigned char @F_s{i}[] = {{{c_bytes(enc)}}};")
        calls.append(f"r += @F_dec(@F_s{i}, sizeof @F_s{i}, buf); r += @F_use(buf);")
    return "\n".join(parts) + _SINK + r'''
static __attribute__((noinline)) int @F_dec(volatile unsigned char *in, int n, char *out) {
    for (int i = 0; i < n; i++) out[i] = (char)(in[i] ^ 0x%02X);
    return 0;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[256]; int r = 0;
    %s
    return r;
}''' % (key, "\n    ".join(calls))


def _xorN(rng):
    strs = _pick(rng, rng.randint(2, 5))
    klen = rng.randint(3, 16)
    key = bytes(rng.randint(0, 255) for _ in range(klen))
    parts, calls = [], []
    for i, s in enumerate(strs):
        raw = s.encode() + b"\0"
        enc = bytes(b ^ key[j % klen] for j, b in enumerate(raw))
        parts.append(f"static volatile unsigned char @F_s{i}[] = {{{c_bytes(enc)}}};")
        calls.append(f"@F_dec(@F_s{i}, sizeof @F_s{i}, buf); r += @F_use(buf);")
    return "\n".join(parts) + f"\nstatic const unsigned char @F_k[{klen}] = {{{c_bytes(key)}}};" + _SINK + r'''
static void @F_dec(volatile unsigned char *in, unsigned n, char *out) {
    for (unsigned i = 0; i < n; i++) out[i] = (char)(in[i] ^ @F_k[i %% sizeof @F_k]);
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[256]; int r = 0;
    %s
    return r;
}''' % "\n    ".join(calls)


def _stack(rng):
    strs = _pick(rng, rng.randint(1, 3))
    body = []
    for i, s in enumerate(strs):
        body.append(f"volatile char s{i}[{len(s) + 1}];")
        order = list(range(len(s)))
        if rng.random() < 0.5:
            rng.shuffle(order)
        for j in order:
            ch = s[j]
            lit = f"'{ch}'" if ch.isalnum() else str(ord(ch))
            body.append(f"s{i}[{j}] = {lit};")
        body.append(f"s{i}[{len(s)}] = 0; r += @F_use((const char *)s{i});")
    return _SINK + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    int r = 0;
    %s
    return r;
}''' % "\n    ".join(body)


def _addroll(rng):
    strs = _pick(rng, rng.randint(2, 4))
    k, m = rng.randint(1, 255), rng.randint(1, 31)
    parts, calls = [], []
    for i, s in enumerate(strs):
        raw = s.encode() + b"\0"
        enc = bytes((b + k + j * m) & 0xFF for j, b in enumerate(raw))
        parts.append(f"static volatile unsigned char @F_s{i}[] = {{{c_bytes(enc)}}};")
        calls.append(f"for (unsigned j = 0; j < sizeof @F_s{i}; j++) buf[j] = (char)(@F_s{i}[j] - {k} - j * {m});\n    r += @F_use(buf);")
    return "\n".join(parts) + _SINK + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[256]; int r = 0;
    %s
    return r;
}''' % "\n    ".join(calls)


def _split(rng):
    strs = _pick(rng, rng.randint(1, 3))
    body = []
    for s in strs:
        frags, i = [], 0
        while i < len(s):
            n = rng.randint(1, 3)
            frags.append(s[i:i + n]); i += n
        body.append("buf[0] = 0;")
        for f in frags:
            body.append(f"strcat(buf, {c_str(f)});")
        body.append("r += @F_use(buf);")
    return _SINK + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[256]; int r = 0;
    %s
    return r;
}''' % "\n    ".join(body)


def _b64(rng):
    strs = _pick(rng, rng.randint(2, 4))
    alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    custom = rng.random() < 0.4
    if custom:  # shuffled alphabet, common in malware
        a = list(alpha); rng.shuffle(a); alpha2 = "".join(a)
        tr = str.maketrans(alpha, alpha2)
    lits = []
    for s in strs:
        e = base64.b64encode(s.encode()).decode()
        if custom:
            e = e.translate(tr)
        lits.append(c_str(e))
    calls = "\n    ".join(f"@F_b64d({l}, buf); r += @F_use(buf);" for l in lits)
    return _SINK + r'''
static const char @F_al[] = %s;
static int @F_idx(char c) { for (int i = 0; i < 64; i++) if (@F_al[i] == c) return i; return -1; }
static void @F_b64d(const char *in, char *out) {
    unsigned v = 0; int bits = 0, o = 0;
    for (; *in && *in != '='; in++) {
        int d = @F_idx(*in); if (d < 0) continue;
        v = (v << 6) | (unsigned)d; bits += 6;
        if (bits >= 8) { bits -= 8; out[o++] = (char)((v >> bits) & 0xFF); }
    }
    out[o] = 0;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[256]; int r = 0;
    %s
    return r;
}''' % (c_str(alpha2 if custom else alpha), calls)


def _subst(rng):
    strs = _pick(rng, rng.randint(2, 4))
    perm = list(range(256)); rng.shuffle(perm)
    inv = [0] * 256
    for i, p in enumerate(perm):
        inv[p] = i
    parts, calls = [], []
    for i, s in enumerate(strs):
        enc = bytes(perm[b] for b in s.encode() + b"\0")
        parts.append(f"static volatile unsigned char @F_s{i}[] = {{{c_bytes(enc)}}};")
        calls.append(f"for (unsigned j = 0; j < sizeof @F_s{i}; j++) buf[j] = (char)@F_inv[@F_s{i}[j]];\n    r += @F_use(buf);")
    return "\n".join(parts) + f"\nstatic const unsigned char @F_inv[256] = {{{c_bytes(bytes(inv))}}};" + _SINK + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    char buf[256]; int r = 0;
    %s
    return r;
}''' % "\n    ".join(calls)


_SINC = ("stdio.h", "string.h", "stdlib.h")
for i, fn in enumerate([_xor1, _xorN, _stack, _addroll, _split, _b64, _subst], 1):
    T(f"obf.any.strings_{fn.__name__.strip('_')}.v{i}", "obf.strings", OB, "any", fn, inc=_SINC)


# ---------------------------------------------------------------- control-flow flattening
def _blocks(rng, n):
    ops = [
        "x = x * {a}u + {b}u;", "y ^= x >> {s};", "x += y << {s};", "y = (y * {a}u) ^ x;",
        "x ^= {b}u;", "y += {a}u - (x & {m}u);", "x = (x << {s}) | (x >> (32 - {s}));",
        "if (y & 1) x += {b}u; else x -= {a}u;", "y = y + (x %% {m}u + 1u);",
    ]
    out = []
    for _ in range(n):
        k = rng.randint(1, 3)
        stmts = []
        for _ in range(k):
            o = rng.choice(ops)
            stmts.append(o.replace("%%", "%").format(a=rng.randint(3, 99991), b=rng.randint(1, 1 << 30),
                                                     s=rng.randint(1, 31), m=rng.randint(3, 255)))
        out.append(" ".join(stmts))
    return out


def _cff_switch(rng, encoded=False):
    n = rng.randint(5, 14)
    blocks = _blocks(rng, n)
    states = rng.sample(range(1, 1 << 31), n + 1)
    key = rng.randint(1, (1 << 31) - 1) if encoded else 0
    loop_at = rng.randint(1, n - 1)
    enc = lambda s: s ^ key
    cases = []
    for i in range(n):
        nxt = enc(states[i + 1])
        if i == loop_at:
            tr = f"st = (cnt++ < {rng.randint(3, 40)}u) ? {enc(states[1])}u : {nxt}u;"
        else:
            tr = f"st = {nxt}u;"
        cases.append(f"case {states[i]}u: {blocks[i]} {tr} break;")
    rng.shuffle(cases)
    sel = f"(st ^ {key}u)" if encoded else "st"
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned x = (unsigned)argc, y = 0x9e37u, cnt = 0;
    volatile unsigned st = %du;
    while (%s != %du) {
        switch (%s) {
        %s
        default: st = %du; break;
        }
    }
    return (int)(x ^ y);
}''' % (enc(states[0]), sel, states[n], sel, "\n        ".join(cases), enc(states[n]))


def _cff_goto(rng):
    n = rng.randint(5, 12)
    blocks = _blocks(rng, n)
    perm = list(range(n)); rng.shuffle(perm)  # table slot of block i
    body = []
    for i in range(n):
        nxt = f"goto *tbl[{perm[i + 1]}];" if i + 1 < n else "goto done;"
        body.append(f"L{i}: {blocks[i]} {nxt}")
    rng.shuffle(body)
    tbl = [None] * n
    for i in range(n):
        tbl[perm[i]] = f"&&L{i}"
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned x = (unsigned)argc * 7u, y = 3u;
    static void *tbl[] = {%s};
    goto *tbl[%d];
    %s
done:
    return (int)(x + y);
}''' % (", ".join(tbl), perm[0], "\n    ".join(body))


def _cff_fptr(rng):
    n = rng.randint(5, 12)
    blocks = _blocks(rng, n)
    perm = list(range(n)); rng.shuffle(perm)
    fns, tbl = [], [None] * n
    for i in range(n):
        nxt = perm[i + 1] if i + 1 < n else -1
        fns.append(f"static int @F_b{i}(unsigned *px, unsigned *py) {{ unsigned x = *px, y = *py; {blocks[i]} *px = x; *py = y; return {nxt}; }}")
        tbl[perm[i]] = f"@F_b{i}"
    rng.shuffle(fns)
    return "\n".join(fns) + r'''
typedef int (*@F_fn)(unsigned *, unsigned *);
static @F_fn @F_tbl[] = {%s};
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned x = (unsigned)argc, y = 0x1234u;
    volatile int s = %d;
    while (s >= 0) s = @F_tbl[s](&x, &y);
    return (int)(x ^ y);
}''' % (", ".join(tbl), perm[0])


def _cff_arith(rng):
    # next state derived arithmetically from current state: st = (st * A + B) % M
    n = rng.randint(5, 12)
    A, B, M = rng.choice([5, 13, 21, 29]), rng.randint(1, 97) | 1, 1 << rng.randint(8, 16)
    seq, st = [], rng.randint(0, M - 1)
    seen = set()
    while len(seq) < n + 1:
        if st in seen:
            st = (st + 1) % M; continue
        seen.add(st); seq.append(st); st = (st * A + B) % M
    blocks = _blocks(rng, n)
    cases = []
    for i in range(n):
        target = seq[i + 1]
        cases.append(f"case {seq[i]}: {blocks[i]} st = {target}u; break;")
    rng.shuffle(cases)
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned x = (unsigned)argc + 11u, y = 5u;
    volatile unsigned st = %du;
    for (;;) {
        switch (st) {
        %s
        default: goto out;
        }
        if (st == %du) break;
    }
out:
    return (int)(x - y);
}''' % (seq[0], "\n        ".join(cases), seq[n])


T("obf.any.cff_switch.v1", "obf.cff", OB, "any", lambda r: _cff_switch(r, False))
T("obf.any.cff_switch_enc.v2", "obf.cff", OB, "any", lambda r: _cff_switch(r, True))
T("obf.any.cff_goto.v3", "obf.cff", OB, "any", _cff_goto)
T("obf.any.cff_fptr.v4", "obf.cff", OB, "any", _cff_fptr)
T("obf.any.cff_arith.v5", "obf.cff", OB, "any", _cff_arith)


# ---------------------------------------------------------------- opaque predicates / junk
def _opaque(rng, style):
    n = rng.randint(3, 8)
    blocks = _blocks(rng, n)
    junk = _blocks(rng, n)
    preds = {
        1: ["(v * (v + 1)) % 2 == 0", "((v * v) & 3) != 2", "(v | 1) != 0"],
        2: ["7 * w * w - 1 != v * v", "(v * v + v) % 2 == 0", "((v ^ v) == 0)"],
        3: ["((g_@F_c * (g_@F_c - 1)) & 1) == 0", "(g_@F_c & ~g_@F_c) == 0", "((g_@F_c << 1) & 1) == 0"],
    }[style]
    body = []
    for b, j in zip(blocks, junk):
        p = rng.choice(preds)
        if rng.random() < 0.5:
            body.append(f"if ({p}) {{ {b} }} else {{ {j} @F_junk(); }}")
        else:
            body.append(f"if (!({p})) {{ {j} @F_junk(); }} else {{ {b} }}")
    return r'''
static volatile unsigned g_@F_c = 0x1337u;
static __attribute__((noinline)) void @F_junk(void) { volatile int z = 0; for (int i = 0; i < 9; i++) z += i * i; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    volatile unsigned v = (unsigned)argc * 0x45d9f3bu, w = (unsigned)argc + 3u;
    unsigned x = v, y = w;
    %s
    return (int)(x ^ y);
}''' % "\n    ".join(body)


def _junk_dead(rng):
    n = rng.randint(4, 10)
    blocks = _blocks(rng, n)
    body = []
    for b in blocks:
        body.append(b)
        for _ in range(rng.randint(1, 3)):
            body.append(f"{{ volatile unsigned t = x ^ {rng.randint(1, 1 << 30)}u; t = t * t + {rng.randint(1, 999)}u; (void)t; }}")
        if rng.random() < 0.5:
            body.append('__asm__ volatile("nop\\n\\tnop\\n\\t.byte 0x0f,0x1f,0x44,0x00,0x00\\n\\txchg %%ax, %%ax");')
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned x = (unsigned)argc, y = 99u;
    %s
    return (int)(x + y);
}''' % "\n    ".join(body)


T("obf.any.opaque_parity.v1", "obf.opaque", OB, "any", lambda r: _opaque(r, 1))
T("obf.any.opaque_quadratic.v2", "obf.opaque", OB, "any", lambda r: _opaque(r, 2))
T("obf.any.opaque_global.v3", "obf.opaque", OB, "any", lambda r: _opaque(r, 3))
T("obf.any.junk_dead.v4", "obf.opaque", OB, "any", _junk_dead, inc=(), arch="x86_64")


# ---------------------------------------------------------------- anti-disassembly
def _antidis(rng, style):
    reps = rng.randint(2, 6)
    snip = {
        1: '__asm__ volatile("jmp 1f\\n\\t.byte 0xe8\\n1:");',
        2: '__asm__ volatile("jz 1f\\n\\tjnz 1f\\n\\t.byte 0xe9\\n1:" ::: "cc");',
        3: '__asm__ volatile("call 1f\\n1:\\n\\tadd $%d, %%%%esp\\n" ::: "memory");',  # placeholder (unused)
        4: '__asm__ volatile(".byte 0xeb, 0xff, 0xc0\\n\\tdec %%eax" ::: "eax", "cc");',
        5: '__asm__ volatile("push %%%%rax\\n\\txor %%%%eax, %%%%eax\\n\\tjz 1f\\n\\t.byte 0x0f, 0x0b, 0xe8\\n1:\\n\\tpop %%%%rax" ::: "cc", "memory");',
    }[style]
    if style == 3:
        snip = ('__asm__ volatile(\n#ifdef __x86_64__\n"call 1f\\n1:\\n\\tpop %%rax\\n\\tadd $1, %%rax"\n#else\n'
                '"call 1f\\n1:\\n\\tpop %%eax\\n\\tadd $1, %%eax"\n#endif\n ::: "eax", "memory");')
    if style == 5:
        snip = ('__asm__ volatile(\n#ifdef __x86_64__\n"push %%rax\\n\\txor %%eax, %%eax\\n\\tjz 1f\\n\\t.byte 0x0f, 0x0b, 0xe8\\n1:\\n\\tpop %%rax"\n#else\n'
                '"push %%eax\\n\\txor %%eax, %%eax\\n\\tjz 1f\\n\\t.byte 0x0f, 0x0b, 0xe8\\n1:\\n\\tpop %%eax"\n#endif\n ::: "cc", "memory");')
    blocks = _blocks(rng, reps)
    body = []
    for b in blocks:
        body.append(snip.replace("%%", "%") if style in (1, 2) else snip)
        body.append(b)
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned x = (unsigned)argc, y = 17u;
    %s
    return (int)(x ^ y);
}''' % "\n    ".join(body)


T("obf.any.antidis_jmpbyte.v1", "obf.antidisasm", OB, "any", lambda r: _antidis(r, 1))
T("obf.any.antidis_jzjnz.v2", "obf.antidisasm", OB, "any", lambda r: _antidis(r, 2))
T("obf.any.antidis_callpop.v3", "obf.antidisasm", OB, "any", lambda r: _antidis(r, 3))
T("obf.any.antidis_overlap.v4", "obf.antidisasm", OB, "any", lambda r: _antidis(r, 4))
T("obf.any.antidis_fakeud2.v5", "obf.antidisasm", OB, "any", lambda r: _antidis(r, 5))


# ---------------------------------------------------------------- indirect calls
def _indirect_xorptr(rng):
    k = rng.randint(1, (1 << 31) - 1)
    n = rng.randint(3, 6)
    blocks = _blocks(rng, n)
    fns = [f"static __attribute__((noinline)) unsigned @F_f{i}(unsigned x) {{ unsigned y = {i + 1}u; {blocks[i]} return x ^ y; }}" for i in range(n)]
    order = [rng.randrange(n) for _ in range(rng.randint(3, 8))]
    calls = "\n    ".join(f"acc = ((@F_fn)((uintptr_t)@F_tbl[{o}] ^ @F_KEY))(acc);" for o in order)
    return "\n".join(fns) + r'''
#define @F_KEY ((uintptr_t)%du)
typedef unsigned (*@F_fn)(unsigned);
static volatile uintptr_t @F_tbl[%d];
__attribute__((noinline)) int @F(int argc, char **argv) {
    %s
    unsigned acc = (unsigned)argc;
    %s
    return (int)acc;
}''' % (k, n, "\n    ".join(f"@F_tbl[{i}] = (uintptr_t)&@F_f{i} ^ @F_KEY;" for i in range(n)), calls)


def _indirect_hashidx(rng):
    n = rng.randint(4, 8)
    blocks = _blocks(rng, n)
    fns = [f"static __attribute__((noinline)) unsigned @F_f{i}(unsigned x) {{ unsigned y = {i * 7 + 1}u; {blocks[i]} return x + y; }}" for i in range(n)]
    return "\n".join(fns) + r'''
typedef unsigned (*@F_fn)(unsigned);
static @F_fn @F_tbl[] = {%s};
__attribute__((noinline)) int @F(int argc, char **argv) {
    unsigned acc = (unsigned)argc, h = 2166136261u;
    for (int i = 0; i < %d; i++) {
        h = (h ^ (unsigned)i) * 16777619u;
        acc = @F_tbl[h %% %du](acc);
    }
    return (int)acc;
}''' % (", ".join(f"@F_f{i}" for i in range(n)), rng.randint(4, 16), n)


def _indirect_retjmp(rng):
    blocks = _blocks(rng, 3)
    return r'''
static __attribute__((noinline)) unsigned @F_t(unsigned x) { unsigned y = 5u; %s return x ^ y; }
__attribute__((noinline)) int @F(int argc, char **argv) {
    volatile uintptr_t a = (uintptr_t)&@F_t;
    unsigned (*volatile p)(unsigned) = 0;
    a = (a + 0x1000u) - 0x1000u;
    p = (unsigned (*)(unsigned))a;
    return (int)p((unsigned)argc);
}''' % blocks[0]


T("obf.any.indirect_xorptr.v1", "obf.indirect", OB, "any", _indirect_xorptr, inc=("stdint.h",))
T("obf.any.indirect_hashidx.v2", "obf.indirect", OB, "any", _indirect_hashidx)
T("obf.any.indirect_computed.v3", "obf.indirect", OB, "any", _indirect_retjmp, inc=("stdint.h",))


# ---------------------------------------------------------------- API hashing / dynamic resolution
def ror13(name):
    h = 0
    for ch in name.encode():
        h = ((h >> 13) | (h << 19)) & 0xFFFFFFFF
        h = (h + ch) & 0xFFFFFFFF
    return h


def djb2(name):
    h = 5381
    for ch in name.encode():
        h = (h * 33 + ch) & 0xFFFFFFFF
    return h


def fnv1a(name):
    h = 2166136261
    for ch in name.encode():
        h = ((h ^ ch) * 16777619) & 0xFFFFFFFF
    return h


WIN_NEUTRAL = ["GetTickCount", "Sleep", "lstrlenA", "GetCurrentProcessId", "GetSystemTimeAsFileTime", "GetCommandLineA"]
LNX_NEUTRAL = ["getpid", "time", "strlen", "getuid", "sysconf", "getppid"]

_PE_EXPORT_WALK = r'''
static void *@F_find(unsigned char *base, unsigned want) {
    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)base;
    IMAGE_NT_HEADERS *nt = (IMAGE_NT_HEADERS *)(base + dos->e_lfanew);
    DWORD rva = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    if (!rva) return 0;
    IMAGE_EXPORT_DIRECTORY *ex = (IMAGE_EXPORT_DIRECTORY *)(base + rva);
    DWORD *names = (DWORD *)(base + ex->AddressOfNames);
    WORD *ords = (WORD *)(base + ex->AddressOfNameOrdinals);
    DWORD *funcs = (DWORD *)(base + ex->AddressOfFunctions);
    for (DWORD i = 0; i < ex->NumberOfNames; i++) {
        if (@F_hash((const char *)(base + names[i])) == want) return base + funcs[ords[i]];
    }
    return 0;
}'''

_HASHFN = {
    "ror13": ("static unsigned @F_hash(const char *s) { unsigned h = 0; while (*s) { h = (h >> 13) | (h << 19); h += (unsigned char)*s++; } return h; }", ror13),
    "djb2": ("static unsigned @F_hash(const char *s) { unsigned h = 5381; while (*s) h = h * 33 + (unsigned char)*s++; return h; }", djb2),
    "fnv1a": ("static unsigned @F_hash(const char *s) { unsigned h = 2166136261u; while (*s) { h ^= (unsigned char)*s++; h *= 16777619u; } return h; }", fnv1a),
}


def _win_peb_hash(rng):
    hname = rng.choice(list(_HASHFN))
    hsrc, hpy = _HASHFN[hname]
    apis = rng.sample(WIN_NEUTRAL, rng.randint(1, 3))
    calls = []
    for a in apis:
        calls.append(f"r += @F_find(base, 0x{hpy(a):08X}u) != 0;")
    return hsrc + _PE_EXPORT_WALK + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    PPEB peb = NtCurrentTeb()->ProcessEnvironmentBlock;
    LIST_ENTRY *head = &peb->Ldr->InMemoryOrderModuleList, *e;
    unsigned char *base = 0; int r = 0;
    for (e = head->Flink; e != head; e = e->Flink) {
        LDR_DATA_TABLE_ENTRY *m = CONTAINING_RECORD(e, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
        if (!m->FullDllName.Buffer) continue;
        WCHAR *n = m->FullDllName.Buffer; int len = m->FullDllName.Length / 2;
        if (len >= 12 && (n[len - 12] == L'k' || n[len - 12] == L'K') && (n[len - 11] == L'e' || n[len - 11] == L'E')) {
            base = (unsigned char *)m->DllBase; break;
        }
    }
    if (!base) return 0;
    %s
    return r;
}''' % "\n    ".join(calls)


def _win_getproc_xor(rng):
    apis = rng.sample(WIN_NEUTRAL, rng.randint(1, 3))
    key = rng.randint(1, 255)
    arrs, calls = [], []
    for i, a in enumerate(apis + ["kernel32.dll"]):
        enc = bytes(b ^ key for b in a.encode() + b"\0")
        arrs.append(f"static volatile unsigned char @F_n{i}[] = {{{c_bytes(enc)}}};")
    mod = len(apis)
    for i in range(len(apis)):
        calls.append(f"@F_d(@F_n{i}, sizeof @F_n{i}, nm); r += GetProcAddress(k, nm) != NULL;")
    return "\n".join(arrs) + r'''
static void @F_d(volatile unsigned char *s, unsigned n, char *o) { for (unsigned i = 0; i < n; i++) o[i] = (char)(s[i] ^ %d); }
__attribute__((noinline)) int @F(int argc, char **argv) {
    char nm[64]; int r = 0;
    @F_d(@F_n%d, sizeof @F_n%d, nm);
    HMODULE k = LoadLibraryA(nm);
    %s
    return r;
}''' % (key, mod, mod, "\n    ".join(calls))


def _win_module_hash(rng):
    hname = rng.choice(list(_HASHFN))
    hsrc, hpy = _HASHFN[hname]
    apis = rng.sample(WIN_NEUTRAL, rng.randint(1, 3))
    calls = "\n    ".join(f"r += @F_find(base, 0x{hpy(a):08X}u) != 0;" for a in apis)
    return hsrc + _PE_EXPORT_WALK + r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    volatile char m[13];
    m[0]='k';m[1]='e';m[2]='r';m[3]='n';m[4]='e';m[5]='l';m[6]='3';m[7]='2';m[8]='.';m[9]='d';m[10]='l';m[11]='l';m[12]=0;
    unsigned char *base = (unsigned char *)GetModuleHandleA((const char *)m);
    int r = 0;
    if (!base) return 0;
    %s
    return r;
}''' % calls


def _lnx_dlsym_xor(rng):
    apis = rng.sample(LNX_NEUTRAL, rng.randint(1, 3))
    key = rng.randint(1, 255)
    arrs = []
    for i, a in enumerate(apis + ["libc.so.6"]):
        enc = bytes(b ^ key for b in a.encode() + b"\0")
        arrs.append(f"static volatile unsigned char @F_n{i}[] = {{{c_bytes(enc)}}};")
    mod = len(apis)
    calls = "\n    ".join(f"@F_d(@F_n{i}, sizeof @F_n{i}, nm); r += dlsym(h, nm) != NULL;" for i in range(len(apis)))
    return "\n".join(arrs) + r'''
static void @F_d(volatile unsigned char *s, unsigned n, char *o) { for (unsigned i = 0; i < n; i++) o[i] = (char)(s[i] ^ %d); }
__attribute__((noinline)) int @F(int argc, char **argv) {
    char nm[64]; int r = 0;
    @F_d(@F_n%d, sizeof @F_n%d, nm);
    void *h = dlopen(nm, RTLD_LAZY);
    if (!h) h = RTLD_DEFAULT;
    %s
    return r;
}''' % (key, mod, mod, "\n    ".join([calls]))


def _lnx_phdr_hash(rng):
    hname = rng.choice(list(_HASHFN))
    hsrc, hpy = _HASHFN[hname]
    apis = rng.sample(LNX_NEUTRAL, rng.randint(1, 3))
    wants = ", ".join(f"0x{hpy(a):08X}u" for a in apis)
    return hsrc + r'''
static unsigned @F_want[] = {%s};
static int @F_found;
static int @F_cb(struct dl_phdr_info *info, size_t sz, void *data) {
    for (int i = 0; i < info->dlpi_phnum; i++) {
        if (info->dlpi_phdr[i].p_type != PT_DYNAMIC) continue;
        ElfW(Dyn) *d = (ElfW(Dyn) *)(info->dlpi_addr + info->dlpi_phdr[i].p_vaddr);
        ElfW(Sym) *sym = 0; const char *str = 0;
        for (; d->d_tag != DT_NULL; d++) {
            if (d->d_tag == DT_SYMTAB) sym = (ElfW(Sym) *)d->d_un.d_ptr;
            if (d->d_tag == DT_STRTAB) str = (const char *)d->d_un.d_ptr;
        }
        if (!sym || !str) continue;
        for (ElfW(Sym) *s = sym + 1; (const char *)s < str; s++)
            for (unsigned k = 0; k < sizeof @F_want / sizeof *@F_want; k++)
                if (s->st_name && @F_hash(str + s->st_name) == @F_want[k]) @F_found++;
    }
    return 0;
}
__attribute__((noinline)) int @F(int argc, char **argv) {
    dl_iterate_phdr(@F_cb, NULL);
    return @F_found;
}''' % wants


def _lnx_dlsym_stack(rng):
    api = rng.choice(LNX_NEUTRAL)
    sets = " ".join(f"n[{i}] = '{c}';" for i, c in enumerate(api))
    return r'''
__attribute__((noinline)) int @F(int argc, char **argv) {
    volatile char n[32];
    %s n[%d] = 0;
    void *p = dlsym(RTLD_DEFAULT, (const char *)n);
    return p != NULL;
}''' % (sets, len(api))


T("obf.win.apihash_peb.v1", "obf.api_hash", OB, "windows", _win_peb_hash, inc=("windows.h", "winternl.h"))
T("obf.win.getproc_xor.v2", "obf.api_hash", OB, "windows", _win_getproc_xor, inc=("windows.h",))
T("obf.win.apihash_module.v3", "obf.api_hash", OB, "windows", _win_module_hash, inc=("windows.h",))
T("obf.linux.dlsym_xor.v4", "obf.api_hash", OB, "linux", _lnx_dlsym_xor, inc=("dlfcn.h",))
T("obf.linux.apihash_phdr.v5", "obf.api_hash", OB, "linux", _lnx_phdr_hash, inc=("link.h", "elf.h"))
T("obf.linux.dlsym_stack.v6", "obf.api_hash", OB, "linux", _lnx_dlsym_stack, inc=("dlfcn.h",))
