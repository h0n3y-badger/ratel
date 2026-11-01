#!/usr/bin/env python3
"""Synthetic labeled corpus generator for ratel.

    python3 train/gen/generate.py --out data/synth --n 12000 --seed 1 --jobs 16

Each sample = random benign filler + 0..4 technique snippets (+ optional hard
negatives), compiled with a random toolchain/opt level/strip setting. ~13% are
then "packed": the compiled inner program is encrypted into a stub.

Nothing here ever EXECUTES a generated binary. Packed stubs decode their blob
into memory but never transfer control to it, so they carry a packer's static
signature without being a working loader.
"""
import argparse
import json
import os
import random
import shutil
import subprocess
import sys
import time
from collections import Counter
from concurrent.futures import ProcessPoolExecutor, as_completed

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import common  # noqa: E402
import lib_antidebug, lib_antivm, lib_obf, lib_crypto, lib_net, lib_benign  # noqa: E402,F401
from common import CAPS, REGISTRY, c_bytes, order_includes  # noqa: E402

ZIG = ["zig", "cc", "-fno-sanitize=all"]
TOOLCHAINS = [
    # name, platform, arch, argv prefix, weight
    ("gcc", "linux", "x86_64", ["gcc"], 0.20),
    ("clang", "linux", "x86_64", ["clang"], 0.13),
    ("musl", "linux", "x86_64", ["musl-gcc", "-static"], 0.10),
    ("zigmusl", "linux", "x86_64", ZIG + ["-target", "x86_64-linux-musl"], 0.07),
    ("zigwin64", "windows", "x86_64", ZIG + ["-target", "x86_64-windows-gnu"], 0.30),
    ("zigwin32", "windows", "x86", ZIG + ["-target", "x86-windows-gnu"], 0.20),
]
P_NO_TECH = 0.35
P_PACKED = 0.13
P_HARDNEG = 0.40


def eligible(kind, plat, arch):
    return [s for s in REGISTRY if s.kind == kind and s.plat in (plat, "any") and (s.arch in (None, arch))]


def render(snip, fname, rng):
    code = snip.code(rng) if callable(snip.code) else snip.code
    return code.replace("@F", fname)


def assemble(parts, plat, rng, extra_top=""):
    """parts: list of (snip_or_None, code_already_rendered, fname)."""
    incs = ["stdio.h", "stdlib.h", "string.h", "stdint.h"]
    for s, _, _ in parts:
        if s is not None:
            incs += list(s.inc)
    head = "#define _GNU_SOURCE\n" if plat == "linux" else "#define WIN32_LEAN_AND_MEAN_OFF 1\n"
    head += "\n".join(f"#include <{h}>" for h in order_includes(incs)) + "\n"
    body = "\n".join(code for _, code, _ in parts)
    order = [f for _, _, f in parts]
    rng.shuffle(order)
    calls = "\n".join(f"    acc += {f}(argc, argv);" for f in order)
    main = f"\nint main(int argc, char **argv) {{\n    int acc = 0;\n{calls}\n    printf(\"%d\\n\", acc);\n    return acc & 1;\n}}\n"
    return head + extra_top + body + main


def compile_c(src, out, tc, opt, strip, libs, cflags, tmp, plat):
    cpath = out + ".c"
    with open(cpath, "w") as fh:
        fh.write(src)
    argv = list(tc[3]) + ["-w", opt] + list(cflags) + [cpath, "-o", out]
    if strip:
        argv.append("-s")
    if plat == "linux":
        argv += ["-lm"] + (["-ldl"] if tc[0] in ("gcc", "clang") else [])
    argv += [f"-l{l}" for l in dict.fromkeys(libs)]
    env = dict(os.environ, ZIG_GLOBAL_CACHE_DIR=os.path.join(tmp, "..", "zigcache"))
    p = subprocess.run(argv, capture_output=True, text=True, timeout=180, env=env, cwd=tmp)
    try:
        os.unlink(cpath)
    except OSError:
        pass
    if p.returncode != 0 or not os.path.exists(out):
        return p.stderr[-1500:]
    return None


# ------------------------------------------------------------------ packing
def encrypt(data, method, rng):
    if method == "xor":
        key = bytes(rng.getrandbits(8) for _ in range(rng.randint(1, 16)))
        return bytes(b ^ key[i % len(key)] ^ (i & 0xFF) for i, b in enumerate(data)), {"key": key}
    if method == "lcg":
        seed = rng.getrandbits(32) | 1
        out = bytearray(len(data))
        x = seed
        for i, b in enumerate(data):
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF
            out[i] = b ^ (x >> 16 & 0xFF)
        return bytes(out), {"seed": seed}
    # rc4
    key = bytes(rng.getrandbits(8) for _ in range(16))
    S = list(range(256))
    j = 0
    for i in range(256):
        j = (j + S[i] + key[i % 16]) & 0xFF
        S[i], S[j] = S[j], S[i]
    i = j = 0
    out = bytearray()
    for b in data:
        i = (i + 1) & 0xFF
        j = (j + S[i]) & 0xFF
        S[i], S[j] = S[j], S[i]
        out.append(b ^ S[(S[i] + S[j]) & 0xFF])
    return bytes(out), {"key": key}


def decoder_c(method, meta):
    if method == "xor":
        k = meta["key"]
        return (f"static const unsigned char pk_key[{len(k)}] = {{{c_bytes(k)}}};\n"
                "static void pk_decode(unsigned char *b, size_t n) { for (size_t i = 0; i < n; i++) "
                f"b[i] ^= pk_key[i % {len(k)}] ^ (unsigned char)(i & 0xff); }}\n")
    if method == "lcg":
        return ("static void pk_decode(unsigned char *b, size_t n) { uint32_t x = %uu; for (size_t i = 0; i < n; i++) "
                "{ x = x * 1103515245u + 12345u; b[i] ^= (unsigned char)(x >> 16); } }\n" % meta["seed"])
    k = meta["key"]
    return (f"static const unsigned char pk_key[16] = {{{c_bytes(k)}}};\n"
            "static void pk_decode(unsigned char *b, size_t n) {\n"
            "    unsigned char S[256]; unsigned i, j = 0, t;\n"
            "    for (i = 0; i < 256; i++) S[i] = (unsigned char)i;\n"
            "    for (i = 0; i < 256; i++) { j = (j + S[i] + pk_key[i & 15]) & 255; t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t; }\n"
            "    i = j = 0;\n"
            "    for (size_t k = 0; k < n; k++) { i = (i + 1) & 255; j = (j + S[i]) & 255; t = S[i]; S[i] = S[j]; S[j] = (unsigned char)t; b[k] ^= S[(S[i] + S[j]) & 255]; }\n"
            "}\n")


def stub_source(plat, method, meta, blob_len, where, rng):
    """Returns (top-of-file C, stub function code, includes)."""
    sec = rng.choice([".pdata1", ".xdat", ".payload", ".cfgx", ".rsrc2", ".sdata1", "UPX1", ".mpress1", ".nsp1"])
    if where == "array":
        storage = "static const unsigned char pk_blob[%d] = {@BLOB@};\n" % blob_len
    elif where == "section":
        storage = '__attribute__((section("%s"), used)) static const unsigned char pk_blob[%d] = {@BLOB@};\n' % (sec, blob_len)
    else:
        storage = ""
    top = decoder_c(method, meta) + storage
    if plat == "linux":
        incs = ("sys/mman.h", "unistd.h", "fcntl.h", "sys/syscall.h")
        if where == "overlay":
            load = ("    FILE *f = fopen(\"/proc/self/exe\", \"rb\"); if (!f) return 0;\n"
                    f"    fseek(f, -{blob_len}L, SEEK_END); unsigned char *b = malloc({blob_len}); size_t n = fread(b, 1, {blob_len}, f); fclose(f);\n")
        else:
            load = f"    size_t n = sizeof pk_blob; unsigned char *b = malloc(n); memcpy(b, pk_blob, n);\n"
        sink = rng.choice([
            "    int fd = (int)syscall(SYS_memfd_create, \"\", 1); if (fd >= 0) { ssize_t w = write(fd, b, n); (void)w; close(fd); }\n",
            "    void *m = mmap(0, n, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);\n"
            "    if (m != MAP_FAILED) { memcpy(m, b, n); mprotect(m, n, PROT_READ | PROT_EXEC); munmap(m, n); }\n",
            "    int fd = memfd_create(\"pk\", MFD_CLOEXEC); if (fd >= 0) { ssize_t w = write(fd, b, n); (void)w; close(fd); }\n",
        ])
    else:
        incs = ("windows.h",)
        if where == "overlay":
            load = ("    char me[MAX_PATH]; GetModuleFileNameA(NULL, me, MAX_PATH); FILE *f = fopen(me, \"rb\"); if (!f) return 0;\n"
                    f"    fseek(f, -{blob_len}L, SEEK_END); unsigned char *b = malloc({blob_len}); size_t n = fread(b, 1, {blob_len}, f); fclose(f);\n")
        else:
            load = "    size_t n = sizeof pk_blob; unsigned char *b = malloc(n); memcpy(b, pk_blob, n);\n"
        sink = rng.choice([
            "    void *m = VirtualAlloc(NULL, n, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);\n"
            "    if (m) { DWORD old; memcpy(m, b, n); VirtualProtect(m, n, PAGE_EXECUTE_READ, &old); VirtualFree(m, 0, MEM_RELEASE); }\n",
            "    HANDLE h = HeapCreate(0, 0, 0); void *m = HeapAlloc(h, 0, n);\n"
            "    if (m) { DWORD old; memcpy(m, b, n); VirtualProtect(m, n, PAGE_EXECUTE_READWRITE, &old); }\n",
        ])
    fn = ("__attribute__((noinline)) int pk_main(int argc, char **argv) {\n" + load + "    pk_decode(b, n);\n" + sink +
          "    unsigned s = 0; for (size_t i = 0; i < n; i += 4096) s += b[i];\n    free(b);\n    return (int)(s & 1);\n}\n")
    return top, fn, incs


# ------------------------------------------------------------------ one sample
def build(i, seed, out_dir):
    rng = random.Random(f"{seed}:{i}")
    tc = rng.choices(TOOLCHAINS, weights=[t[4] for t in TOOLCHAINS])[0]
    plat, arch = tc[1], tc[2]
    tmp = os.path.join(out_dir, "tmp", f"w{i}")
    os.makedirs(tmp, exist_ok=True)
    sid = f"s{seed}_{i:06d}"
    final = os.path.join(out_dir, "bin", sid + (".exe" if plat == "windows" else ""))
    try:
        techs_pool = eligible("tech", plat, arch)
        n_tech = 0 if rng.random() < P_NO_TECH else rng.choice([1, 1, 1, 2, 2, 3, 4])
        # Pick a capability first, then a variant, so rare capabilities (network:
        # few variants) are as common as ones with many variants (anti_debug).
        techs = []
        for _ in range(n_tech):
            cap = rng.choice([c for c in CAPS if c != "packed"])
            pool = [s for s in techs_pool if s.labels.get(cap) and s not in techs]
            if pool:
                techs.append(rng.choice(pool))
        fill = rng.sample(eligible("benign", plat, arch), rng.randint(1, 6))
        if rng.random() < P_HARDNEG:
            fill += rng.sample(eligible("hardneg", plat, arch), rng.randint(1, 2))
        snips = techs + fill
        parts = [(s, render(s, f"f{k}", rng), f"f{k}") for k, s in enumerate(snips)]
        libs = [l for s in snips for l in s.libs]
        cflags = list(dict.fromkeys(f for s in snips for f in s.cflags))
        opt = rng.choice(["-O0", "-O1", "-O2", "-Os"])
        strip = rng.random() < 0.5
        labels = {c: int(any(s.labels.get(c) for s in techs)) for c in CAPS}
        packed = rng.random() < P_PACKED
        target = os.path.join(tmp, "inner" if packed else "out")
        err = compile_c(assemble(parts, plat, rng), target, tc, opt, strip, libs, cflags, tmp, plat)
        if err:
            return {"ok": False, "id": sid, "snips": [s.id for s in snips], "tc": tc[0], "err": err}
        toolchain = f"{tc[0]}{opt}{'-strip' if strip else ''}"
        info = {}
        if packed:
            inner = open(target, "rb").read()
            method = rng.choice(["xor", "lcg", "lcg", "rc4"])
            where = rng.choice(["array", "array", "section", "overlay"])
            blob, meta = encrypt(inner, method, rng)
            top, fn, incs = stub_source(plat, method, meta, len(blob), where, rng)
            top = top.replace("@BLOB@", c_bytes(blob, 64))
            stub_fill = rng.sample(eligible("benign", plat, arch), rng.randint(0, 2))
            sparts = [(s, render(s, f"g{k}", rng), f"g{k}") for k, s in enumerate(stub_fill)]
            fake = common.Snip(id="packer.stub", family="packer", labels={}, plat=plat, code="", inc=incs)
            sparts.append((fake, fn, "pk_main"))
            s_opt = rng.choice(["-O1", "-O2", "-Os"])
            s_strip = rng.random() < 0.7
            target = os.path.join(tmp, "out")
            err = compile_c(assemble(sparts, plat, rng, top), target, tc, s_opt, s_strip,
                            [l for s in stub_fill for l in s.libs], [], tmp, plat)
            if err:
                return {"ok": False, "id": sid, "snips": ["packer.stub"], "tc": tc[0], "err": err}
            if where == "overlay":
                with open(target, "ab") as fh:
                    fh.write(blob)
            # Inner capabilities are hidden from static analysis.
            labels = {c: None for c in CAPS}
            labels.update({"packed": 1, "crypto": int(method == "rc4"), "anti_debug": 0, "anti_vm": 0,
                           "obfuscation": None, "network": 0})
            info = {"pack": method, "where": where, "inner_techniques": [s.id for s in techs]}
            techs_ids = [f"packer.{method}.{where}"]
            groups = [f"packer.{where}"]
            toolchain = f"{tc[0]}{s_opt}{'-strip' if s_strip else ''}"
        else:
            techs_ids = [s.id for s in techs]
            groups = sorted({s.family for s in techs})
        shutil.move(target, final)
        row = {"id": sid, "path": os.path.relpath(final, out_dir), "format": "pe" if plat == "windows" else "elf",
               "arch": arch, "toolchain": toolchain, "labels": labels, "techniques": techs_ids, "groups": groups,
               "hardneg": [s.id for s in fill if s.kind == "hardneg"], **info}
        return {"ok": True, "row": row}
    except subprocess.TimeoutExpired:
        return {"ok": False, "id": sid, "snips": [], "tc": tc[0], "err": "timeout"}
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--out", required=True)
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--jobs", type=int, default=os.cpu_count())
    ap.add_argument("--start", type=int, default=0, help="first sample index (to extend a corpus)")
    a = ap.parse_args()
    out = os.path.abspath(a.out)
    os.makedirs(os.path.join(out, "bin"), exist_ok=True)
    os.makedirs(os.path.join(out, "tmp"), exist_ok=True)
    t0 = time.time()
    ok, fails = [], []
    snip_fail = Counter()
    with ProcessPoolExecutor(a.jobs) as ex, open(os.path.join(out, "labels.jsonl"), "a") as lab, \
            open(os.path.join(out, "failures.jsonl"), "a") as fl:
        futs = [ex.submit(build, i, a.seed, out) for i in range(a.start, a.start + a.n)]
        for k, f in enumerate(as_completed(futs), 1):
            r = f.result()
            if r["ok"]:
                ok.append(r["row"])
                lab.write(json.dumps(r["row"]) + "\n")
            else:
                fails.append(r)
                fl.write(json.dumps(r) + "\n")
                for s in r["snips"]:
                    snip_fail[s] += 1
            if k % 500 == 0:
                print(f"{k}/{a.n} done, {len(fails)} failed, {time.time() - t0:.0f}s", flush=True)
    shutil.rmtree(os.path.join(out, "tmp"), ignore_errors=True)
    print(f"built {len(ok)} / {a.n} in {time.time() - t0:.0f}s ({len(fails)} failures)")
    print("formats:", dict(Counter(r["format"] for r in ok)))
    for c in CAPS:
        v = Counter(r["labels"][c] for r in ok)
        print(f"  {c:12s} pos={v[1]} neg={v[0]} unknown={v[None]}")
    if snip_fail:
        print("snippets most involved in failures:", snip_fail.most_common(15))


if __name__ == "__main__":
    main()
