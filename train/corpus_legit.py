#!/usr/bin/env python3
"""Download legitimate software that legitimately *contains* VM / debugger /
container code, plus a broad sample of Alpine (the deployment target) packages.

Nothing is installed or executed: packages are downloaded over HTTPS from the
Arch/Artix mirrors (via `pacman -Sp`, which only prints URLs) and the Alpine
CDN, and unpacked with bsdtar into data/legit/.

Outputs:
  data/legit_tools.jsonl   {"path","origin","distro","category"} for the curated tools
  data/alpine_train.txt    general Alpine binaries (negatives)
  data/alpine_holdout.txt  general Alpine binaries, other packages (FPR check)

Categories decide the training labels (see train.py LEGIT_LABELS):
  hypervisor / container / debugger / wine : they *implement* VMs / tracing, so they
      are negatives for anti_vm / anti_debug even though they contain the strings.
  vm_guest / sysinfo : they really do detect VMs; never relabelled, evaluation only.
"""
import gzip
import io
import json
import os
import random
import subprocess
import sys
import tarfile
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from corpus_real import kind  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "data", "legit")
ALPINE = "https://dl-cdn.alpinelinux.org/alpine/v3.24"

# category -> (arch package names, alpine origins)
LEGIT = {
    "hypervisor": (["virtualbox", "qemu-system-x86", "qemu-system-aarch64", "qemu-img", "qemu-common", "firecracker", "libvirt"],
                   ["qemu", "libvirt", "firecracker"]),
    "container": (["docker", "podman", "crun", "runc", "lxc", "containerd"],
                  ["docker", "containerd", "runc", "crun", "podman", "lxc"]),
    "debugger": (["gdb", "lldb", "strace", "ltrace", "valgrind", "radare2", "rizin"],
                 ["gdb", "lldb", "strace", "ltrace", "valgrind", "radare2", "rizin"]),
    "wine": (["wine"], ["wine"]),
    "vm_guest": (["open-vm-tools", "virtualbox-guest-utils"], ["open-vm-tools", "virtualbox-guest-additions"]),
    "sysinfo": (["dmidecode", "hwinfo"], ["dmidecode", "util-linux"]),
}
# Alpine qemu builds every target; keep the relevant ones.
ALPINE_QEMU_KEEP = {"qemu-system-x86_64", "qemu-system-aarch64", "qemu-img", "qemu-x86_64", "qemu-guest-agent", "qemu"}
QEMU_GUEST = {"qemu-guest-agent"}
SKIP_SUFFIX = ("-doc", "-dev", "-dbg", "-lang", "-bash-completion", "-zsh-completion", "-fish-completion", "-openrc",
               "-pyc", "-static", "-tests")
PER_PKG = 150
N_ALPINE = 450


def fetch(url, dest):
    if os.path.exists(dest) and os.path.getsize(dest) > 0:
        return dest
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    tmp = dest + ".part"
    if url.startswith("file://"):
        with open(url[7:], "rb") as src, open(tmp, "wb") as dst:
            dst.write(src.read())
    else:
        with urllib.request.urlopen(url, timeout=120) as r, open(tmp, "wb") as fh:
            while chunk := r.read(1 << 20):
                fh.write(chunk)
    os.replace(tmp, dest)
    return dest


def unpack(pkg_file, dest):
    if os.path.isdir(dest):
        return dest
    os.makedirs(dest + ".part", exist_ok=True)
    # bsdtar handles .pkg.tar.zst and Alpine's concatenated-gzip .apk; never extract
    # absolute paths or '..' (bsdtar refuses them by default), never set modes beyond rw.
    subprocess.run(["bsdtar", "-xf", pkg_file, "-C", dest + ".part", "--no-same-owner", "--no-same-permissions"],
                   check=False, stderr=subprocess.DEVNULL)
    os.replace(dest + ".part", dest)
    return dest


def binaries(d, rng, cap=PER_PKG):
    out = []
    for dp, _, fns in os.walk(d):
        for fn in fns:
            p = os.path.join(dp, fn)
            if os.path.islink(p) or not os.path.isfile(p):
                continue
            sz = os.path.getsize(p)
            if 1024 <= sz <= (96 << 20) and kind(p):
                out.append(p)
    out.sort()
    rng.shuffle(out)
    return sorted(out[:cap])


def arch_urls(names):
    urls = {}
    for n in names:
        r = subprocess.run(["pacman", "-Spdd", "--print-format", "%n %l", n], capture_output=True, text=True)
        for line in r.stdout.splitlines():
            name, url = line.split(" ", 1)
            urls[name] = url
        if r.returncode:
            print(f"  arch: {n} not found", file=sys.stderr)
    return urls


def apkindex(repo):
    raw = urllib.request.urlopen(f"{ALPINE}/{repo}/x86_64/APKINDEX.tar.gz", timeout=60).read()
    # APKINDEX.tar.gz is a signature tarball followed by the index tarball (two gzip members).
    text = None
    with tarfile.open(fileobj=io.BytesIO(gzip.decompress(raw))) as tf:
        for m in tf.getmembers():
            if m.name == "APKINDEX":
                text = tf.extractfile(m).read().decode()
    pkgs = []
    for block in text.split("\n\n"):
        d = {}
        for line in block.splitlines():
            if len(line) > 2 and line[1] == ":":
                d[line[0]] = line[2:]
        if "P" in d:
            d["repo"] = repo
            pkgs.append(d)
    return pkgs


def main():
    rng = random.Random(11)
    os.makedirs(OUT, exist_ok=True)
    rows = []

    # ---- Arch / Artix
    all_arch = sorted({n for names, _ in LEGIT.values() for n in names})
    urls = arch_urls(all_arch)
    for cat, (names, _) in LEGIT.items():
        for n in names:
            if n not in urls:
                continue
            url = urls[n]
            f = fetch(url, os.path.join(OUT, "pkgs", "arch", os.path.basename(url)))
            d = unpack(f, os.path.join(OUT, "arch", n))
            bins = binaries(d, rng)
            origin = "qemu" if n.startswith("qemu") else n
            rows += [{"path": p, "origin": origin, "distro": "arch", "category": cat, "pkg": n} for p in bins]
            print(f"arch   {cat:10s} {n:24s} {len(bins)}")

    # ---- Alpine
    idx = apkindex("main") + apkindex("community")
    by_origin = {}
    for p in idx:
        by_origin.setdefault(p.get("o", p["P"]), []).append(p)

    def get_alpine(p):
        fn = f"{p['P']}-{p['V']}.apk"
        f = fetch(f"{ALPINE}/{p['repo']}/x86_64/{fn}", os.path.join(OUT, "pkgs", "alpine", fn))
        return unpack(f, os.path.join(OUT, "alpine", p["P"]))

    legit_alpine = set()
    for cat, (_, origins) in LEGIT.items():
        for o in origins:
            for p in by_origin.get(o, []):
                name = p["P"]
                if name.endswith(SKIP_SUFFIX) or int(p.get("S", 0)) > (120 << 20):
                    continue
                if o == "qemu" and name not in ALPINE_QEMU_KEEP:
                    continue
                if o == "util-linux" and name != "util-linux-misc":
                    continue
                c = "vm_guest" if name in QEMU_GUEST else cat
                bins = binaries(get_alpine(p), rng)
                legit_alpine.add(name)
                rows += [{"path": b, "origin": o, "distro": "alpine", "category": c, "pkg": name} for b in bins]
                print(f"alpine {c:10s} {name:24s} {len(bins)}")

    with open(os.path.join(ROOT, "data", "legit_tools.jsonl"), "w") as fh:
        for r in rows:
            fh.write(json.dumps(r) + "\n")

    # ---- broad Alpine sample: the server's own distro, musl builds.
    cand = sorted((p for p in idx if p["P"] not in legit_alpine and p.get("A") == "x86_64"
                   and not p["P"].endswith(SKIP_SUFFIX) and 20_000 <= int(p.get("S", 0)) <= (25 << 20)
                   and p.get("o", p["P"]) not in {o for _, os_ in LEGIT.values() for o in os_}),
                  key=lambda p: p["P"])
    rng.shuffle(cand)
    tr, ho = [], []
    got = 0
    for p in cand:
        if got >= N_ALPINE:
            break
        try:
            bins = binaries(get_alpine(p), rng, cap=30)
        except Exception as e:  # network hiccup: skip the package
            print(f"  skip {p['P']}: {e}", file=sys.stderr)
            continue
        if not bins:
            continue
        got += 1
        # split by origin so a project's subpackages stay on one side
        h = sum(p.get("o", p["P"]).encode()) % 10
        (ho if h < 3 else tr).extend(bins)
    for name, lst in [("alpine_train", tr), ("alpine_holdout", ho)]:
        with open(os.path.join(ROOT, "data", f"{name}.txt"), "w") as fh:
            fh.write("\n".join(lst) + "\n")
        print(name, len(lst))
    print("legit tools", len(rows))


if __name__ == "__main__":
    sys.exit(main())
