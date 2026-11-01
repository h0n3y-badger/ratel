#!/usr/bin/env python3
"""Build path lists of real-world ELF/PE files for training negatives / holdout.

Writes data/real_train.txt, data/real_holdout.txt, data/real_games.txt.
Only x86/x86-64 files; caps files per directory so no single package dominates.
"""
import os, random, struct, sys
from collections import defaultdict

HOME = os.path.expanduser("~")
STEAM = f"{HOME}/.var/app/com.valvesoftware.Steam/.local/share/Steam/steamapps/common"
TRAIN_ROOTS = ["/usr/bin", "/usr/lib", "/usr/libexec", "/usr/sbin", f"{HOME}/.cargo/bin", f"{STEAM}/Proton 11.0"]
HOLDOUT_ROOTS = [f"{HOME}/.local/share/flatpak/runtime", "/var/lib/flatpak/runtime"]
GAME_ROOT = STEAM
PER_DIR = 60
MAX = 96 << 20


def kind(path):
    try:
        with open(path, "rb") as fh:
            h = fh.read(4096)
    except OSError:
        return None
    if h[:4] == b"\x7fELF" and len(h) >= 20:
        mach = struct.unpack_from("<H", h, 18)[0]
        return "elf" if mach in (3, 62) else None
    if h[:2] == b"MZ" and len(h) >= 0x40:
        off = struct.unpack_from("<I", h, 0x3C)[0]
        if off + 6 <= len(h) and h[off:off + 4] == b"PE\0\0":
            mach = struct.unpack_from("<H", h, off + 4)[0]
            return "pe" if mach in (0x14C, 0x8664) else None
    return None


def walk(roots, skip=lambda p: False):
    by_dir = defaultdict(list)
    for r in roots:
        for dp, dns, fns in os.walk(r):
            dns[:] = [d for d in dns if not skip(os.path.join(dp, d))]
            for fn in fns:
                p = os.path.join(dp, fn)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                if not os.path.isfile(p) or os.path.islink(p) or st.st_size < 1024 or st.st_size > MAX:
                    continue
                if kind(p):
                    by_dir[dp].append(p)
    return by_dir


def sample(by_dir, per_dir, rng):
    out = []
    for d in sorted(by_dir):
        fs = sorted(by_dir[d])
        rng.shuffle(fs)
        out += fs[:per_dir]
    return out


def main():
    rng = random.Random(7)
    os.makedirs("data", exist_ok=True)
    skip_games = lambda p: "/Proton" in p or "SteamLinuxRuntime" in p or "Steamworks Shared" in p
    tr = sample(walk(TRAIN_ROOTS, lambda p: "/usr/lib/modules" in p or "/usr/lib/firmware" in p), PER_DIR, rng)
    ho = sample(walk(HOLDOUT_ROOTS), PER_DIR // 2, rng)
    games = sample(walk([GAME_ROOT], skip_games), 400, rng)
    for name, lst in [("real_train", tr), ("real_holdout", ho), ("real_games", games)]:
        with open(f"data/{name}.txt", "w") as fh:
            fh.write("\n".join(lst) + "\n")
        print(name, len(lst))


if __name__ == "__main__":
    sys.exit(main())
