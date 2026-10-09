#!/usr/bin/env python3
"""Extract a PS3 legacy .pkg entry (chain-resolved, Oodle via liblinoodle3.so).

Entry record: {u32 class_tag; u32 u04; u64 loc}.
  loc bits 0..13 = first block; 14..27 = byte offset /16; 28..57 = size.
Blocks are 0x40000 logical; block record {u32 file_off; u32 stored; u16 gen; u16 flags; sha1[20]}.
The bytes physically live in <stem>_<gen>.pkg of the same chain.
"""
import ctypes, functools, glob, os, re, struct, sys
from pathlib import Path

REPO = Path(__file__).resolve().parents[1]
DLLDIR = REPO / "local/oodle"
BRIDGE = Path(os.environ.get("D1_OODLE", "liblinoodle3.so"))   # Oodle bridge library, user supplied
BLOCK = 0x40000
PKGDIRS = [os.path.expanduser("~/.config/rpcs3/dev_hdd0/game/BLUS31181/USRDIR/a0000001/packages"),
           os.environ.get("D1_DISC_PACKAGES", str(REPO / "game/PS3_GAME/USRDIR/packages"))]

_decomp = None
def _oodle():
    global _decomp
    if _decomp is None:
        os.chdir(DLLDIR)
        lib = ctypes.CDLL(str(BRIDGE))
        f = lib.OodleLZ_Decompress
        f.restype = ctypes.c_longlong
        f.argtypes = [ctypes.c_void_p, ctypes.c_longlong, ctypes.c_void_p, ctypes.c_longlong,
                      ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_void_p, ctypes.c_void_p,
                      ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_int]
        _decomp = f
    return _decomp

def decompress_block(stored):
    """Oodle needs the exact decompressed size. Blocks are 0x40000 except a package's last block,
    which is shorter but still a multiple of 0x4000 (e.g. 012f gen 4 block 291 = 0x2c000), so
    retry at each smaller multiple."""
    buf = ctypes.create_string_buffer(stored)
    out = ctypes.create_string_buffer(BLOCK)
    for size in range(BLOCK, 0, -0x4000):
        r = _oodle()(ctypes.cast(buf, ctypes.c_void_p), len(stored), ctypes.cast(out, ctypes.c_void_p),
                     size, 1, 0, 1, None, None, None, None, None, None, 3)
        if r > 0:
            return out.raw[:r]
    return None

@functools.lru_cache(maxsize=None)
def find_chain(stem):
    """Return {gen: path} for a stem across the installed + disc dirs."""
    out = {}
    for d in PKGDIRS:
        for p in glob.glob(os.path.join(glob.escape(d), stem + "_*.pkg")):
            m = re.search(r"_(\d+)\.pkg$", p)
            if m:
                out[int(m.group(1))] = p
    return out

def header(data):
    return dict(nent=struct.unpack_from(">I", data, 0xb4)[0],
                entoff=struct.unpack_from(">I", data, 0xb8)[0],
                nblk=struct.unpack_from(">I", data, 0xd0)[0],
                blkoff=struct.unpack_from(">I", data, 0xd4)[0])


def _blocks_ok(path, chain):
    """True iff every block row of `path` resolves to a matching SHA-1 in the chain."""
    import hashlib
    data = open(path, "rb").read()
    h = header(data)
    for b in range(h["nblk"]):
        off, stored, gen, flags = block_row(data, b, h)
        src = chain.get(gen)
        if src is None:
            return False
        with open(src, "rb") as fh:
            fh.seek(off); blob = fh.read(stored)
        if len(blob) != stored or hashlib.sha1(blob).digest() != data[h["blkoff"] + b*0x20 + 12:h["blkoff"] + b*0x20 + 32]:
            return False
    return True


@functools.lru_cache(maxsize=None)
def coherent_gen(stem):
    """Highest generation kept by the coherent rule (build > last kept, all blocks verify).

    The installed estate leaves stale generations behind; the engine prefers the highest
    generation, so registering a stale one breaks reads. tools/pkg_verify.py reports them.
    """
    chain = find_chain(stem)
    last_kept = None
    best = None
    for gen in sorted(chain):
        p = chain[gen]
        build = struct.unpack_from(">I", open(p, "rb").read(0x20), 0x18)[0]
        if last_kept is not None and build <= last_kept:
            continue
        if _blocks_ok(p, chain):
            last_kept = build
            best = gen
    return best if best is not None else max(chain)


def main_path(stem):
    return find_chain(stem)[coherent_gen(stem)]



def block_row(data, i, h):
    off = h["blkoff"] + i * 0x20
    return struct.unpack_from(">IIHH", data, off)

def entry_row(data, i, h):
    off = h["entoff"] + i * 0x10
    return struct.unpack_from(">IIQ", data, off)

@functools.lru_cache(maxsize=None)
def _read(path):
    with open(path, "rb") as fh:
        return fh.read()


def extract_entry(stem, idx):
    chain = find_chain(stem)
    main = chain.get(coherent_gen(stem))
    data = _read(main)
    h = header(data)
    ct, u04, loc = entry_row(data, idx, h)
    blk = loc & 0x3FFF
    bo = ((loc >> 14) & 0x3FFF) * 16
    size = (loc >> 28) & ((1 << 30) - 1)
    out = bytearray()
    cur = 0
    b = blk
    while len(out) < size:
        row = block_row(data, b, h)
        off, stored, gen, flags = row
        src = chain.get(gen, main)
        with open(src, "rb") as fh:
            fh.seek(off)
            raw = fh.read(stored)
        blob = decompress_block(raw) if (flags & 0x100) else raw
        if blob is None:
            raise RuntimeError(f"oodle failed block={b} gen={gen} stem={stem}")
        start = bo if cur == 0 else 0
        out += blob[start:]
        cur += 1
        b += 1
    return bytes(out[:size]), dict(class_tag=ct, u04=u04, size=size, blk=blk)

if __name__ == "__main__":
    stem, idx = sys.argv[1], int(sys.argv[2])
    blob, info = extract_entry(stem, idx)
    print(info, "first 0x60:", blob[:0x60].hex())
