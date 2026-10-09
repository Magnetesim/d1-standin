#!/usr/bin/env python3
"""Offline block-hash check of installed D1 PS3 .pkg files (big-endian; layout per the PS4
sibling's content-and-packages.md s2): header [0xd0]=block count, [0xd4]=block table offset;
block record 0x20 = {u32 file_offset, u32 stored_size, u16 gen, u16 flags, u8 sha1[20]}.
The bytes live in the generation `gen` file of the same stem.
usage: pkg_verify.py <glob-or-stem>...   (stems resolved under the installed packages dir)"""
import glob, hashlib, os, re, struct, sys
PKG = os.path.expanduser("~/.config/rpcs3/dev_hdd0/game/BLUS31181/USRDIR/a0000001/packages")
DISC = os.environ.get("D1_DISC_PACKAGES", os.path.join(os.path.dirname(os.path.abspath(__file__)), "../game/PS3_GAME/USRDIR/packages"))
def locate(stem, gen):
    for d in (PKG, DISC):
        q = os.path.join(d, f"{stem}_{gen}.pkg")
        if os.path.exists(q): return q
    return None
def hdr(p):
    h = open(p, "rb").read(0x140)
    return dict(magic=struct.unpack(">H", h[0:2])[0], ver=struct.unpack(">H", h[2:4])[0],
                pid=struct.unpack(">H", h[4:6])[0], gen=struct.unpack(">H", h[0x20:0x22])[0],
                nblk=struct.unpack(">I", h[0xd0:0xd4])[0], blkoff=struct.unpack(">I", h[0xd4:0xd8])[0],
                size=struct.unpack(">I", h[0x13c:0x140])[0])
def verify(path):
    h = hdr(path); stem = re.sub(r"_\d+\.pkg$", "", os.path.basename(path))
    data = open(path, "rb").read()
    bad = ok = missing = 0; first_bad = []
    for i in range(h["nblk"]):
        r = data[h["blkoff"] + i * 0x20: h["blkoff"] + (i + 1) * 0x20]
        off, sz, gen, fl = struct.unpack(">IIHH", r[:12]); want = r[12:32]
        src = locate(stem, gen)
        if not src:
            missing += 1; continue
        with open(src, "rb") as fh:
            fh.seek(off); blob = fh.read(sz)
        got = hashlib.sha1(blob).digest()
        if got == want and len(blob) == sz: ok += 1
        else:
            bad += 1
            if len(first_bad) < 3: first_bad.append((i, gen, hex(off), sz, len(blob), got.hex()[:16], want.hex()[:16]))
    return h, ok, bad, missing, first_bad
if __name__ == "__main__":
    args = sys.argv[1:] or ["*"]
    for a in args:
        for p in sorted(glob.glob(a if "/" in a else os.path.join(PKG, a if a.endswith(".pkg") else a + "*.pkg"))):
            h, ok, bad, miss, fb = verify(p)
            flag = "" if bad == 0 and miss == 0 else "  <-- BAD" if bad else "  <-- missing-gen"
            print(f"{os.path.basename(p):48s} magic={h['magic']:#06x} v{h['ver']} id={h['pid']:#06x} gen={h['gen']} "
                  f"blocks={h['nblk']} ok={ok} bad={bad} missing={miss} size_ok={h['size']==os.path.getsize(p)}{flag}")
            for b in fb: print("     bad block", b)
