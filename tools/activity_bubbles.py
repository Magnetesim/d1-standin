#!/usr/bin/env python3
"""Print an activity's bubble table from its scenario record in the content (see tools/activity_records.py):
+0x34 count, table of {bubble hash, sub count, relative offset} at +0x60, sub-bubble records
{+0 choosable, +4 key, +12 public, +16 / +20 / +24 limits}. usage: activity_bubbles.py INDEX"""
import json, os, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pkg_extract as px

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
a = json.load(open(os.path.join(ROOT, "config/activities.json")))[sys.argv[1]]
h = 0x811C9DC5
for c in a["name"].encode():
    h = (h * 0x01000193 & 0xFFFFFFFF) ^ c
key, stem = struct.pack(">I", h), a["package"]
chain, best = px.find_chain(stem), None
data = px._read(chain[px.coherent_gen(stem)])
nblk, blkoff = struct.unpack_from(">II", data, 0xd0)
for i in range(nblk):
    off, sz, gen, fl = struct.unpack_from(">IIHH", data, blkoff + i * 0x20)
    src = px._read(chain[gen])
    dec = (px.decompress_block(src[off:off + sz]) if fl & 0x100 else None) or src[off:off + sz]
    j = dec.find(key)
    while j >= 4:
        w = struct.unpack_from(">16I", dec, j - 4)
        if w[6] == 0x811C9DC5 and 0 < w[13] <= 64 and (best is None or gen >= best[0]):
            best = (gen, dec[j - 4:j - 4 + w[0]])
        j = dec.find(key, j + 1)
gen, rec = best
n = struct.unpack_from(">I", rec, 0x34)[0]
print(f"{a['name']}: record gen {gen}, {len(rec)} bytes, {n} bubbles; head {rec[0x10:0x34].hex(' ', 4)}")
for b in range(n):
    bh, subs, rel = struct.unpack_from(">III", rec, 0x60 + 12 * b)
    # serialized sub-record S = table row + 8 + rel + 16 (the code's logical base is
    # S - 24): S+0 choosable, S+4 key, S+12 public, S+16 / +20 / +24 limits
    S = 0x60 + 12 * b + 8 + rel + 16
    if subs and S + 28 <= len(rec):
        key, pub, l0, l1, l2 = struct.unpack_from(">I4xB3xIII", rec, S + 4)
        print(f"{b:2d} region {b * 8:3d} hash {bh:08x} choosable {rec[S]} key {key:08x} public {pub} limits {l0},{l1},{l2}")
    else:
        print(f"{b:2d} region {b * 8:3d} hash {bh:08x} subs {subs}")
