#!/usr/bin/env python3
"""Fill config/activities.json from the content packages: each activity's scenario record (found by the FNV-1 hash of
its name at record word 1, word 6 = 0x811c9dc5) holds the activity checksum for the private activity client (word
2), for the public one (word 3) and the bubble count (+0x34). The records live in the
`*_activities_*` packages; the newest coherent generation of each chain is used (tools/pkg_extract.py).
Controls: patrol_deltas_com01 = 0x6a556a7f / 0xe354f1ea / 22, as read from the running game.
usage: [JOBS=16] activity_records.py [STEM_REGEX]   (default: every package whose name contains "activit")"""
import glob, json, os, re, struct, sys
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import pkg_extract as px

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
F = os.path.join(ROOT, "config/activities.json")
acts = json.load(open(F))


def fnv1(s):
    h = 0x811C9DC5
    for c in s.encode():
        h = (h * 0x01000193 & 0xFFFFFFFF) ^ c
    return h


by_hash = {struct.pack(">I", fnv1(a["name"])): k for k, a in acts.items()}
rx = re.compile(sys.argv[1] if len(sys.argv) > 1 else "activit")
stems = sorted({re.sub(r"_\d+\.pkg$", "", os.path.basename(p)) for d in px.PKGDIRS
                for p in glob.glob(os.path.join(glob.escape(d), "*.pkg")) if rx.search(os.path.basename(p))})
pattern = re.compile(b"|".join(re.escape(h) for h in by_hash))


def scan(stem):
    """Records in one package chain (worker process; the Oodle bridge needs its own working directory)."""
    out = []
    chain = px.find_chain(stem)
    top = px.coherent_gen(stem)
    data = px._read(chain[top])
    nblk, blkoff = struct.unpack_from(">II", data, 0xd0)
    for i in range(nblk):
        off, sz, gen, fl = struct.unpack_from(">IIHH", data, blkoff + i * 0x20)
        src = px._read(chain[gen]) if gen in chain else data
        dec = (px.decompress_block(src[off:off + sz]) if fl & 0x100 else None) or src[off:off + sz]
        for m in pattern.finditer(dec):
            j = m.start()
            if j < 4 or j + 60 > len(dec):
                continue
            w = struct.unpack_from(">16I", dec, j - 4)
            if w[6] == 0x811C9DC5 and 0 < w[13] <= 64:
                out.append((by_hash[m.group()], w[2], w[3], w[13], stem, gen))
    return out


found = {}
if __name__ == "__main__":
    from concurrent.futures import ProcessPoolExecutor
    with ProcessPoolExecutor(int(os.environ.get("JOBS", "16"))) as ex:
        for rows in ex.map(scan, stems):
            for k, c, pb, b, stem, gen in rows:
                found.setdefault(k, set()).add((gen, c, pb, b, stem))
os.chdir(ROOT)
n = 0
for k, v in sorted(found.items(), key=lambda t: int(t[0])):
    # a rewritten record leaves its old copy in an older generation's block: the newest block wins
    newest = max(x[0] for x in v)
    v = {x for x in v if x[0] == newest}
    if len({x[1:4] for x in v}) != 1:
        print(f"{k} {acts[k]['name']}: ambiguous {sorted(v)}")
        continue
    _, c, p, b, stem = sorted(v)[0]
    acts[k].update({"checksum": f"0x{c:08X}", "public_checksum": f"0x{p:08X}", "bubbles": b, "package": stem})
    n += 1
json.dump(acts, open(F, "w"), indent=1)
print(f"{n} of {len(acts)} named activities have a record; saved {F}")
for k in ("90", "91", "92", "93", "94"):
    print(k, {x: acts[k].get(x) for x in ("name", "checksum", "public_checksum", "bubbles")})
