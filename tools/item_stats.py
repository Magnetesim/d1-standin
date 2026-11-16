#!/usr/bin/env python3
"""Per-weapon base stats from the PS3 01.24 item definitions -> private/item_stats.tsv.

    python3 tools/item_stats.py [CI ...]      # default: every ci in private/item_gear_index.tsv

Each weapon definition holds an array {u32 0x80800184, u32 count, u32 0x8080190C, 0, 0, elements} of
8-byte elements {u8 stat key, 3 pad, i32 value} (investment stat values; e.g. Fatebringer 2221:
28:15 12:60 13:40 ...). The stand-in sends them per equipped weapon in the family-0 peer view
0x80801855 fields [13]/[14]/[15] ({i8 key, i32 value} x 16, primary/special/heavy), which the in-world
loadout uses for the weapon's behaviour.
"""
import os
import struct
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import item_art  # noqa: E402  (changes the working directory; use absolute paths below)

ARRAY, STATS = 0x80800184, 0x8080190C


def stats(blob):
    marker = struct.pack(">I", ARRAY)
    i = blob.find(marker)
    while i >= 0:
        n, tag = struct.unpack_from(">II", blob, i + 4)
        if tag == STATS and i + 20 + 8 * n <= len(blob):
            d = blob[i + 20:i + 20 + 8 * n]
            return [(d[k * 8], struct.unpack(">i", d[k * 8 + 4:k * 8 + 8])[0]) for k in range(n)]
        i = blob.find(marker, i + 4)
    return []


def main(argv):
    if argv:
        cis = [int(a) for a in argv]
    else:
        with open(os.path.join(ROOT, "private", "item_gear_index.tsv")) as fh:
            cis = [int(line.split("\t")[0]) for line in fh if line[0].isdigit()]
    rows = item_art.content_rows()
    out = ["# ci\tstats (key:value,...)  weapon definition array 0x8080190C {u8 stat key, i32 value}, sent per",
           "# equipped weapon in peer view 0x80801855 [13]/[14]/[15] (primary/special/heavy). tools/item_stats.py."]
    for ci in cis:
        pairs = stats(item_art.definition(rows[ci][1]))
        if pairs:
            out.append(f"{ci}\t" + ",".join(f"{k}:{v}" for k, v in pairs))
    with open(os.path.join(ROOT, "private", "item_stats.tsv"), "w") as fh:
        fh.write("\n".join(out) + "\n")
    print(f"{len(out) - 2} of {len(cis)} items have stats", file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
