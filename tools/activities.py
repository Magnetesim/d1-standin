#!/usr/bin/env python3
"""Generate the activity host's activities.json from the user's own installed packages.

What is derived, and from where
--------------------------------
* name, hash (job/activity hash) and level: the Director/activity definition table,
  `ps3_investment_globals_0130` entry 3487 (338 records class 0x8080181e; 294 carry a C-string
  identifier at +0x30, the hash at +0x04 and the level in the high byte of +0x64).
* checksum (private activity client), public_checksum (public activity client), bubbles and
  package: the activity's *scenario record*. That record is a plain content-package entry: its
  first byte starts the entry, word 0 is the entry size, word 1 is FNV-1 of the identifier,
  words 2/3 are the two checksums (the checks are `*(rec + 8 + ac[+16]*4)` with ac[+16] = 0/1),
  +0x34 is the bubble count and +0x4c is the bubble-table header
  {marker 0x80800184, count, class 0x8080060c}. The records live in the activity content
  packages (`*_activit*`, `*_activ_*`, `*_act_*`: patrols and patrol variants, story mission
  scenarios, tower scenarios, ambient/raid/pvp scenarios), in any generation of the chain --
  every copy of a record agrees on all four
  values, and the copy that starts a package entry is the one the runtime content registry
  serves (handle = 0x80800000 | pkg << 13 | entry).
* public (optional, --public): the bubbles whose serialized public byte is set, as regions
  (region = bubble * 8). This is the set the host uses to classify a public landing; the
  reference file only carries it for the two patrols it was measured on.
* sensor (optional): only emitted when a spawn fixture `ah_sensor_<name>.json` exists in
  --sensor-dir (fixtures are per-user, made from your packages by sensor_fixture.py; they are not shipped).
* start (optional): NOT a content field. It is the host's choice of a bubble (see
  they are not in the content); supply --starts to set them.

Usage
-----
  python3 tools/activities.py                       # -> private/activities.json
  python3 tools/activities.py --out /tmp/a.json --diff private/activities.json
  python3 tools/activities.py --public --starts private/activity_starts.json
  python3 tools/activities.py --stems 'activit'     # fast: only activity-ish package stems
  python3 tools/activities.py --no-public           # strict shape parity with the old file

Writes only the --out file (and prints the diff against --diff). Needs tools/pkg_extract.py and
the Oodle bridge it documents (local/oodle + liblinoodle3.so), like tools/activity_records.py.
"""
import argparse
import concurrent.futures as cf
import glob
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)          # the tree this script sits in (tools/ -> tree root)

TABLE_PACKAGE = "ps3_investment_globals_0130"
TABLE_ENTRY = 3487
TABLE_RECORD_CLASS = 0x808018A7
TABLE_RECORD_COUNT = 338
BUBBLE_MARK = 0x80800184
BUBBLE_CLASS = 0x8080060C
FNV_EMPTY = 0x811C9DC5


def _load_pkg_extract():
    """tools/pkg_extract.py from this tree, from $PWD/tools, or from $D1_TOOLS."""
    cands = [HERE, os.path.join(HERE, "tools"), os.path.join(os.getcwd(), "tools")]
    d = HERE
    for _ in range(4):                       # this script may sit in <tree>/tools or anywhere below it
        cands += [d, os.path.join(d, "tools")]
        d = os.path.dirname(d)
    if os.environ.get("D1_TOOLS"):
        cands.insert(0, os.environ["D1_TOOLS"])
    for d in cands:
        if os.path.exists(os.path.join(d, "pkg_extract.py")):
            sys.path.insert(0, d)
            import pkg_extract
            return pkg_extract
    sys.exit("activities.py: cannot find tools/pkg_extract.py (looked in: %s); "
             "set D1_TOOLS to the directory that holds it" % ", ".join(dict.fromkeys(cands)))


px = _load_pkg_extract()


def fnv1(s: str) -> int:
    """FNV-1 32-bit, the identifier hash the content uses (`fnv1(name) == record word 1`)."""
    h = FNV_EMPTY
    for c in s.encode():
        h = (h * 0x01000193 & 0xFFFFFFFF) ^ c
    return h


# --------------------------------------------------------------------------- activity table
def activity_table():
    """[{idx, hash, name, level, content}] for every named record of the definition table."""
    blob, info = px.extract_entry(TABLE_PACKAGE, TABLE_ENTRY)
    marker = struct.pack(">I", BUBBLE_MARK)
    arr, i = None, blob.find(marker)
    while i >= 0:
        cnt, cls = struct.unpack_from(">II", blob, i + 4)
        if cls == TABLE_RECORD_CLASS and cnt == TABLE_RECORD_COUNT:
            arr = i
            break
        i = blob.find(marker, i + 1)
    if arr is None:
        raise SystemExit(f"{TABLE_PACKAGE}/{TABLE_ENTRY}: record array "
                         f"({BUBBLE_MARK:#x}, {TABLE_RECORD_COUNT}, {TABLE_RECORD_CLASS:#x}) not found")
    base = arr + 0x14

    def cstr(p):
        if not 0 <= p < len(blob):
            return None
        e = blob.find(b"\x00", p)
        if e < 0:
            e = p + 64
        try:
            return blob[p:e].decode("ascii")
        except UnicodeDecodeError:
            return None

    out = []
    for k in range(TABLE_RECORD_COUNT):
        h, off = struct.unpack_from(">II", blob, base + k * 8)
        p = base + k * 8 + off                       # record pointer is self-relative
        f = lambda o: struct.unpack_from(">I", blob, p + o)[0]
        name = cstr(p + 0x30 + f(0x30)) if f(0x30) else None
        if not name:
            continue
        out.append(dict(idx=k, hash=h, name=name, level=f(0x64) >> 24, content=f(0x60)))
    return out, dict(info, entry=TABLE_ENTRY)


# --------------------------------------------------------------------------- scenario records
def _scan_stem(stem):
    """Every scenario record in one package chain: entry-start copies flagged with their entry."""
    out = []
    chain = px.find_chain(stem)
    if not chain:
        return stem, out
    top = px.coherent_gen(stem)
    data = px._read(chain[top])
    hdr = px.header(data)
    nblk, blkoff = struct.unpack_from(">II", data, 0xd0)
    entries = {}
    for e in range(hdr["nent"]):
        ct, _, loc = px.entry_row(data, e, hdr)
        entries[(loc & 0x3FFF, ((loc >> 14) & 0x3FFF) * 16)] = e
    try:
        pkg = int(stem[-4:], 16)
    except ValueError:
        pkg = None
    for b in range(nblk):
        off, stored, gen, flags = struct.unpack_from(">IIHH", data, blkoff + b * 0x20)
        src = px._read(chain[gen]) if gen in chain else data
        blob = px.decompress_block(src[off:off + stored]) if flags & 0x100 else src[off:off + stored]
        if not blob:
            continue
        a = blob.find(struct.pack(">I", BUBBLE_MARK))
        while a >= 0:
            p = a - 0x4C
            if p >= 0 and a + 12 <= len(blob):
                cnt, cls = struct.unpack_from(">II", blob, a + 4)
                if cls == BUBBLE_CLASS and 0 < cnt <= 64:
                    w = struct.unpack_from(">16I", blob, p)
                    if 0x40 < w[0] <= 0x40000 and w[6] == FNV_EMPTY and w[13] == cnt:
                        entry = entries.get((b, p))
                        out.append(dict(stem=stem, block=b, gen=gen, hash=w[1],
                                        checksum=w[2], public=w[3], bubbles=cnt, size=w[0],
                                        entry=entry, tag=(0x80800000 | (pkg << 13) | entry)
                                        if (entry is not None and pkg is not None) else None))
            a = blob.find(struct.pack(">I", BUBBLE_MARK), a + 1)
    px._read.cache_clear()          # do not keep whole packages cached (the estate is ~17 GB)
    return stem, out


def scenario_records(stem_re, jobs):
    """Scan the installed estate; returns {name hash: [record, ...]} (entry-start copies only)."""
    stems = sorted({os.path.basename(p).rsplit("_", 1)[0] for d in px.PKGDIRS
                    for p in glob.glob(os.path.join(glob.escape(d), "*.pkg"))})
    stems = [s for s in stems if stem_re.search(s)]
    found, n = {}, 0
    with cf.ProcessPoolExecutor(max(1, jobs)) as ex:
        for stem, rows in ex.map(_scan_stem, stems):
            n += len(rows)
            for r in rows:
                if r["entry"] is not None and r["tag"] is not None:
                    found.setdefault(r["hash"], []).append(r)
    return found, len(stems), n


def _stem_rank(stem):
    """Prefer the plain `*_activities_*` stem over an `*_ambient_*` twin (both carry the same record)."""
    return ("ambient" in stem, stem)


def pick(found, name):
    """The single scenario record for an identifier, or (None, reason)."""
    rows = found.get(fnv1(name))
    if not rows:
        return None, "no scenario record in any installed package"
    vals = {(r["checksum"], r["public"], r["bubbles"]) for r in rows}
    if len(vals) > 1:
        return None, "conflicting scenario records: %s" % sorted(
            (hex(r["checksum"]), hex(r["public"]), r["bubbles"], r["stem"]) for r in rows)
    return min(rows, key=lambda r: _stem_rank(r["stem"])), None


def bubble_table(stem, entry, size):
    """(bubble count, [(region, authoring-name hash, public)]) read from the record entry itself."""
    rec, info = px.extract_entry(stem, entry)
    if len(rec) != size or struct.unpack_from(">I", rec, 0)[0] != size:
        raise SystemExit(f"{stem}/{entry}: entry is {len(rec)} B, record header says {size}")
    n = struct.unpack_from(">I", rec, 0x34)[0]
    bubbles = []
    for b in range(n):
        h, subs, rel = struct.unpack_from(">III", rec, 0x60 + 12 * b)
        # serialized sub-record S = table row + 8 + relative offset + 16; S+0 choosable, +4 key,
        # +12 public, +16/+20/+24 limits 
        s = 0x60 + 12 * b + 8 + rel + 16
        pub = bool(subs and s + 28 <= len(rec) and rec[s + 12])
        bubbles.append((b * 8, h, pub))     # region = bubble * 8, h = FNV-1 of its name
    return n, bubbles


# --------------------------------------------------------------------------- build
def build(args):
    table, tinfo = activity_table()
    print(f"activity table: {TABLE_PACKAGE}/{tinfo['entry']} ({tinfo['size']} B, class "
          f"{tinfo['class_tag']:#x}); {len(table)} of {TABLE_RECORD_COUNT} records named")
    found, nstems, nrows = scenario_records(re.compile(args.stems), args.jobs)
    print(f"scenario records: {nrows} found in {nstems} package chains, "
          f"{sum(len(v) for v in found.values())} entry-start records for {len(found)} identifiers")

    starts = {}
    if args.starts:
        if not os.path.exists(args.starts):
            sys.exit(f"activities.py: --starts {args.starts}: no such file")
        starts = {str(k): v for k, v in json.load(open(args.starts)).items()}

    acts, notes = {}, []
    for rec in table:
        key = str(rec["idx"])
        a = dict(name=rec["name"], hash=f"0x{rec['hash']:08x}", level=rec["level"])
        scen, why = pick(found, rec["name"])
        if scen is None:
            notes.append((key, rec["name"], "checksum", why))
        else:
            nbub, bubbles = bubble_table(scen["stem"], scen["entry"], scen["size"])
            public = [region for region, _h, pub in bubbles if pub]
            a["checksum"] = f"0x{scen['checksum']:08X}"
            a["public_checksum"] = f"0x{scen['public']:08X}"
            a["bubbles"] = scen["bubbles"]
            a["package"] = scen["stem"]
            if nbub != scen["bubbles"]:
                notes.append((key, rec["name"], "bubbles", f"entry table says {nbub}, header {scen['bubbles']}"))
            if args.public and public:
                a["public"] = public
            if key in starts:
                want = starts[key]
                if isinstance(want, str):        # a bubble name: the content owns name -> region
                    hits = [region for region, h, _pub in bubbles if h == fnv1(want)]
                    if not hits:
                        notes.append((key, rec["name"], "start",
                                      f"bubble name {want!r} (FNV-1 {fnv1(want):#010x}) is not in this "
                                      f"record's bubble table"))
                    else:
                        a["start"] = hits[0]
                else:                            # a plain region number
                    a["start"] = want
                    if public and want not in public:
                        notes.append((key, rec["name"], "start",
                                      f"region {want} is not a public bubble {public}"))
        sensor = os.path.join(args.sensor_dir, f"ah_sensor_{rec['name']}.json") if args.sensor_dir else None
        if sensor and os.path.exists(sensor):
            a["sensor"] = f"{args.sensor_prefix}/{os.path.basename(sensor)}"
        acts[key] = a
    return acts, notes, table


# --------------------------------------------------------------------------- diff
def diff(generated, reference):
    """Every mismatch between the generated file and a reference, with a reason."""
    rows = []
    for key in sorted(set(generated) | set(reference), key=int):
        g, r = generated.get(key), reference.get(key)
        if g is None:
            rows.append((key, "*", "missing", "", "activity absent from the generated file"))
            continue
        if r is None:
            rows.append((key, "*", "extra", "", "activity absent from the reference"))
            continue
        fields = list(r) + [f for f in g if f not in r]
        for field in fields:
            if g.get(field) == r.get(field):
                continue
            if field in g and field not in r:
                why = ("'public' is content-derived (bubble table public byte; region = bubble * 8), "
                       "the reference carries it only where it was measured")
                if field != "public":
                    why = "not in the reference file; recovered from the content now (see notes)"
            elif field == "start":
                why = "host policy, not a content field: pass --starts (the landing area is the host's choice)"
            elif field == "sensor":
                why = "no spawn fixture (ah_sensor_<name>.json) in the sensor directory"
            elif field == "checksum":
                why = "no scenario record in any installed package (see notes)"
            else:
                why = "value differs"
            rows.append((key, r.get("name", g.get("name")), field, r.get(field), g.get(field), why))
    return rows


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default=os.path.join(ROOT, "private", "activities.json"),
                    help="output file (default: <tree>/private/activities.json)")
    ap.add_argument("--diff", default=None,
                    help="reference file to diff against (default: --out if it exists)")
    ap.add_argument("--starts", default=None,
                    help='JSON {index: region} of start regions for --out -- not a content field')
    ap.add_argument("--public", dest="public", action="store_true", default=True,
                    help="emit 'public' (the public bubble regions the content defines; default)")
    ap.add_argument("--no-public", dest="public", action="store_false",
                    help="omit 'public' (strict shape parity with the pre-2026-11 file)")
    ap.add_argument("--sensor-dir", default=os.path.join(ROOT, "private"),
                    help="directory searched for ah_sensor_<name>.json (default: <tree>/private)")
    ap.add_argument("--sensor-prefix", default="private",
                    help="path prefix written into the 'sensor' field (default: private)")
    ap.add_argument("--stems", default=".", help="regex the package stems must match (default: all)")
    ap.add_argument("--jobs", type=int, default=min(16, os.cpu_count() or 4))
    args = ap.parse_args()

    acts, notes, table = build(args)
    with_ck = sum(1 for a in acts.values() if "checksum" in a)
    print(f"\n{len(acts)} activities, {with_ck} with a checksum")
    if args.public:
        n_pub = sum(1 for a in acts.values() if a.get("public"))
        print(f"{n_pub} activities carry a content-defined 'public' bubble list")

    ref = args.diff
    if ref is None and os.path.exists(args.out):
        ref = args.out
    if ref:
        print(f"\ndiff against {ref}:")
        rows = diff(acts, json.load(open(ref)))
        for row in rows:
            print("  %-4s %-28s %-9s reference=%-24s generated=%s  [%s]" % (
                row[0], str(row[1])[:28], row[2], str(row[3])[:24], row[4], row[5]))
        if not rows:
            print("  no differences")
        print(f"  {len(rows)} difference(s)")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    with open(args.out, "w") as f:
        f.write(json.dumps(acts, indent=1))          # same formatting as the existing file
    print(f"wrote {args.out}")

    if notes:
        print("\nnotes:")
        for key, name, field, why in notes:
            print(f"  {key:>4} {name:<30} {field:<8} {why}")


if __name__ == "__main__":
    main()
