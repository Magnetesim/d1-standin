#!/usr/bin/env python3
"""Generate the weapon -> gear-table index from the installed PS3 01.24 packages.

    python3 tools/item_gear_index.py [-o private/item_gear_index.tsv] [-v]

Output: one row per weapon item definition, ``ci<TAB>gear_index<TAB>note``.  ``ci`` is the row
index of the item in the content table ``ps3_investment_globals_012f`` entry 4673; ``gear_index``
is the index (0..141) into the gear table in the same package, entry 4653 (runtime tag
0x80a5f22d); ``-1`` means "no blueprint" (the game then builds no weapon sobject for that item).

Everything below is read from the user's own dump at run time (tools/pkg_extract.py); nothing is
embedded.  Entries used:

  ps3_investment_globals_012f/4673  6557 x {u32 item hash, u32 0, u32 definition content tag}
  ps3_investment_globals_012f/4653  142 x 24 B {u32 blueprint, u32 model hash, u32 class hash,
                                    u32 ?, u32 sublist count, u32 sublist offset}
  ps3_investment_assets_*          model lists (class tag 0x80800861): 180 B records
                                    {u32 0x8080268a, u32 model hash, ...}; word[3] and word[16]
                                    carry the item kind the model serves
  item definition                  {u32 item hash @0x30, u32 item kind @0x34} in a globals package

The 142 gear entries are weapon *models*, not types: the model hash of the generic entry of a
kind equals the kind hash for fusion, hand cannon, shotgun, sniper, rocket, sidearm, 12496650 and
sword (5e8893e0 is a class); for auto_rifle/pulse_rifle/scout_rifle/machinegun the kind hash is not
in the table at all.  Selection, per kind:

  1. own entry: the lowest-index gear entry whose model hash (word[1]) is a 32-bit word of the
     item definition (other than the kind).  Never fires in 01.24: the only model hash a weapon
     definition contains is its kind, and no item names a specific model.
  2. else the lowest-index entry whose model hash equals the kind (this is what makes the eight
     kinds above load their kind's generic entry);
  3. else the lowest-index entry of the kind's class (word[2]);
  4. for auto_rifle/pulse_rifle/scout_rifle/machinegun: the class comes from the model lists --
     machinegun's list family is the class machine_gun (model == class); the three primaries
     have a private family, and the lowest-index model carrying the kind is the one whose firing
     sequence is the bare kind sequence (entry 5/7/9).

The note names the kind from the FNV-1 preimage found in the model lists' strings
("auto_rifle" -> label "auto"), falling back to "type<high 4 hex digits>".

Requires the dump to be reachable through tools/pkg_extract.py (PKGDIRS / Oodle bridge); see
that module.  Runtime on the 01.24 install: ~20 s.
"""
import argparse
import glob
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
try:
    import pkg_extract as P  # noqa: E402
except ImportError:
    sys.exit("pkg_extract.py not found next to %s -- put this script in tools/ (see tools/pkg_extract.py "
             "for the dump path and the Oodle bridge)" % os.path.basename(__file__))

CONTENT_ENTRY = ("ps3_investment_globals", 0x012F, 4673)   # content table: ci -> {hash, 0, tag}
GEAR_ENTRY = ("ps3_investment_globals", 0x012F, 4653)      # 142-entry gear table
ASSET_PREFIX = "ps3_investment_assets_"
MARKER = 0x8080268A        # model-list record tag
NULL = 0x811C9DC5          # FNV-1 offset basis = "no value"
REC = 45                   # 180 B per model-list record


# ---------------------------------------------------------------- packages
def stem_for_pkg(pkg):
    """Package stem for a content-table package number (pkg = (tag >> 13) & 0x3fff - 0x400)."""
    for d in P.PKGDIRS:
        hits = glob.glob(os.path.join(glob.escape(d), "*_%04x_*.pkg" % pkg))
        if hits:
            return os.path.basename(hits[0]).rsplit("_", 1)[0]
    return None


def tag_entry(tag):
    """Entry blob for a content tag (0x80800000 | pkg << 13 | entry), or None."""
    pkg = ((tag >> 13) & 0x3FFF) - 0x400
    stem = stem_for_pkg(pkg)
    if not stem:
        return None
    try:
        return P.extract_entry(stem, tag & 0x1FFF)[0]
    except Exception:                       # unreadable block / missing generation
        return None


def table(entry):
    """Parse an array record {u32 total, u32 count, u32 stride, u32 0x80800184, u32 count, ...} whose
    elements are `count` fixed-size rows after the 0x20-byte header.  The returned stride is valid only
    when the record is a pure array (content table); the gear table has per-entry sub-arrays after the
    rows and is read with its fixed 24-byte row size."""
    kind, pkg, idx = entry
    stem = "%s_%04x" % (kind, pkg)
    if not P.find_chain(stem):
        raise SystemExit("package %s not found under %s (see PKGDIRS in tools/pkg_extract.py)"
                         % (stem, ", ".join(P.PKGDIRS)))
    blob = P.extract_entry(stem, idx)[0]
    total, count, x8, marker, count2 = struct.unpack_from(">5I", blob, 0)
    if marker != 0x80800184 or count != count2 or count == 0:
        raise SystemExit("%s/%d is not an array record (marker %#x, count %d/%d)"
                         % (stem, idx, marker, count, count2))
    return blob, count, (total - 0x20) // count


# ---------------------------------------------------------------- data
def content_table():
    """[(ci, item hash, definition tag)] -- ci is the row index the game's content index uses."""
    blob, count, stride = table(CONTENT_ENTRY)
    if stride < 12:
        raise SystemExit("content table stride %d < 12" % stride)
    out = []
    for i in range(count):
        h, z, tag = struct.unpack_from(">3I", blob, 0x20 + i * stride)
        out.append((i, h, tag))
    return out


def gear_table():
    """142 rows -> dicts; 'i' is the gear index, 'model' word[1], 'cls' word[2]."""
    blob, count, _ = table(GEAR_ENTRY)
    if count != 142:
        raise SystemExit("gear table has %d entries, expected 142" % count)
    out = []
    for i in range(count):
        w = struct.unpack_from(">6I", blob, 0x20 + 24 * i)
        out.append({"i": i, "words": w, "model": w[1], "cls": w[2]})
    return out


def asset_stems():
    stems = set()
    for d in P.PKGDIRS:
        for p in glob.glob(os.path.join(glob.escape(d), ASSET_PREFIX + "*.pkg")):
            stems.add(os.path.basename(p).rsplit("_", 1)[0])
    return sorted(stems)


def model_lists():
    """Scan the model-list entries: returns
         records: [(package stem, entry index, words[REC])]
         family:  entry index -> word[3] of the null-model record of that list
       Entries are found by extracting the entries of one probe package that carry the marker,
       then using their class tag to scan the other asset packages (fast path)."""
    stems = asset_stems()
    probe = [s for s in stems if s.endswith("_0135")] or stems[:1]
    tags = set()
    for st in probe:
        data = P._read(P.find_chain(st)[P.coherent_gen(st)])
        header = P.header(data)
        for i in range(header["nent"]):
            try:
                blob, info = P.extract_entry(st, i)
            except Exception:
                continue
            if struct.pack(">I", MARKER) in blob:
                tags.add(info["class_tag"])
    if not tags:                            # unusual install: fall back to every asset entry
        tags = None

    records = []
    family = {}
    for st in stems:
        try:
            data = P._read(P.find_chain(st)[P.coherent_gen(st)])
            header = P.header(data)
        except Exception as exc:            # unreadable package: skip, the mapping does not need it
            print("item_gear_index: skipping %s (%s)" % (st, exc), file=sys.stderr)
            continue
        for i in range(header["nent"]):
            ct, _, _ = P.entry_row(data, i, header)
            if tags is not None and ct not in tags:
                continue
            try:
                blob, _ = P.extract_entry(st, i)
            except Exception:
                continue
            mk = struct.pack(">I", MARKER)
            off = blob.find(mk)
            while off >= 0:
                if off + 4 * REC <= len(blob):
                    words = struct.unpack_from(">%dI" % REC, blob, off)
                    if words[1] != 0:
                        records.append((st, i, words))
                        if words[1] == NULL and words[3] not in (0, NULL):
                            family[i] = words[3]
                off = blob.find(mk, off + 4)
    return records, family


# ---------------------------------------------------------------- kind helpers
def kind_fields(words):
    """The two record positions that carry the item kind in 01.24's model lists."""
    return (words[3], words[16])


def entry_strings(tag, cache):
    """Printable strings of the entry a model-list tag points at (tag and tag+1, as the lists do)."""
    if tag in cache:
        return cache[tag]
    out = []
    for t in (tag, tag + 1):
        pkg = ((t >> 13) & 0x3FFF) - 0x400
        stem = stem_for_pkg(pkg)
        if not stem:
            continue
        try:
            blob = P.extract_entry(stem, t & 0x1FFF)[0]
        except Exception:
            continue
        out += [m.decode("ascii", "replace") for m in re.findall(rb"[ -~]{4,}", blob)]
    cache[tag] = out
    return out


def record_strings(words, cache):
    out = []
    for w in words:
        if 0x80A00000 <= w < 0x81000000:
            out += entry_strings(w, cache)
    return out


def ngrams(strings, limit=3):
    """Candidate kind names: runs of up to `limit` alphanumeric tokens joined by '_'."""
    seen = set()
    for s in strings:
        toks = [t for t in re.split(r"[^A-Za-z0-9]+", s) if t]
        for n in range(1, limit + 1):
            for k in range(len(toks) - n + 1):
                name = "_".join(toks[k:k + n])
                if name not in seen:
                    seen.add(name)
                    yield name


def fnv1(s):
    h = 0x811C9DC5
    for c in s.lower().encode():
        h = ((h * 16777619) & 0xFFFFFFFF) ^ c
    return h


def label(name):
    for suffix in ("_rifle", "_launcher"):
        if name.endswith(suffix):
            return name[:-len(suffix)]
    return name


class GearIndex:
    def __init__(self):
        self.entries = gear_table()
        self.by_model = {}
        self.by_class = {}
        for e in self.entries:
            if e["model"] != NULL:
                self.by_model.setdefault(e["model"], []).append(e["i"])
            if e["cls"] != NULL:
                self.by_class.setdefault(e["cls"], []).append(e["i"])
        self.records, self.family = model_lists()
        self.model_rec = {}
        self.kind_recs = {}
        self.list_of = {}
        for st, i, w in self.records:
            model = w[1]
            self.model_rec.setdefault(model, []).append(w)
            self.list_of.setdefault(model, i)
            for k in kind_fields(w):
                if k not in (0, NULL):
                    self.kind_recs.setdefault(k, []).append(w)
        # classes of each entry, so a kind's label can use every model record of its class
        self.class_recs = {}
        for e in self.entries:
            for w in self.model_rec.get(e["model"], []):
                self.class_recs.setdefault(e["cls"], []).append(w)
        self._strcache = {}

    def _lowest(self, idxs):
        return min(idxs) if idxs else -1

    def weapon_kinds(self):
        return set(self.by_model) | set(self.by_class) | set(self.kind_recs)

    def generic(self, kind):
        """Gear index for a weapon kind (see module docstring)."""
        if kind in self.by_model:                                   # 1/2
            return self._lowest(self.by_model[kind])
        if kind in self.by_class:                                   # 3
            return self._lowest(self.by_class[kind])
        # 4: kinds unknown to the table -- use the model lists
        recs = self.kind_recs.get(kind, [])
        lists = {self.list_of[w[1]] for w in recs if w[1] in self.list_of}
        for li in lists:
            fam = self.family.get(li)
            if fam in self.by_class:
                return self._lowest(self.by_class[fam])
        cands = [self.by_model[w[1]][0] for w in recs if w[1] in self.by_model]
        return self._lowest(cands)

    def kind_label(self, kind, gear_i):
        """Name of a kind: FNV-1 preimage among the strings of its class/model records."""
        recs = list(self.kind_recs.get(kind, []))
        if gear_i >= 0:
            cls = self.entries[gear_i]["cls"]
            recs += self.class_recs.get(cls, [])
        strings = []
        for w in recs:
            strings += record_strings(w, self._strcache)
        hits = [n for n in ngrams(strings) if fnv1(n) == kind]
        if hits:
            hits.sort(key=lambda n: (n.count("_"), len(n)))
            return label(hits[0])
        return "type%04x" % (kind >> 16)

    def own_entry(self, def_words, kind):
        """Rule 1: a model hash named by the definition itself (other than the kind's generic)."""
        for w in def_words:
            if w not in (0, NULL, 0x80800184) and w in self.by_model and w != kind:
                return self._lowest(self.by_model[w])
        return -1


def main(argv):
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("-o", "--out", default=os.path.join(os.path.dirname(HERE), "private",
                                                        "item_gear_index.tsv"),
                    help="output TSV (default: <repo>/private/item_gear_index.tsv)")
    ap.add_argument("-v", "--verbose", action="store_true", help="print per-kind counts to stderr")
    args = ap.parse_args(argv)

    rows = {ci: (h, tag) for ci, h, tag in content_table()}
    gi = GearIndex()
    kinds = gi.weapon_kinds()
    out = []
    per_kind = {}
    own = 0
    skipped = 0
    nonweapon = 0
    for ci in sorted(rows):
        h, tag = rows[ci]
        blob = tag_entry(tag)
        if blob is None or len(blob) < 0x38:
            skipped += 1
            continue
        h30, kind = struct.unpack_from(">II", blob, 0x30)
        if h30 != h:
            skipped += 1
            continue
        if kind == NULL or kind not in kinds:
            nonweapon += 1
            continue
        g = gi.generic(kind)
        if g < 0:
            skipped += 1
            continue
        o = gi.own_entry(struct.unpack_from(">%dI" % (len(blob) // 4), blob, 0), kind)
        if o >= 0:
            own += 1
            g = o
        out.append((ci, g, "%s %08x %s" % (gi.kind_label(kind, g), kind,
                                           "own" if o >= 0 else "generic")))
        per_kind[kind] = per_kind.get(kind, 0) + 1

    outdir = os.path.dirname(os.path.abspath(args.out))
    if outdir and not os.path.isdir(outdir):
        os.makedirs(outdir)
    with open(args.out, "w") as fh:
        fh.write("# ci\tgear_index\tnote  (generated by tools/item_gear_index.py from the installed\n"
                 "# packages: index into the 142-entry gear table ps3_investment_globals_012f entry 4653\n"
                 "# (runtime tag 0x%08x); one entry per weapon kind, generic unless named.)\n"
                 % (0x80800000 | (GEAR_ENTRY[1] << 13) | GEAR_ENTRY[2]))
        for ci, g, note in out:
            fh.write("%d\t%d\t%s\n" % (ci, g, note))
    if args.verbose:
        for k, n in sorted(per_kind.items(), key=lambda kv: -kv[1]):
            print("  %08x %4d  %s" % (k, n, gi.kind_label(k, gi.generic(k))), file=sys.stderr)
    print("%d weapon items, %d kinds -> %s (non-weapon definitions: %d, unreadable: %d, own entries: %d)"
          % (len(out), len(per_kind), args.out, nonweapon, skipped, own), file=sys.stderr)


if __name__ == "__main__":
    main(sys.argv[1:])
