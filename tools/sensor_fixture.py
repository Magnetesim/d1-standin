#!/usr/bin/env python3
"""Derive an activity-host spawn fixture (private/ah_sensor_*.json, the format run.sh's server reads) from the installed content packages.

Everything comes from the user's installed packages (plus activities.json for the activity names) - no game-memory
capture, no fixture input. Paths are configurable:

  D1_PKGDIRS    colon-separated package directories  (default: tools/pkg_extract.PKGDIRS)
  D1_ACTIVITIES activities.json path                  (default: <tree>/private/activities.json)

Content chain:
  activities.json entry  -> scenario record in the planet's activity package
                            (FNV-1 of the name at word 1, 0x811c9dc5 at word 6; bubble count +0x34,
                            bubble rows +0x60 {hash, subs, rel}; sub record S = row+8+rel+16, public byte S+12)
  bubble table           -> records {0x22, 0x18, key, idx, tag, 0x80800065, len, "<level>"} (one run per world,
                            idx = bubble index)
  group-list entry       -> 0x80800184 <n> 0x808040d3 0 0 <n tags>: first list = world groups, second = bubble's
  group tag              -> named-globals group object (class 0x8080076e): group hash, name count, `split`
                            (high 16 = number of replicated definitions), per-name {type i7, name}
  definition             -> udt 5 name ref {group hash, i7, index}; schema-B presence is a function of i7.

Usage:
  sensor_fixture.py ACTIVITY [-o OUT.json] [--check FIXTURE] [-v]
  sensor_fixture.py --all OUTDIR [--keep]   (--keep: leave existing ah_sensor_*.json files alone)
  ACTIVITY = activities.json name ("patrol_deltas_com01") or index ("90").
"""
import glob
import json
import os
import re
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import pkg_extract as px  # noqa: E402


# decompressed-block cache over pkg_extract
BLOCK = 0x40000


class Pkg:
    def __init__(self, stem):
        self.stem = stem
        self.chain = px.find_chain(stem)
        self.top = px.coherent_gen(stem)
        self.data = px._read(self.chain[self.top])
        self.h = px.header(self.data)
        self._blocks = {}

    def block(self, i):
        if i not in self._blocks:
            off, stored, gen, flags = px.block_row(self.data, i, self.h)
            src = self.chain.get(gen, self.chain[self.top])
            with open(src, "rb") as fh:
                fh.seek(off)
                raw = fh.read(stored)
            blob = px.decompress_block(raw) if (flags & 0x100) else raw
            self._blocks[i] = blob
        return self._blocks[i]

    def prefetch(self):
        """Decode every block of the package in parallel (the scans below read them all anyway)."""
        todo, raws = [], []
        for i in range(self.h["nblk"]):
            if i in self._blocks:
                continue
            off, stored, gen, flags = px.block_row(self.data, i, self.h)
            with open(self.chain.get(gen, self.chain[self.top]), "rb") as fh:
                fh.seek(off)
                raw = fh.read(stored)
            if flags & 0x100:
                todo.append(i)
                raws.append(raw)
            else:
                self._blocks[i] = raw
        for i, blob in zip(todo, px.decompress_blocks(raws)):
            self._blocks[i] = blob

    def nent(self):
        return self.h["nent"]

    def entry(self, i):
        ct, u04, loc = px.entry_row(self.data, i, self.h)
        blk = loc & 0x3FFF
        bo = ((loc >> 14) & 0x3FFF) * 16
        size = (loc >> 28) & ((1 << 30) - 1)
        out = bytearray()
        b, cur = blk, 0
        while len(out) < size:
            blob = self.block(b)
            start = bo if cur == 0 else 0
            out += blob[start:]
            b += 1
            cur += 1
        return bytes(out[:size]), dict(class_tag=ct, u04=u04, size=size, blk=blk, bo=bo, entry=i)

    def find_block(self, pat):
        self.prefetch()
        return [(i, bl.find(pat)) for i in range(self.h["nblk"])
                for bl in [self.block(i)] if pat in bl]


def stems():
    import glob, re
    s = set()
    for d in px.PKGDIRS:
        for p in glob.glob(os.path.join(glob.escape(d), "*.pkg")):
            s.add(os.path.basename(p).rsplit("_", 1)[0])
    return sorted(s)


GROUP_CLASS = 0x8080076E
TAG_STRING = 0x80800065
TAG_OFFSETS = 0x80800184
TAG_LIST = 0x808040D3
BUBBLE_REC = struct.pack(">I", 0x18)     # second word of a bubble-table record; first word varies (0x22 / 0x27)
# schema-B presence per definition type i7 [V: 5888 entries of the three fixtures, 21 types, 0 mismatches]
HAS_B = {5: False, 6: False, 11: False, 15: False, 16: False, 17: False, 29: False, 32: False, 33: False,
         34: False, 35: False, 40: False, 1: True, 2: True, 3: True, 4: True, 12: True, 22: True, 24: True,
         28: True, 37: True, 39: True}
PHASE = 3
GEN = 0     # world object +17 (replication generation): not in content, 0 in every run so far [U]


def pkgdirs():
    env = os.environ.get("D1_PKGDIRS")
    return env.split(":") if env else list(px.PKGDIRS)


_stems = None


def all_stems():
    global _stems
    if _stems is None:
        s = set()
        for d in pkgdirs():
            for p in glob.glob(os.path.join(glob.escape(d), "*.pkg")):
                s.add(os.path.basename(p).rsplit("_", 1)[0])
        _stems = sorted(s)
    return _stems


def stem_for_pkg(pkg):
    for d in pkgdirs():
        for p in glob.glob(os.path.join(glob.escape(d), f"*_{pkg:04x}_*.pkg")):
            return os.path.basename(p).rsplit("_", 1)[0]
    return None


def planet_stems(stem):
    planet = re.sub(r"_(activities|ambient|destination|globals).*$", "", stem)
    # only the planet's activity packages (*_activities_* / *_ambient_activity*) hold bubble tables and the
    # named-globals groups used here; the much larger destination packages do not, and scanning them is slow
    return [s for s in all_stems() if planet and s.startswith(planet) and "_act" in s
            and not re.search(r"_(de|en|fr|it|jpn|pt|sp)$", s)]


def fnv1(s):
    h = 0x811C9DC5
    for ch in s.encode():
        h = ((h * 16777619) & 0xFFFFFFFF) ^ ch
    return h


class Group:
    """One named-globals group object (content class 0x8080076e)."""

    def __init__(self, blob):
        self.size, self.unk, self.hash, self.split, self.count = struct.unpack_from(">5I", blob, 0)
        self.stride = struct.unpack_from(">I", blob, 0x14)[0]
        self.types = [blob[0x40 + 8 * i] for i in range(self.count)]
        self.ndef = self.split >> 16
        j = blob.find(struct.pack(">I", TAG_STRING), 0x40 + 8 * self.count)
        n = struct.unpack_from(">I", blob, j + 4)[0] if j >= 0 else 0
        self.names = [x.decode("latin1") for x in blob[j + 8:j + 8 + n].split(b"\x00")] if j >= 0 else []

    def name(self, i):
        return self.names[i] if i < len(self.names) else ""

    def defs(self):
        """The replicated definitions: (index = sub, type = i7, name)."""
        return [(i, self.types[i], self.name(i)) for i in range(min(self.ndef, self.count))]


class Content:
    def __init__(self):
        self.pkgs, self.entries, self.groups = {}, {}, {}

    def pkg(self, stem):
        if stem not in self.pkgs:
            try:
                self.pkgs[stem] = Pkg(stem)
            except Exception:  # noqa: BLE001 - missing generation chain
                self.pkgs[stem] = None
        return self.pkgs[stem]

    def entry(self, tag):
        if tag not in self.entries:
            pkg, ent = (tag >> 13) & 0x3FF, tag & 0x1FFF
            p = self.pkg(stem_for_pkg(pkg) or "")
            self.entries[tag] = p.entry(ent) if p and ent < p.nent() else None
        return self.entries[tag]

    def group(self, tag):
        if tag not in self.groups:
            r = self.entry(tag)
            g = None
            if r and r[1]["class_tag"] == GROUP_CLASS and len(r[0]) >= 0x48:
                g = Group(r[0])
                if not (0 < g.count < 20000 and g.stride == 28):
                    g.odd = True if hasattr(g, "odd") else (g.stride != 28)
            self.groups[tag] = g
        return self.groups[tag]


def group_list(c, tag):
    """A group-list entry -> (world group tags, bubble group tags)."""
    r = c.entry(tag)
    if not r:
        return [], []
    blob = r[0]
    lists, i = [], 0
    while i + 20 <= len(blob):
        if struct.unpack_from(">I", blob, i)[0] == TAG_OFFSETS:
            n = struct.unpack_from(">I", blob, i + 4)[0]
            if n < 4096 and i + 20 + 4 * n <= len(blob) and \
                    struct.unpack_from(">I", blob, i + 8)[0] == TAG_LIST:
                lists.append([struct.unpack_from(">I", blob, i + 20 + 4 * t)[0] for t in range(n)])
                i += 20 + 4 * n
                continue
        i += 4
    return lists


def bubble_tables(c, stem):
    """Runs of bubble-table records {u32 hdr, u32 0x18, key, idx(0..n-1), group-list tag, 0x80800065, len, name}."""
    p = c.pkg(stem)
    if not p:
        return []
    p.prefetch()
    recs = []
    word = struct.pack(">I", 0x18)
    for i in range(p.h["nblk"]):
        bl = p.block(i)
        j = bl.find(word, 4)
        while j >= 4:
            st = j - 4                                    # record start
            if st + 36 <= len(bl) and 0x10 <= struct.unpack_from(">I", bl, st)[0] <= 0x40 \
                    and struct.unpack_from(">I", bl, st + 0x14)[0] == TAG_STRING:
                key, idx, tag = struct.unpack_from(">III", bl, st + 8)
                n = struct.unpack_from(">I", bl, st + 0x18)[0]
                if 0 < n < 40 and all(32 <= ch < 127 for ch in bl[st + 0x1c:st + 0x1b + n]):
                    recs.append((i, st, key, idx, tag, bl[st + 0x1c:st + 0x1c + n - 1].decode("latin1")))
            j = bl.find(word, j + 1)
    recs.sort(key=lambda r: (r[0], r[1]))
    runs, cur = [], []
    for r in recs:
        if cur and (r[3] != len(cur) or r[2] != cur[0][2] or r[5] != cur[0][5]):
            runs.append(cur)
            cur = []
        cur.append(r)
    if cur:
        runs.append(cur)
    return [dict(level=r[0][5], key=r[0][2], n=len(r), bubbles={x[3]: x[4] for x in r}) for r in runs]


def groups_of(c, stems):
    out = {}
    for stem in stems:
        p = c.pkg(stem)
        if not p:
            continue
        for i in range(p.nent()):
            if px.entry_row(p.data, i, p.h)[0] != GROUP_CLASS:
                continue
            blob = p.entry(i)[0]
            if len(blob) < 0x48:
                continue
            g = Group(blob)
            g.entry, g.stem = i, stem           # discovery order = content build order
            if 0 < g.count < 20000 and g.stride == 28 and (g.hash not in out or g.count > out[g.hash].count):
                out[g.hash] = g
    return out


def scenario(c, stem, name):
    """-> (bubble hashes, public flags) for an activity name in a package."""
    key = struct.pack(">I", fnv1(name))
    p = c.pkg(stem)
    if not p:
        return None
    p.prefetch()
    best = None
    for i in range(p.h["nblk"]):
        dec = p.block(i)
        j = dec.find(key)
        while j >= 4:
            if j + 60 > len(dec):
                j = dec.find(key, j + 1)
                continue
            w = struct.unpack_from(">16I", dec, j - 4)
            if w[6] == 0x811C9DC5 and 0 < w[13] <= 64 and w[0] < len(dec):
                best = dec[j - 4:j - 4 + w[0]]
            j = dec.find(key, j + 1)
    if not best:
        return None
    n = struct.unpack_from(">I", best, 0x34)[0]
    hashes, public = [], []
    for b in range(n):
        bh, subs, rel = struct.unpack_from(">III", best, 0x60 + 12 * b)
        hashes.append(bh)
        S = 0x60 + 12 * b + 8 + rel + 16
        public.append(bool(subs) and S + 40 <= len(best) and best[S + 12] == 1)
    return hashes, public


SIGHTING = re.compile(r"^patrol_sighting_([a-z0-9_]+)\.pm_bubble$")
RACE = re.compile(r"^com_patrol_race_([a-z0-9_]+)\.")


def scoped_token(name, i7):
    """The bubble token a definition name is scoped to (None = global)."""
    m = SIGHTING.match(name)
    if m and i7 == 28:
        return m.group(1)
    m = RACE.match(name)
    if m and i7 in (4, 24):
        return m.group(1)
    return None


def pick_lifetime(groups, actname=""):
    cand = [(g, i, n) for g in groups.values() for i, t, n in g.defs()
            if t == 16 and (n.endswith("_lifetime") or n.split(".")[-1] == "lifetime")]
    if not cand:
        return None, None
    token = actname.split("_")[0] if actname else ""
    g, i, _ = max(cand, key=lambda x: (x[0].ndef, bool(token) and token in x[2]))
    return g, i


def pick_slot(groups):
    cand = [g for g in groups.values() if any(t == 12 and n.startswith("players[0]") for _, t, n in g.defs())]
    if not cand:
        return None, None
    g = max(cand, key=lambda g: g.count)
    return g, next(i for i, t, n in g.defs() if t == 12 and n.startswith("players[0]"))


_CACHE = {}


def planet_info(stems):
    """Cached per planet: (Content, {hash: Group}, [(stem, run, world lists, world group hashes)])."""
    key = tuple(stems)
    if key not in _CACHE:
        c = Content()
        groups = groups_of(c, stems)
        contig = []
        for stem in stems:
            for run in bubble_tables(c, stem):
                ls = group_list(c, run["bubbles"].get(0, 0))
                hs = [c.group(t).hash for l in ls for t in l if c.group(t)]
                contig.append((stem, run, ls, hs, True))
        worlds = {}
        for stem in stems:
            for run in bubble_tables(c, stem):
                for idx, tag in run["bubbles"].items():
                    ls = group_list(c, tag)
                    if not ls:
                        continue
                    wkey = tuple(ls[0])
                    w = worlds.setdefault(wkey, dict(stem=stem, level=run["level"], bubbles={}))
                    w["bubbles"].setdefault(idx, tag)
        runs = list(contig)
        for wkey, w in worlds.items():
            ls = group_list(c, w["bubbles"][min(w["bubbles"])])
            hs = [c.group(t).hash for l in ls for t in l if c.group(t)]
            run = dict(n=len(w["bubbles"]), bubbles=w["bubbles"], level=w["level"], key=None)
            runs.append((w["stem"], run, ls, hs, False))
        _CACHE[key] = (c, groups, runs)
    return _CACHE[key]


def build(act, verbose=False):
    """-> (fixture dict, diagnostics string) or (None, reason)."""
    a = load_activities().get(str(act))
    if a is None:
        for k, v in load_activities().items():
            if v["name"] == act:
                a = v
                break
    if a is None or "package" not in a:
        return None, "no scenario-record package in activities.json"
    stems = planet_stems(a["package"])
    c, groups, all_runs = planet_info(stems)
    lg, li = pick_lifetime(groups, a["name"])
    if lg is None:
        return None, "no activity-lifetime definition in the planet content"
    sg, si = pick_slot(groups)
    rec = scenario(c, a["package"], a["name"])
    if rec is None:
        return None, "scenario record not found"
    bhashes, public = rec
    # per-bubble group lists: the run whose world list contains the lifetime group
    runs = [(stem, run, ls, contig) for stem, run, ls, hs, contig in all_runs if lg.hash in hs]
    if verbose:
        print(f"{a['name']}: {len(groups)} group objects, {len(runs)} bubble table(s) with the lifetime group, "
              f"{len(bhashes)} bubbles, public {[b for b, p in enumerate(public) if p]}")
    if not runs:
        return None, "no bubble table whose world group list contains the lifetime group"
    # prefer a contiguous table of exactly the activity's bubble count, then a complete world map
    runs.sort(key=lambda r: (r[1]["n"] != len(bhashes), not r[3], abs(r[1]["n"] - len(bhashes))))
    stem, run, wlists, _c = runs[0]
    if run["n"] != len(bhashes):
        diag_tbl = f"bubble table has {run['n']} entries, activity has {len(bhashes)} bubbles"
    else:
        diag_tbl = ""
    world = wlists[0] if wlists else []
    tokens = set()
    for g in groups.values():
        for _, _, nm in g.defs():
            t = scoped_token(nm, 0)
            m = SIGHTING.match(nm) or RACE.match(nm)
            if m:
                tokens.add(m.group(1))
    tok_of_hash = {fnv1(t): t for t in tokens}
    # terminal groups: type-4 `_terminal` definitions are instantiated in one bubble per group, in content order
    terms = []
    for t in world:
        g = c.group(t)
        if g and any(tt == 4 and n.endswith("._terminal") for _, tt, n in g.defs()):
            terms.append((t, groups.get(g.hash) or g))     # the discovered object carries its entry index
    terms.sort(key=lambda x: getattr(x[1], "entry", 0))    # entry order = content build order
    pub_regions = sorted(b * 8 for b, p in enumerate(public) if p)
    term_assign = {g.hash: pub_regions[i] for i, (_, g) in enumerate(terms) if i < len(pub_regions)}
    bhash_set = set(bhashes)
    fx = {"gen": GEN, "hash": lg.hash, "sub": li, "phase": PHASE,
          "slot": {"hash": sg.hash, "i7": sg.types[si], "sub": si}, "regions": {}, "names": {}, "exits": {}}
    diag = [diag_tbl] if diag_tbl else []
    for b in range(len(bhashes)):
        region = b * 8
        want_tok = tok_of_hash.get(bhashes[b])
        tag = run["bubbles"].get(b)
        lists = group_list(c, tag) if tag else []
        if not lists:
            lists = [world]
            diag.append(f"bubble {b}: no table entry, world list used")
        lists = [list(l) for l in lists]
        gtags = [(t, False) for t in lists[0]]
        if not public[b]:                      # the private world instantiates the bubble's own groups
            for l in lists[1:]:
                gtags += [(t, True) for t in l]
        else:
            diag.append(f"bubble {b}: public, bubble groups ignored")
        rows, seen = [], set()
        for t, bub_owned in gtags:
            g = c.group(t)
            if not g or g.hash in seen:
                continue
            seen.add(g.hash)
            glob, scoped = [], []
            for i, i7, nm in g.defs():
                if (g.hash, i) == (lg.hash, li):
                    continue
                m = RACE.match(nm) or SIGHTING.match(nm)
                if m and fnv1(m.group(1)) not in bhash_set:
                    continue                     # dangling bubble name: not registered in this activity
                tok = scoped_token(nm, i7)
                if tok is not None and tok != want_tok:
                    continue
                is_term = i7 == 4 and nm.endswith("._terminal")
                if is_term and term_assign.get(g.hash) != region:
                    continue
                if i7 not in HAS_B:
                    diag.append(f"unknown definition type {i7} ({nm})")
                    continue
                (scoped if (tok is not None or bub_owned or is_term) else glob).append(
                    [g.hash, i7, i, True, HAS_B[i7]])
            if bub_owned and len(scoped) > 1:
                # load order: the bubble's object filters / timer definitions register before the rest [U]
                pres = [k for k, x in enumerate(scoped) if x[1] in (5, 11, 17, 33)]
                scoped = [scoped[k] for k in pres] + [x for k, x in enumerate(scoped) if k not in pres]
            rows += glob + scoped
        fx["regions"][str(region)] = rows
    return fx, "; ".join(sorted(set(diag)))


def check(fx, path):
    ref = json.load(open(path))
    ok, lines = True, []
    for k in ("gen", "hash", "sub", "phase", "slot"):
        if fx[k] != ref[k]:
            ok = False
            lines.append(f"  MISMATCH {k}: derived {fx[k]} vs fixture {ref[k]}")
    exact = diff = 0
    for r, rows in ref["regions"].items():
        got = [tuple(x) for x in fx["regions"].get(r, [])]
        want = [tuple(x) for x in rows]
        if got == want:
            exact += 1
        else:
            diff += 1
            gs, ws = set(got), set(want)
            lines.append(f"  region {r}: fixture {len(want)}, derived {len(got)}, "
                         f"missing {len(ws - gs)}, extra {len(gs - ws)}"
                         + (f" first missing {sorted(ws - gs)[:3]}" if ws - gs else ""))
    return ok, exact, diff, lines


def load_activities():
    return json.load(open(os.environ.get("D1_ACTIVITIES", os.path.join(ROOT, "private", "activities.json"))))


def main(argv):
    if not argv or argv[0] in ("-h", "--help"):
        sys.exit(__doc__)
    verbose = "-v" in argv or "--verbose" in argv
    out = argv[argv.index("-o") + 1] if "-o" in argv else None
    ref = argv[argv.index("--check") + 1] if "--check" in argv else None
    allout = argv[argv.index("--all") + 1] if "--all" in argv else None
    keep = "--keep" in argv
    if allout:
        acts = load_activities()
        os.makedirs(allout, exist_ok=True)
        ok = 0
        for k, v in sorted(acts.items(), key=lambda kv: int(kv[0])):
            if "package" not in v:
                continue
            path = os.path.join(allout, f"ah_sensor_{v['name']}.json")
            if keep and os.path.exists(path):
                print(f"  {k:3s} {v['name']:26s} kept existing file")
                ok += 1
                continue
            fx, why = build(k)
            if not fx:
                print(f"  {k:3s} {v['name']:26s} SKIP: {why}")
                continue
            json.dump(fx, open(path, "w"), separators=(",", ":"))
            ok += 1
            print(f"  {k:3s} {v['name']:26s} {len(fx['regions'])} bubbles, "
                  f"{sum(len(x) for x in fx['regions'].values())} entries" + (f"  [{why}]" if why else ""))
        print(f"{ok} fixtures -> {allout}")
        return
    skip = {out, ref}
    args = [x for x in argv if not x.startswith("-") and x not in skip]
    act = args[0] if args else ""
    fx, why = build(act, verbose)
    if not fx:
        sys.exit(f"cannot derive {act}: {why}")
    print(f"lifetime    {fx['hash']:#010x} i7=16 sub={fx['sub']}")
    print(f"player slot {fx['slot']['hash']:#010x} i7={fx['slot']['i7']} sub={fx['slot']['sub']}")
    if why:
        print("diagnostics:", why)
    if ref:
        ok, exact, diff, lines = check(fx, ref)
        print(f"check {ref}: {exact} exact region(s), {diff} differing, scalars {'OK' if ok else 'DIFFER'}")
        print("\n".join(lines))
    if out:
        json.dump(fx, open(out, "w"), separators=(",", ":"))
        print("wrote", out)


if __name__ == "__main__":
    main(sys.argv[1:])
