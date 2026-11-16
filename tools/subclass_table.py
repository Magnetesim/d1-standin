#!/usr/bin/env python3
"""Generate the stand-in's subclass ability table from the INSTALLED PACKAGES ONLY (release build).

No runtime data: this script reads only the installed packages (no memory captures, no stand-in state files, no
public manifest or a saved savestate. It reads the user's own `ps3_*.pkg` packages (through tools/pkg_extract.py,
which needs the Oodle bridge) and nothing else.

  usage:  python3 gen_subclass_table_release.py [OUTPUT.json]
          D1_PKGDIRS=/path/a:/path/b python3 ...      # default: pkg_extract.PKGDIRS
          D1_OODLE_DIR=/path/to/oodle python3 ...     # default: local/oodle (pkg_extract's)

Output (argv[1], default ./subclass_abilities_release.json): the same shape as subclass_abilities.json for the
fields the stand-in uses:

  {"subclasses": {"Striker": {"item": {"ci": 710, "def_tag": ..., "item_hash": ...},
                              "class_name": "Titan", "element": "arc",
                              "base_blocks": [32, 4, 7, 9, 13],     # [4] selectors: grenade, super, melee,
                              "nodes": {"3": [["d8487db0", []]], ...},   # jump, sprint
                              ...}},
   "constants": {...}}                                            # what came from the constant table below

Everything structural is read from the packages:

  012f/4673  item index        {u32 item hash, u32 0, u32 definition tag} x 6557, at 0x2C;  ci = index + 1
  013x/…     item definition   class 0x80801806; u16 after the LAST 0x808017BD = grid index
  012f/4650  grid registry     1135 rows at 0x20, {u32 0, u32 grid tag};  row = grid index
  0130/…     talent grid       class 0x80803397, 30 nodes: node table at 0x1C, step blocks at 0x64C + 0x40k
  0131/…     node perk table   class 0x80801963, 30 rows, chained tables ending in 0x808018E8 {hash, flags, -1}

The only constants are POSITIONS/IDENTITIES, not ability data (see CONST below): each subclass's item ci, its
class, its element, and two 012f/476 row indexes (the super row and the default-grenade row). Everything else —
the grid, the node order, the perk hashes, the base melee/jump/sprint rows, the [4] layout — is derived.
"""
import json, os, struct, sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.environ.get("D1_ROOT") or os.path.abspath(os.path.join(HERE, ".."))
sys.path.insert(0, os.path.join(ROOT, "tools"))
import pkg_extract as P                                    # package reader (Oodle)
from pathlib import Path

# configurable tool/paths (all optional):
#   D1_ROOT          repo root (default: the directory above tools/)
#   D1_PKGDIRS       ':'-separated package directories (default: pkg_extract.PKGDIRS)
#   D1_OODLE_DIR     directory holding the Oodle DLL (default: pkg_extract's REPO/local/oodle)
#   D1_OODLE_BRIDGE  the liblinoodle3.so bridge (default: pkg_extract's)
if os.environ.get("D1_OODLE_DIR"):
    P.DLLDIR = Path(os.environ["D1_OODLE_DIR"])
if os.environ.get("D1_OODLE_BRIDGE"):
    P.BRIDGE = Path(os.environ["D1_OODLE_BRIDGE"])
if os.environ.get("D1_PKGDIRS"):
    P.PKGDIRS = [p for p in os.environ["D1_PKGDIRS"].split(os.pathsep) if p]

# ---------------------------------------------------------------------------------------------------------------
# Structural constants. Each is a POSITION or an IDENTITY, not game data:
#   ci            item index + 1 in 012f/4673 (a table position)
#   class_name    one of Titan/Hunter/Warlock (selects the melee and jump row below)
#   element       selects the grenade row; the only field the dump does not carry (set per subclass below)
#   super_row     row of 012f/476 (table position) for the subclass's super
#   grenade_row   row of 012f/476 (table position) for the default (progression-0) grenade node
# Melee/jump/sprint rows are per CLASS and are also table positions.
CONST = {
    #    ci    name           class      element  super_row  grenade_row
    708: ("Bladedancer", "Hunter", "arc",   12, 26),
    709: ("Gunslinger",  "Hunter", "solar",  5, 33),
    710: ("Striker",     "Titan",  "arc",    4, 32),
    711: ("Defender",    "Titan",  "void",  15, 28),
    712: ("Sunsinger",   "Warlock", "solar", 11, 24),
    713: ("Voidwalker",  "Warlock", "void",  10, 25),
    4339: ("Nightstalker", "Hunter", "void",  2, 31),
    4341: ("Sunbreaker", "Titan",  "solar", 14, 27),
    4343: ("Stormcaller", "Warlock", "arc",   0, 23),
}
MELEE_ROW = {"Titan": 7, "Hunter": 8, "Warlock": 16}       # 012f/476 rows: one base melee per class
JUMP_ROW = {"Titan": 9, "Hunter": 3, "Warlock": 6}         # Titan Lift, Hunter High Jump, Warlock Glide
SPRINT_ROW = 13
GRID_MARKER = 0x808017BD                                    # the u16 after its last record = grid index
# node step h1 family ids (content values, used only to *locate* the super node and the three grenade nodes)
SUPER_FAMILY = 0x0952A70D
GRENADE_FAMILIES = (0xD613146C, 0xD613146D, 0xD613146E)
NULL_HASH = 0x811C9DC5

STEM_GRIDS = "ps3_investment_globals_0130"                  # talent grids
STEM_NODES = "ps3_investment_globals_0131"                  # node -> perk tables
STEM_TABLES = "ps3_investment_globals_012f"                 # item index + grid registry


# ---------------------------------------------------------------------------------------------------------------
# package access (block cache, one decompression per block)
_PKGS = {}


def Pkg(stem):
    """cached package handle (one block cache per stem for the whole run)"""
    if stem not in _PKGS:
        _PKGS[stem] = _Pkg(stem)
    return _PKGS[stem]


class _Pkg:
    def __init__(self, stem):
        self.stem = stem
        self.chain = P.find_chain(stem)
        self.data = P._read(P.main_path(stem))
        self.h = P.header(self.data)
        self._blocks = {}

    def block(self, i):
        if i not in self._blocks:
            off, n, gen, flags = P.block_row(self.data, i, self.h)
            with open(self.chain[gen], "rb") as fh:
                fh.seek(off)
                raw = fh.read(n)
            self._blocks[i] = P.decompress_block(raw) if flags & 0x100 else raw
        return self._blocks[i]

    def entry(self, i):
        ct, _, loc = P.entry_row(self.data, i, self.h)
        n = (loc >> 28) & ((1 << 30) - 1)
        blk = loc & 0x3FFF
        off = ((loc >> 14) & 0x3FFF) * 16
        out = self.block(blk)[off:]
        while len(out) < n:
            blk += 1
            out += self.block(blk)
        return out[:n], ct

    def nent(self):
        return self.h["nent"]


def u32(b, o):
    return struct.unpack_from(">I", b, o)[0]


def by_tag(tag):
    """(stem, entry, bytes, class) for a content tag 0x80800000 | (pkg << 13) | entry."""
    pk_, ent = (tag >> 13) & 0x3FF, tag & 0x1FFF
    import glob
    for d in P.PKGDIRS:
        for p in glob.glob(os.path.join(glob.escape(d), f"*_{pk_:04x}_*.pkg")):
            stem = os.path.basename(p).rsplit("_", 1)[0]
            b, ct = Pkg(stem).entry(ent)
            return stem, ent, b, ct
    return None


# ---------------------------------------------------------------------------------------------------------------
# content parsers
def item_table():
    """{ci: (item hash, definition tag)} from 012f/4673 (6557 x 12 B at 0x2C; ci = index + 1)."""
    b, _ = Pkg(STEM_TABLES).entry(4673)
    n = u32(b, 4)
    return {i + 1: (u32(b, 0x2C + 12 * i), u32(b, 0x2C + 12 * i + 8))
            for i in range(n) if 0x2C + 12 * i + 12 <= len(b)}


def grid_registry():
    """index -> grid tag from 012f/4650 (1135 rows at 0x20, {u32 0, u32 tag})."""
    b, _ = Pkg(STEM_TABLES).entry(4650)
    return {i: u32(b, 0x20 + 8 * i + 4) for i in range(u32(b, 4))}


def grid_index(defblob):
    i = defblob.rfind(struct.pack(">I", GRID_MARKER))
    return None if i < 0 or i + 6 > len(defblob) else struct.unpack_from(">H", defblob, i + 4)[0]


def parse_grid(b):
    """30 nodes: [{row, col, h1, h2, tag, prog}]; node order == the game's node order."""
    nodes = [dict(row=u32(b, 0x30 + 52 * k + 44) >> 16, col=u32(b, 0x30 + 52 * k + 44) & 0xFFFF)
             for k in range(30)]
    for k in range(30):
        a = 0x64C + 0x40 * k
        if a + 20 + 44 > len(b):
            break
        rec = [u32(b, a + 20 + 4 * i) for i in range(11)]
        nodes[k].update(h1=rec[1], h2=rec[3], tag=rec[7], prog=rec[8])
    return nodes


def tables_in(b):
    """[(addr, count, element class)] for every {0x80800184, count, cls} header in b."""
    out, i = [], 0
    while True:
        i = b.find(b"\x80\x80\x01\x84", i)
        if i < 0:
            return out
        out.append((i, u32(b, i + 4), u32(b, i + 8)))
        i += 1


def parse_node_table(b):
    """30 rows: {h1, h2, perks}; rows at 0x30, 36 B = 3 x 12-B units; the unit {count, rel_off} points at a table
    header at (unit address + rel_off); the chain ends in {0x80800184, n, 0x808018E8} records {hash, flags, -1}."""
    rows = []
    for k in range(30):
        a = 0x30 + 36 * k
        rows.append(dict(h1=u32(b, a), h2=u32(b, a + 28), chain=a + 12 + u32(b, a + 16), perks=[]))
    starts = sorted((r["chain"], k) for k, r in enumerate(rows))
    for (addr, n, cls) in tables_in(b):
        if cls != 0x808018E8:
            continue
        for j in range(n):
            rec = addr + 20 + 12 * j
            if rec + 12 > len(b):
                break
            h = u32(b, rec)
            # a genuine record is {perk hash, flags, stack}; the mis-aligned sub-records of the 4-row
            # effect tables put their *flags* word first (0xNN000000), so require a non-zero low 24 bits
            if h in (NULL_HASH, 0xFFFFFFFF, 0) or (h & 0x00FFFFFF) == 0:
                continue
            best = None
            for (s, k) in starts:
                if s <= rec:
                    best = k
                else:
                    break
            if best is not None:
                rows[best]["perks"].append(h)
    return rows


def find_node_tables():
    """entries of 0131 that are 30-row node->perk tables (class 0x80801963, header count 30)"""
    p = Pkg(STEM_NODES)
    out = []
    for i in range(p.nent()):
        ct, _, loc = P.entry_row(p.data, i, p.h)
        if ct != 0x80801963 or ((loc >> 28) & ((1 << 30) - 1)) < 0x400:
            continue
        b, _ = p.entry(i)
        if u32(b, 8) == 30:
            out.append(i)
    return out


# ---------------------------------------------------------------------------------------------------------------
def main(argv):
    outpath = argv[1] if len(argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                                          "subclass_abilities_release.json")
    itab = item_table()
    reg = grid_registry()
    ntabs = find_node_tables()
    print(f"012f/4673: {len(itab)} items, 012f/4650: {len(reg)} grids, 0131 node tables: {len(ntabs)}")

    grids = []
    for ci in sorted(CONST):
        name, cls, elem, super_row, gren_row = CONST[ci]
        if ci not in itab:
            sys.exit(f"ci {ci}: not in 012f/4673")
        item_hash, def_tag = itab[ci]
        gidx = grid_index(by_tag(def_tag)[2])
        gtag = reg.get(gidx)
        r = by_tag(gtag) if gtag else None
        if r is None:
            sys.exit(f"ci {ci}: grid index {gidx} does not resolve")
        grids.append(dict(ci=ci, name=name, cls=cls, elem=elem, super_row=super_row, gren_row=gren_row,
                          def_tag=def_tag, item_hash=item_hash, gidx=gidx, gtag=gtag, stem=r[0], entry=r[1],
                          nodes=parse_grid(r[2])))
        print(f"  ci {ci:5d} {name:12s} def {def_tag:#010x} grid idx {gidx:3d} -> "
              f"{r[0].split('_')[-1]}/{r[1]}")
    # pair grids <-> node tables by enumeration order (both lists are in item-table order in this dump)
    grids.sort(key=lambda g: g["gidx"])
    ntabs.sort()
    if len(ntabs) != len(grids):
        sys.exit(f"expected {len(grids)} node tables, found {len(ntabs)}")
    for g, e in zip(grids, ntabs):
        g["node_table"] = e
        g["rows"] = parse_node_table(Pkg(STEM_NODES).entry(e)[0])

    out = {"generated_from": "installed ps3 packages only (012f/4673, 012f/4650, 0130 grids, 0131 node tables)",
           "generator": os.path.basename(__file__),
           "constants": {"note": "positions/identities only; see CONST in the script",
                         "melee_row": MELEE_ROW, "jump_row": JUMP_ROW, "sprint_row": SPRINT_ROW,
                         "per_subclass": {ci: {"name": v[0], "class": v[1], "element": v[2],
                                               "super_row": v[3], "grenade_row": v[4]}
                                          for ci, v in CONST.items()}},
           "subclasses": {}}
    for g in grids:
        # the super node is additionally located from the content (family hash) as a cross-check
        base = [g["gren_row"], g["super_row"], MELEE_ROW[g["cls"]], JUMP_ROW[g["cls"]], SPRINT_ROW]
        gren = [dict(node=k, prog=n["prog"], gridpos=[n["row"], n["col"]])
                for k, n in enumerate(g["nodes"])
                if n.get("h1") in GRENADE_FAMILIES and n.get("tag") != 0xFFFFFFFF]
        default_gren = min(gren, key=lambda x: (x["prog"], x["gridpos"][0])) if gren else None
        sup = [k for k, n in enumerate(g["nodes"]) if n.get("h1") == SUPER_FAMILY]
        if len(sup) != 1 or len(gren) != 3:
            print(f"  !! {g['name']}: {len(sup)} super node(s), {len(gren)} grenade node(s) -- check the grid")
        # the constants must agree with the content: the default grenade node is the progression-0 one and the
        # subclass has exactly one super node; if a future dump shifts either, this prints and can be re-derived
        print(f"  {g['name']:12s} default grenade node {default_gren['node'] if default_gren else '-'} "
              f"(prog {default_gren['prog'] if default_gren else '-'}) super node {sup}")
        nodes = {}
        for k, r in enumerate(g["rows"]):
            hs = [h for h in r["perks"]]
            if hs:
                nodes[str(k)] = [[f"{h:08x}", []] for h in hs]    # rows []: unknown without runtime data -> [5]
        out["subclasses"][g["name"]] = dict(
            item=dict(ci=g["ci"], def_tag=g["def_tag"], item_hash=g["item_hash"]),
            class_name=g["cls"], element=g["elem"],
            grid=f"{g['stem'].split('_')[-1]}/{g['entry']}", grid_index=g["gidx"], grid_tag=f"{g['gtag']:#010x}",
            node_table=f"{STEM_NODES.split('_')[-1]}/{g['node_table']}",
            base_blocks=base, nodes=nodes,
            grenade_node=gren, default_grenade_node=(default_gren["node"] if default_gren else None),
            super_node=sup,
        )
    with open(outpath, "w") as fh:
        json.dump(out, fh, indent=1)
    print(f"\n== base blocks (grenade, super, melee, jump, sprint) -> {outpath}")
    for name, d in out["subclasses"].items():
        print(f"   {name:12s} {d['class_name']:7s} {d['element']:5s} {d['base_blocks']}  "
              f"super node(s) {d['super_node']}  grenade nodes {[x['node'] for x in d['grenade_node']]}")


if __name__ == "__main__":
    main(sys.argv)
