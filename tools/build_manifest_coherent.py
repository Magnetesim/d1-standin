#!/usr/bin/env python3
"""Build the CdnContentManifest from the *coherent* installed estate.

Installing every Sony update leaves stale generation files behind: later updates re-base a
chain (new _2/_3...) and stop shipping the old higher generations, but nothing deletes them.
The engine prefers the highest generation, so registering a stale _N breaks content reads
("hash verification failed for package" -> "Problem reading game content").
Rule per (stem): walk generations upward; keep a file iff its content build is greater than the
last kept generation's and every block hash verifies (tools/pkg_verify.py); skip otherwise.
usage: [WITH_GEN0=1] build_manifest_coherent.py [OUT]   (default local/tls/manifest-coherent.bin)
       WITH_GEN0=1 also declares the disc-resident _0 generations - the configuration that boots."""
import glob, os, re, struct, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
from build_manifest import PKG, UNP, parse, varint
# The disc *_unpatchable_0 packages share (id, gen) with the engine-registered unp2 files
# (ids 0x42/0x49/0x179): declaring them collides at registration.
UNP = set(UNP) | {"ps3_client_bootstrap_unpatchable_0", "ps3_ui_startup_unpatchable_0", "ps3_ui_bootflow_unpatchable_0"}
DISC = os.environ.get("D1_DISC_PACKAGES", os.path.join(HERE, "../game/PS3_GAME/USRDIR/packages"))
WITH_GEN0 = os.environ.get("WITH_GEN0") == "1"   # also declare each chain's disc-resident _0
from pkg_verify import verify
out = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "..", "local", "tls", "manifest-coherent.bin")
chains = {}
srcs = glob.glob(PKG + "/*.pkg") + (glob.glob(glob.escape(DISC) + "/*.pkg") if WITH_GEN0 else [])
for p in srcs:
    stem = re.sub(r"_\d+\.pkg$", "", os.path.basename(p))
    chains.setdefault(stem, []).append(p)
keep, dropped = [], []
for stem, files in sorted(chains.items()):
    rows = sorted(((parse(p), p) for p in files), key=lambda t: t[0]["gen"])
    last_kept = 0
    for r, p in rows:
        build = struct.unpack(">I", open(p, "rb").read(0x20)[0x18:0x1c])[0]
        _, good, bad, miss, _ = verify(p)
        ok = build > last_kept and bad == 0 and miss == 0
        (keep if ok else dropped).append((r, build))
        if ok:
            last_kept = build
sel = sorted((r for r, _ in keep if r["loc"] in (0, 1) and r["base"] not in UNP), key=lambda r: (r["pid"], r["loc"], r["gen"]))
body = bytearray()
for r in sel:
    pb = r["base"].encode()
    p = b"\x08" + varint(0) + b"\x12" + varint(len(pb)) + pb + b"\x18" + varint(r["pid"]) + b"\x20" + varint(r["guid"])
    body += b"\x1a" + varint(len(p)) + p
body += b"\x2a\x00"
open(out, "wb").write(body)
with open(out + ".dropped.txt", "w") as fh:
    for r, b in sorted(dropped, key=lambda t: t[0]["base"]): fh.write(f"{r['base']} build={b}\n")
print(f"files={sum(len(v) for v in chains.values())} kept={len(keep)} dropped={len(dropped)} manifest_packages={len(sel)} bytes={len(body)} out={out}")
