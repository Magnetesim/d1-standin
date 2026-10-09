#!/usr/bin/env python3
"""Build a CdnContentManifest protobuf body from the installed PS3 package estate.

Schema:
  CdnContentManifest := Package* guid
  Package := 1a <len> 08 <varint offer_id> 12 <len> <path> 18 <varint id> 20 <varint guid>
  guid    := 2a <len> <bytes>   (present; must equal engine-config key 101, default empty)

Package.path is the on-disk stem (register_package builds "packages/<stem>.pkg").
Exit: writes local/tls/manifest-powered.bin and prints a summary.
"""
import os, struct, glob, sys

PKG = os.path.expanduser(
    "~/.config/rpcs3/dev_hdd0/game/BLUS31181/USRDIR/a0000001/packages")
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(ROOT, "local", "tls", "manifest-powered.bin")

# Engine hard-codes registration of these three names (with the name pattern
# "%s_%s.pkg"): ps3_client_bootstrap_unp2_0, ps3_ui_startup_unp2_0,
# ps3_ui_bootflow_unp2_0.  Their unp1 twins share (id,gen) with a different GUID,
# so both variants are excluded from the manifest to avoid -64.
UNP = {
    "ps3_client_bootstrap_unp1_0", "ps3_client_bootstrap_unp2_0",
    "ps3_ui_startup_unp1_0", "ps3_ui_startup_unp2_0",
    "ps3_ui_bootflow_unp1_0", "ps3_ui_bootflow_unp2_0",
}


def varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def parse(f):
    base = os.path.basename(f)[:-4]
    with open(f, "rb") as fh:
        h = fh.read(0x140)
    return dict(
        base=base,
        pid=struct.unpack(">H", h[4:6])[0],
        guid=struct.unpack(">Q", h[8:16])[0],
        gen=struct.unpack(">H", h[0x20:0x22])[0],
        loc=struct.unpack(">H", h[0x22:0x24])[0],
        magic=struct.unpack(">H", h[0:2])[0],
    )


def main():
    locales = {int(x) for x in (sys.argv[1].split(",") if len(sys.argv) > 1 else ["0", "1"])}
    files = sorted(glob.glob(PKG + "/*.pkg"))
    rows = [parse(f) for f in files]
    sel = [r for r in rows if r["loc"] in locales and r["base"] not in UNP]
    sel.sort(key=lambda r: (r["pid"], r["loc"], r["gen"]))

    body = bytearray()
    for r in sel:
        p = bytearray()
        p += b"\x08" + varint(0)                # f1 offer_id = 0 (classless -> always registered)
        pb = r["base"].encode()
        p += b"\x12" + varint(len(pb)) + pb     # f2 path = on-disk stem
        p += b"\x18" + varint(r["pid"])         # f3 package_id = header[0x04]
        p += b"\x20" + varint(r["guid"])        # f4 guid = header[0x08] (BE u64)
        body += b"\x1a" + varint(len(p)) + bytes(p)  # f3 packages
    body += b"\x2a\x00"                          # f5 guid = empty string (must match key 101)

    os.makedirs(os.path.dirname(OUT), exist_ok=True)
    with open(OUT, "wb") as fh:
        fh.write(body)

    print("locales:", sorted(locales))
    print("packages declared:", len(sel))
    print("body bytes:", len(body))
    print("hex-head:", body[:24].hex(" "))
    print("hex-tail:", body[-24:].hex(" "))
    print("out:", OUT)


if __name__ == "__main__":
    main()
