#!/usr/bin/env python3
"""Download a PS3 title's official update packages from Sony's update server (setup.py uses this).

    python3 tools/fetch_updates.py [TITLE_ID] [-o DIR]       (default BLUS31181 -> private/updates)

Sony still serves PS3 title updates: the update list reports status="alive" and gives every package with its size
and SHA-1. For Destiny that is 12 packages, 01.13 to 01.24, 10.7 GB. Completed packages are verified and skipped and
partial downloads resume, so it is safe to run again. Installing them is setup.py's job (oldest first).
"""
import argparse
import hashlib
import os
import re
import ssl
import subprocess
import sys
import urllib.request

UPDATE_LIST = "https://a0.ww.np.dl.playstation.net/tpl/np/{tid}/{tid}-ver.xml"
# Sony's certificate chain for this host does not validate against a modern store; every package is checked against
# the SHA-1 in the list instead, which is the guarantee that matters
SSL_CTX = ssl.create_default_context()
SSL_CTX.check_hostname = False
SSL_CTX.verify_mode = ssl.CERT_NONE
PKG_TRAILER = 32   # the list's SHA-1 covers the package without its last 32 bytes


def sha1_of(path, chunk=1 << 22):
    h = hashlib.sha1()
    remaining = max(os.path.getsize(path) - PKG_TRAILER, 0)
    with open(path, "rb") as f:
        while remaining:
            block = f.read(min(chunk, remaining))
            if not block:
                break
            remaining -= len(block)
            h.update(block)
    return h.hexdigest()


def fetch_manifest(title_id="BLUS31181"):
    """[{url, version, size, sha1sum}, ...] from Sony's update list."""
    with urllib.request.urlopen(UPDATE_LIST.format(tid=title_id), context=SSL_CTX, timeout=30) as r:
        xml = r.read().decode("utf-8", "replace")
    return [dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))
            for m in re.finditer(r"<package\s+([^>]+?)/?>", xml) if "url=" in m.group(1)]


def verified(path, p):
    return (os.path.isfile(path) and os.path.getsize(path) == int(p.get("size", -1))
            and (not p.get("sha1sum") or sha1_of(path) == p["sha1sum"].lower()))


def download(pkgs, folder):
    """Download and verify every package; True when all are present and verified."""
    os.makedirs(folder, exist_ok=True)
    ok = True
    for i, p in enumerate(pkgs, 1):
        dest = os.path.join(folder, p["url"].rsplit("/", 1)[-1])
        label = f"  [{i}/{len(pkgs)}] {p.get('version', '?')} {int(p.get('size', 0)) / 2**20:.0f} MB"
        if verified(dest, p):
            print(f"{label} already downloaded, verified")
            continue
        print(f"{label} downloading")
        rc = subprocess.call(["curl", "-fL", "--insecure", "-C", "-", "--retry", "3", "--retry-delay", "5",
                              "--progress-bar", "-o", dest, p["url"]])
        if rc != 0 or not verified(dest, p):
            print(f"{label} FAILED ({'download error' if rc else 'checksum mismatch'}); run again to resume")
            ok = False
    return ok


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("title_id", nargs="?", default="BLUS31181")
    ap.add_argument("-o", "--out", default=os.path.join(os.path.dirname(__file__), "..", "private", "updates"))
    args = ap.parse_args()
    pkgs = fetch_manifest(args.title_id)
    print(f"{len(pkgs)} packages, {sum(int(p['size']) for p in pkgs) / 2**30:.2f} GB -> {os.path.abspath(args.out)}")
    ok = download(pkgs, args.out)
    print("all packages verified; run setup.py to install them" if ok else "some packages failed")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
