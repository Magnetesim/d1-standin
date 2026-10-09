#!/usr/bin/env bash
# Starts the two TLS listeners the title needs before it opens its game connection:
#   127.0.0.1:443   sign-on: answers with config/signon-reply.bin (points the title at the manifest below)
#   127.0.0.1:8443  content manifest: private/manifest.bin (built by setup.py from your own install)
# Port 443 is privileged, so the first one runs under sudo. Stop both with Ctrl-C.
cd "$(dirname "${BASH_SOURCE[0]}")" || exit 1
if ss -ltn 2>/dev/null | grep -qE '127\.0\.0\.1:(443|8443) '; then
    echo "port 443 or 8443 is already in use - an earlier listener is still running (ss -ltnp | grep 8443)" >&2; exit 1
fi
for f in private/tls.crt private/tls.key private/manifest.bin; do
    [[ -f $f ]] || { echo "missing $f - run setup.py first" >&2; exit 1; }
done
# Both request-capture folders are created here, as you: the sign-on listener runs as root and would otherwise
# create a folder the manifest listener cannot write to (the title then reports NIGHTINGALE).
mkdir -p private/requests-signon private/requests-manifest
common=(--cert private/tls.crt --key private/tls.key --dedup-captures)
python3 tools/tls_probe_server.py --port 8443 "${common[@]}" --capture-dir private/requests-manifest \
    --reply-body-file private/manifest.bin &
manifest_pid=$!
# Background jobs of a script ignore Ctrl-C, so stop the manifest listener explicitly on every way out.
trap 'kill $manifest_pid 2>/dev/null; exit' EXIT INT TERM
sudo python3 tools/tls_probe_server.py --port 443 "${common[@]}" --capture-dir private/requests-signon \
    --reply-body-file config/signon-reply.bin
