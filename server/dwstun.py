#!/usr/bin/env python3
"""Stand-in for dev-stun.demonware.net, the NAT-discovery service Destiny 1 (PS3) talks to.

What the two roles do:

  primary    answers 1E 03 00        and 14 02 00 00
  secondary  answers 14 02 00 02
  neither answers 14 02 00 01, 14 02 00 03, or the 29-byte 0E keepalive

The roles are split across two addresses, and the client finds the second one by incrementing the
first (there is only one A record; dev-stun is a CNAME to stun.us.demonware.net). So redirecting
dev-stun to 127.0.0.1 means the title will look for its secondary on 127.0.0.2.

Reply layout, 15 bytes:

    <opcode+1> <b1> <b2> <addrA:4> <portA:2> <addrB:4> <portB:2>

addrA is a constant the real service always sends. addrB depends on the opcode:

    0x1E  -> the client's own mapped address and port   (STUN MAPPED-ADDRESS)
    0x14  -> the secondary server's address             (STUN CHANGED-ADDRESS)

Getting that second case wrong is what kept the title from ever probing our secondary: we were
handing back the client's address where it expected to be told where the alternate server lives.

Silence is meaningful here. A client discovers its NAT type partly from which probes go
unanswered, so this deliberately does NOT reply to everything - use --answer-all to override.

The 2.x connection manager also opens a TCP BAP connection to the advertised mapped endpoint
after its readiness checks pass. Use --tcp-sink to accept that connection and log the client bytes
without guessing at a BAP response; UDP STUN behavior is unchanged.
"""
import argparse
import json
import subprocess
import selectors
import socket
import struct
import sys
import time

# First address/port pair in every reply. This is the caller's own public address as the
# server sees it (MAPPED-ADDRESS); it is NOT a server constant. Override per-run with
# --public-ip; the placeholder below is only a fallback for offline testing.
PEER_ADDR = "203.0.113.1"
PEER_PORT = 0x020C

# Port reported alongside the secondary address. Observed as 02 0C in reference captures.
ALT_REPORT_PORT = 0x020C

START = time.monotonic()


def log(msg: str) -> None:
    print(f"[{time.monotonic() - START:8.3f}] {msg}", flush=True)


def hx(b: bytes) -> str:
    return " ".join(f"{c:02X}" for c in b)


# --- 2.x (2.3.1.1) reply -------------------------------------------------------------------
# The reply to the 4-byte 0x00 probe:
#
#   00 01 00 01 | addr ^ key32 | port ^ key16 | key32 | key16
#
# The key is carried in the packet. Decoding with the key yields the caller's own public address - it is MAPPED-ADDRESS,
# obfuscated. The 2014 beta sent the same field in the clear. So this is the beta payload
# wrapped in an XOR layer, not a new protocol.
XOR_KEY32 = 0x76C3F6BC


def build_reply_2x(req: bytes, mapped_ip: str, mapped_port: int) -> bytes:
    """MAPPED-ADDRESS: tell the client the address and port we saw it from, XOR-obfuscated.

    This field looked like a fixed server constant at first because every probe in testing came
    from the same machine, so the same value came back every time - and the 2014 beta sent that
    same value in the clear, which made it look persistent across versions. It is not a constant:
    it is the caller's own public address, which is the entire point of STUN.
    """
    key16 = XOR_KEY32 & 0xFFFF
    addr = struct.unpack(">I", socket.inet_aton(mapped_ip))[0]
    return (req[:4]
            + struct.pack(">I", addr ^ XOR_KEY32)
            + struct.pack(">H", mapped_port ^ key16)
            + struct.pack(">I", XOR_KEY32)
            + struct.pack(">H", key16))


def build_reply(req: bytes, mapped_ip: str, mapped_port: int, alt_ip: str) -> bytes:
    head = bytes([(req[0] + 1) & 0xFF, req[1], req[2]])
    part_a = socket.inet_aton(PEER_ADDR) + struct.pack(">H", PEER_PORT)

    if req[0] == 0x1E:
        # MAPPED-ADDRESS: tell the client how we see it.
        part_b = socket.inet_aton(mapped_ip) + struct.pack(">H", mapped_port)
    else:
        # CHANGED-ADDRESS: tell the client where the alternate server is.
        part_b = socket.inet_aton(alt_ip) + struct.pack(">H", ALT_REPORT_PORT)

    return head + part_a + part_b


def should_answer(role: str, changed_port: bool, req: bytes) -> bool:
    """Report the address and port split the client expects.

    For 2.x, each CHANGE-REQUEST must reach the endpoint that actually satisfies it. Keeping a
    3075 socket open but answering subtype 04 on 3074 would let a malformed topology appear to
    work and hides which destination the client selected.
    """
    op = req[0]
    sub = req[3] if len(req) > 3 else 0

    # 2.3.1.1 (the retail 2.x client) opens with a 4-byte 0x00 probe that the 2014 beta never
    # sent, and retries it, so it is a request expecting a reply. The 29-byte 0x0E keepalive is
    # unchanged from the beta. Opcodes 0x1E/0x14 belong to the beta handshake and are kept so
    # both clients still work against this server.
    # 2.x subtypes are CHANGE-REQUEST bits: the primary answers 00 01 00 01 on :3074 and 00 01 00 04 on :3075,
    # and stays SILENT on 00 01 00 02 (the change-IP test, which only a second address should answer).
    # Answering 02 from the primary is wrong and mirrors the mistake made on the beta.
    if op == 0x00:
        expected = {
            ("primary", False): 0x01,
            ("primary", True): 0x04,
            ("secondary", False): 0x02,
            ("secondary", True): 0x06,
        }
        return sub == expected[(role, changed_port)]
    if changed_port:
        return False
    if role == "primary":
        return op == 0x1E or (op == 0x14 and sub == 0x00)
    return op == 0x14 and sub == 0x02


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--primary", default="127.0.0.1")
    ap.add_argument("--secondary", default="127.0.0.2",
                    help="the client derives this itself as primary+1")
    ap.add_argument("--port", type=int, default=3074)
    ap.add_argument("--change-port", type=int, default=None,
                    help="alternate port for 2.x change-port tests (default: --port + 1)")
    ap.add_argument("--public-ip", default=None,
                    help="advertise this as the client's mapped address instead of the source IP")
    ap.add_argument("--map-port", type=int, default=None,
                    help="advertise this as the client's mapped port instead of the source port")
    ap.add_argument("--answer-all", action="store_true",
                    help="reply to every packet, ignoring the selective silence the client expects")
    ap.add_argument("--tcp-sink", action="store_true",
                    help="also accept and log TCP connections on the primary/secondary map port")
    ap.add_argument("--tcp-reply-hex", action="append", default=[], metavar="HEX",
                    help="with --tcp-sink, send one hex frame per successive client request; repeat for multiple replies")
    ap.add_argument("--tcp-greet-hex", action="append", default=[], metavar="HEX",
                    help="with --tcp-sink, send one hex frame to each accepted client immediately, before any request")
    ap.add_argument("--bap-channel", action="store_true",
                    help="derive the mode-1 secure channel from the chain's 0x1a reply, decrypt client "
                         "frames, and answer echo (0xfa) and investment 503 (0x0a) once the chain is spent")
    ap.add_argument("--bap-conn-key", default="00" * 16, metavar="HEX",
                    help="16-byte AES key the client uses to open the 0x1a record (conn+0x2261; from SignOn)")
    ap.add_argument("--bap-account-soid", default="0xD100000000000001",
                    help="u64 account id returned in the investment-503 reply")
    ap.add_argument("--bap-silent-investment", default="", metavar="IDS",
                    help="comma-separated investment message ids to leave unanswered (e.g. 503)")
    ap.add_argument("--bap-state-file", default=None, metavar="PATH",
                    help="write the mode-1 channel state (record, counters, unanswered requests) here after every frame")
    ap.add_argument("--bap-resume", default=None, metavar="PATH",
                    help="savestate resume: on accept, restore the channel from this state file, skip the chain, "
                         "and answer its unanswered requests (the reloaded client does not resend)")
    ap.add_argument("--bap-503-hex", default=None, metavar="HEX",
                    help="raw investment-503 response body (after the u16 message id) instead of present+u64")
    ap.add_argument("--bap-family4-push", default="account", choices=["account", "empty", "none"],
                    help="QueueZ family-4 push after the account subscription ack (empty = object_count 0 probe)")
    ap.add_argument("--bap-account-fields", type=int, default=None,
                    help="top-level field count of the account RSAT (PS4 01.29: 25)")
    ap.add_argument("--bap-account-from", default=None, metavar="PATH",
                    help="cold boot with the characters (identities, creations) of a saved state file: "
                         "the roster and family-4 baseline name them, so the client goes to character select")
    ap.add_argument("--bap-auto-resume", action="store_true",
                    help="when a client reconnects after a mode-1 session ended (e.g. RPCS3's reload right "
                         "after saving a state), continue that session instead of starting a new handshake")
    ap.add_argument("--bap-char-stats", default=None, metavar="LEVEL,LIGHT,EMBLEM",
                    help="serve the character appearance block (level, Light stat, emblem content index; "
                         "emblem 'none' leaves slot 12 empty), e.g. 40,385,1512")
    ap.add_argument("--bap-peer", action="store_true",
                    help="answer the family 0/2 subscriptions with the peer view + directory objects "
                         "instead of empty baselines")
    ap.add_argument("--bap-items", default="", metavar="CI@SLOT[e],...",
                    help="inventory: content index at profile slot (93 = first Primary), 'eN' = equipped at ordinal N; "
                         "pushed as a family-4 delta by --bap-resume-push")
    ap.add_argument("--bap-progressions", default="", metavar="ORD:POINTS,...",
                    help="profile progressions (field 8), e.g. 117:346000 = character_level 40 (sibling ordinal)")
    ap.add_argument("--social-activities", default="", metavar="INDEX,...",
                    help="activity indices (max 5) given a matchmaking group limit through an engine-config delta in the "
                         "0x0013 reply; --social-delta-file = the SignOn reply body whose f4.3 delta is repeated")
    ap.add_argument("--social-delta-file", default="config/signon-reply.bin")
    ap.add_argument("--mm-tuning", default="", metavar="FIELD=VALUE,...",
                    help="matchmaking configuration tuning values (0x002b f4.1 varint fields 1..9), e.g. 4=0xffffffff")
    ap.add_argument("--bap-profile-dense", default="", metavar="SUB,...",
                    help="kind-1 unlock flags owned in the profile dense store (field 11) by sub-index")
    ap.add_argument("--bap-account-dense10", default="", metavar="SUB,...",
                    help="unlock flags owned in account field 10 (2560 x 2-bit) by sub-index")
    ap.add_argument("--bap-account-dense", default="", metavar="SUB,...",
                    help="kind-2 unlock flags owned in the account dense store (field 14) by sub-index")
    ap.add_argument("--bap-unlock-values", default="", metavar="IDX:VAL,...",
                    help="unlock values in the account sparse list (field 12 [2]), e.g. 34:12354")
    ap.add_argument("--bap-ah-proxy", default=None, metavar="IP:PORT",
                    help="activity-host proxy address in the 0x0011 reply (default 127.0.0.1:3074)")
    ap.add_argument("--ah-listen", type=int, default=None, metavar="PORT",
                    help="TCP activity-host listener (point --bap-ah-proxy at it): 0x1e -> 0x1f, 0x19 -> 0x1a (the chain's key record), "
                         "then server/activity_host.py answers manager request 6 and logs the rest")
    ap.add_argument("--ah-pushes", default=None, metavar="UDT,...", help="udts pushed on the join (default 4)")
    ap.add_argument("--ah-refresh-pushes", default=None, metavar="UDT,...",
                    help="udts pushed on the client's udt 17 state refresh (default 0,1,11)")
    ap.add_argument("--ah-bubble-count", type=int, default=None, help="udt 1 bubble count (scenario +0x34)")
    ap.add_argument("--ah-bubble-chosen", default=None, metavar="I,...", help="udt 1 bubbles marked chosen (0)")
    ap.add_argument("--ah-public-checksum", default=None, help="activity checksum in the public AH's udt 1 "
                    "(default activity_host.PUBLIC_CHECKSUM; the private value as a control: 0x6A556A7F)")
    ap.add_argument("--ah-activity-fixed", action="store_true", help="answer every launch with the default activity "
                    "(to reach the loading flight of an activity whose checksums are not known yet and probe them)")
    ap.add_argument("--ah-no-travel", action="store_true", help="do not answer the client's udt 21 bubble-travel request")
    ap.add_argument("--ah-public-mode", type=int, default=1, help="region record [2][1] with --ah-public (1 or 2)")
    ap.add_argument("--ah-sensor-route", default="all", choices=["all", "first", "public"],
                    help="with --ah-public: which activity-host connection carries the udt 5 spawn pushes")
    ap.add_argument("--ah-sensor-file", default=None, help="JSON {gen, hash, sub, phase}: push udt 5 when it changes")
    ap.add_argument("--ah-regrant-slots", action="store_true", help="grant all entity indices on every udt 0 "
                    "(control: reproduces the in-world crash)")
    ap.add_argument("--ah-sensor-auto", default=None, help="fixture JSON: send the udt 5 spawn sequence by itself")
    ap.add_argument("--ah-phase", type=int, default=None, help="activity lifetime phase sent in udt 5 (fixture: 3; "
                    "the spawn gate also accepts 6)")
    ap.add_argument("--ah-sensor-delay", type=float, default=None, help="seconds after the 2nd state refresh (6)")
    ap.add_argument("--ah-start", default=None, help="udt 1 initial region REGION[,SPAWNHASH]")
    ap.add_argument("--bap-peer-addr-reply", action="store_true", help="answer BAP 0x12c with 0x12d OK")
    ap.add_argument("--peer-connect", default="R,I,0,O", help="connect-response u32 fields: I = the request's [4] "
                    "(the client's channel id), R = its [0], O = ours (0x5AFE), or numbers; empty = no reply")
    ap.add_argument("--peer-membership", default="", help="after the join-request send a membership-update probe "
                    "with these peer states HOST,JOINER (candidate: 10,5)")
    ap.add_argument("--peer-host", default="", help="act as session host for the joiner: noplayer | player "
                    "(+ ,values for parameters 0/1; + ,time to answer time-synchronize)")
    ap.add_argument("--peer-params", default=None, help="after the membership update queue a type 37 parameters-update "
                    "without bodies: first mask (e.g. 1; 0 = the reset-only negative control)")
    ap.add_argument("--peer-port", type=int, default=3077, help="UDP port of the public-AH peer stand-in")
    ap.add_argument("--peer-reply", type=lambda x: int(x, 0), default=0x0C, help="answer NAT-traversal 0x0A/0x0C with this type")
    ap.add_argument("--ah-public", default=None, help="64-bit public activity-host id put in the udt 11 region "
                    "record (public bubbles; experimental)")
    ap.add_argument("--ah-slice", default=None, help="udt 11 region record REGION,TOKEN[,PEER] (default 0,1,0; "
                    "token 0 = no record)")
    ap.add_argument("--ah-udt11-bool-bits", type=int, default=None, help="bits per bool in udt 11 (default 1)")
    ap.add_argument("--ah-udt1-bool-bits", type=int, default=None, help="bits per bool in udt 1 (default 1)")
    ap.add_argument("--ah-activity-name", default=None, help="udt 1 activity name (default patrol_deltas_com01)")
    ap.add_argument("--ah-activity-checksum", default=None, help="udt 1 activity checksum (default 0xd07bb2d7)")
    ap.add_argument("--ah-activity-index", type=int, default=None, help="udt 1 activity index (default 90)")
    ap.add_argument("--ah-id", default=None, metavar="U64",
                    help="activity-host id in message 7 (default activity_host.AH_ID)")
    ap.add_argument("--bap-current-activity", type=int, default=None, metavar="IDX",
                    help="profile field 6 [0] current-activity index (e.g. 8 = cosmo_patrols_1)")
    ap.add_argument("--bap-family4-extra", action="store_true",
                    help="also serve the family-4 type-2 and type-4 (unlocks) objects, key-only")
    ap.add_argument("--bap-destination", default=None, metavar="HASH",
                    help="profile customization field [10] (last_orbited_destination), e.g. 0x932015bb")
    ap.add_argument("--bap-unlock-flags", default="", metavar="IDX,...",
                    help="unlock-flag indices marked owned in the investment 205/503 unlock object")
    ap.add_argument("--bap-item-art", default="", metavar="TSV",
                    help="art arrangements from tools/item_art.py output into the appearance equipment [3]")
    ap.add_argument("--bap-art-dyes", nargs="?", const="all", default="", choices=["all", "class"],
                    help="with --bap-item-art, also serve the definition dyes in the appearance equipment [5]; "
                         "'class' keeps only the character's class among keys 0/1/2")
    ap.add_argument("--bap-item-grids", nargs="?", const="grid", default=None, choices=["grid", "full"],
                    help="with --bap-item-art: serve each item's talent grid index (item field 4 [2]); 'full' also "
                         "sends zeroed node states / step rolls and empty stat arrays")
    ap.add_argument("--notify-unanswered", action="store_true",
                    help="desktop notification (notify-send) for every decrypted request left unanswered")
    ap.add_argument("--bap-resume-push", action="store_true",
                    help="after a savestate resume, push the family-4 inventory delta (with --bap-items) and family 0/2 deltas")
    args = ap.parse_args()
    change_port = args.change_port if args.change_port is not None else args.port + 1

    tcp_replies = []
    for reply_hex in args.tcp_reply_hex:
        try:
            tcp_replies.append(bytes.fromhex(reply_hex))
        except ValueError as e:
            ap.error(f"--tcp-reply-hex is not valid hex: {e}")

    tcp_greets = []
    for greet_hex in args.tcp_greet_hex:
        try:
            tcp_greets.append(bytes.fromhex(greet_hex))
        except ValueError as e:
            ap.error(f"--tcp-greet-hex is not valid hex: {e}")

    socks = {}
    for role, host in (("primary", args.primary), ("secondary", args.secondary)):
        for port, changed in ((args.port, False), (change_port, True)):
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
            except OSError as e:
                log(f"bind {host}:{port} failed: {e}")
                return 1
            socks[s] = (role, changed)
            label = f"{role}{'+port' if changed else ''}"
            log(f"{label:15} {host}:{port}")

    peer_sock = None
    dtls_peers = {}
    if args.ah_public:
        # stand-in for the public activity host as a DemonWare peer (the udt 11 region record points here)
        peer_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        peer_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        peer_sock.bind((args.primary, args.peer_port))
        socks[peer_sock] = ("peer", False)
        log(f"{'peer':15} {args.primary}:{args.peer_port}")

    tcp_listeners = {}
    tcp_clients = {}
    tcp_reply_index = {}
    tcp_channels = {}
    bap_conn_key = bytes.fromhex(args.bap_conn_key)
    bap_soid = int(args.bap_account_soid, 0)
    body_503 = bytes.fromhex(args.bap_503_hex) if args.bap_503_hex else None
    if args.bap_channel or args.bap_resume:
        import bap_channel  # needs the 'cryptography' package; imported only when used
        bap_channel.FAMILY4_PUSH_MODE = args.bap_family4_push
        if args.bap_account_fields:
            bap_channel.set_account_field_count(args.bap_account_fields)
        if args.bap_char_stats:
            lv, li, em = args.bap_char_stats.split(",")
            bap_channel.CHAR_STATS = {"level": int(lv), "light": int(li),
                                      "emblem": None if em == "none" else int(em)}
        bap_channel.SERVE_PEER = args.bap_peer
        bap_channel.parse_items(args.bap_items)
        if args.social_activities:
            body = open(args.social_delta_file, "rb").read()
            i = body.index(bytes.fromhex("56341200"))
            bap_channel.social_config(body[i:i + body[i - 1]], [int(x) for x in args.social_activities.split(",")])
        bap_channel.MM_TUNING.update({int(a): int(b, 0) for a, b in (x.split("=") for x in args.mm_tuning.split(",") if x)})
        bap_channel.PROGRESSIONS[:] = [tuple(int(v) for v in x.split(":")) for x in args.bap_progressions.split(",") if x]
        bap_channel.PROFILE_DENSE[:] = [int(x) for x in args.bap_profile_dense.split(",") if x]
        bap_channel.ACCOUNT_DENSE10[:] = [int(x) for x in args.bap_account_dense10.split(",") if x]
        bap_channel.ACCOUNT_DENSE[:] = [int(x) for x in args.bap_account_dense.split(",") if x]
        bap_channel.UNLOCK_FLAGS[:] = [int(x) for x in args.bap_unlock_flags.split(",") if x]
        if args.bap_account_from:
            with open(args.bap_account_from) as fh:
                st = json.load(fh)
            bap_channel.CHARACTERS[:] = [int(c, 16) for c in st["characters"]]
            bap_channel.CHARACTER_IDENTITY.update({int(k, 16): tuple(v) for k, v in st.get("identities", {}).items()})
            bap_channel.CHARACTER_CREATION.update({int(k, 16): bytes.fromhex(v) for k, v in st.get("creations", {}).items()})
        bap_channel.CURRENT_ACTIVITY = args.bap_current_activity
        if args.bap_ah_proxy:
            ip, port = args.bap_ah_proxy.rsplit(":", 1)
            bap_channel.AH_PROXY = (ip, int(port))
        bap_channel.FAMILY4_EXTRA = args.bap_family4_extra
        if args.bap_destination:
            bap_channel.DESTINATION = int(args.bap_destination, 0)
        bap_channel.UNLOCK_VALUES[:] = [tuple(int(v) for v in x.split(":")) for x in args.bap_unlock_values.split(",") if x]
        if args.bap_item_art:
            bap_channel.load_item_art(args.bap_item_art)
        bap_channel.ART_DYES = bool(args.bap_art_dyes)
        bap_channel.ITEM_GRIDS = args.bap_item_grids
        bap_channel.DYE_CLASS_FILTER = args.bap_art_dyes == "class"
    bap_pending = {}
    ah_sessions = {}

    def notify_unanswered(pt, ah=False):
        t = struct.unpack(">H", pt[:2])[0]
        if ah:
            what = activity_host.TYPE_NAMES.get(t, f"type 0x{t:04x}")
        else:
            inv = bap_channel.investment_id(pt)
            what = f"investment {inv}" if inv is not None else bap_channel.TYPE_NAMES.get(t, f"type 0x{t:04x}")
        try:
            subprocess.Popen(["notify-send", "-a", "d1 stand-in", "-u", "normal", "-t", "10000",
                              f"Unanswered {'activity-host' if ah else 'BAP'} request: {what}", pt[6:40].hex()],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass
    last_closed = None   # (Channel, pending list) of the most recent mode-1 session that ended
    ah_resume = {}
    if args.bap_resume:
        with open(args.bap_resume) as fh:
            _st = json.load(fh)
        if _st.get("ah", {}).get("record"):
            ah_resume["state"] = _st["ah"]

    ah_state = {}        # the live AH connection's channel + session, saved next to the primary state

    def save_ah_state(sock):
        """Record the AH connection (channel counters + Session) so a savestate taken in world can be resumed."""
        if sock not in tcp_channels or sock not in ah_sessions:
            return
        ch = tcp_channels[sock]
        ah_state.clear()
        ah_state.update({"record": ch.record.hex(), "rx": ch.rx, "tx": ch.tx, **ah_sessions[sock].state()})
        prim = next((c for c, (r, _) in tcp_clients.items() if r != "ah" and c in tcp_channels), None)
        if prim is not None:
            save_bap_state(prim)

    def save_bap_state(sock):
        if not args.bap_state_file or sock not in tcp_channels or tcp_clients.get(sock, ("",))[0] == "ah":
            return
        ch = tcp_channels[sock]
        state = {"record": ch.record.hex(), "conn_key": bap_conn_key.hex(), "rx": ch.rx, "tx": ch.tx,
                 "ah": dict(ah_state),
                 "push_seq": ch.push_seq,
                 "characters": [hex(c) for c in bap_channel.CHARACTERS],
                 "identities": {hex(k): list(v) for k, v in bap_channel.CHARACTER_IDENTITY.items()},
                 "creations": {hex(k): v.hex() for k, v in bap_channel.CHARACTER_CREATION.items()},
                 "family4": dict(bap_channel.FAMILY4_STATE),
                 "pending": [p.hex() for p in bap_pending.get(sock, [])]}
        with open(args.bap_state_file, "w") as fh:
            json.dump(state, fh, indent=1)
    if args.tcp_sink:
        for role, host in (("primary", args.primary), ("secondary", args.secondary)):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, args.port))
                s.listen()
                s.setblocking(False)
            except OSError as e:
                log(f"TCP bind {host}:{args.port} failed: {e}")
                return 1
            tcp_listeners[s] = role
            log(f"tcp-{role:10} {host}:{args.port}")
    if args.ah_listen:
        import activity_host
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind((args.primary, args.ah_listen))
            s.listen()
            s.setblocking(False)
        except OSError as e:
            log(f"TCP bind {args.primary}:{args.ah_listen} failed: {e}")
            return 1
        tcp_listeners[s] = "ah"
        if args.ah_id:
            activity_host.AH_ID = int(args.ah_id, 0)
        if args.ah_pushes:
            activity_host.PUSHES = tuple(int(x) for x in args.ah_pushes.split(","))
        if args.ah_refresh_pushes is not None:
            activity_host.REFRESH_PUSHES = tuple(int(x) for x in args.ah_refresh_pushes.split(",") if x)
        if args.ah_bubble_count is not None:
            activity_host.BUBBLE_COUNT = args.ah_bubble_count
        if args.ah_bubble_chosen is not None:
            activity_host.BUBBLE_CHOSEN = tuple(int(x) for x in args.ah_bubble_chosen.split(",") if x)
        if args.ah_start is not None:
            v = [int(x, 0) for x in args.ah_start.split(",")]
            activity_host.START_REGION = v[0]
            if len(v) > 1:
                activity_host.START_SPAWN = v[1]
        activity_host.REGRANT_ENTITY_SLOTS = args.ah_regrant_slots
        if args.ah_sensor_auto:
            activity_host.SENSOR_AUTO = json.load(open(args.ah_sensor_auto))
        if args.ah_phase is not None and activity_host.SENSOR_AUTO:
            activity_host.SENSOR_AUTO["phase"] = args.ah_phase
        if args.ah_sensor_delay is not None:
            activity_host.AUTO_DELAY_S = args.ah_sensor_delay
        bap_channel.PEER_ADDR_REPLY = args.bap_peer_addr_reply
        if args.ah_no_travel:
            activity_host.TRAVEL = False
        if args.ah_public:
            activity_host.PUBLIC_AH = int(args.ah_public, 0)
            activity_host.SENSOR_ROUTE = args.ah_sensor_route
            activity_host.PUBLIC_MODE = args.ah_public_mode
            if args.ah_public_checksum:
                activity_host.PUBLIC_CHECKSUM = int(args.ah_public_checksum, 0)
            activity_host.PUBLIC_ADDR = (args.primary, args.peer_port)
        if args.ah_slice is not None:
            v = [int(x, 0) for x in args.ah_slice.split(",")] + [0]
            activity_host.SLICE_REGION, activity_host.SLICE_TOKEN, activity_host.SLICE_PEER = v[:3]
        if args.ah_udt11_bool_bits is not None:
            activity_host.UDT11_BOOL_BITS = args.ah_udt11_bool_bits
        if args.ah_udt1_bool_bits is not None:
            activity_host.UDT1_BOOL_BITS = args.ah_udt1_bool_bits
        activity_host.LOG = log
        activity_host.FOLLOW_ACTIVITY = not args.ah_activity_fixed
        if args.ah_activity_name is not None:
            activity_host.ACTIVITY_NAME = args.ah_activity_name
        if args.ah_activity_checksum is not None:
            activity_host.ACTIVITY_CHECKSUM = int(args.ah_activity_checksum, 0)
        if args.ah_activity_index is not None:
            activity_host.ACTIVITY_INDEX = args.ah_activity_index
        log(f"tcp-ah         {args.primary}:{args.ah_listen}")

    log(f"advertising secondary as {args.secondary}:0x{ALT_REPORT_PORT:04X}")

    sel = selectors.DefaultSelector()
    for s in socks:
        sel.register(s, selectors.EVENT_READ)
    for s in tcp_listeners:
        sel.register(s, selectors.EVENT_READ)

    seen: dict[bytes, int] = {}

    while True:
        # the AH must not stay silent: the client calls 20.5 s without a frame from us a host crash (BABOON)
        for sock, sess in list(ah_sessions.items()):
            live = sock in tcp_channels and sock in tcp_clients
            for rep in ((sess.sensor_due(args.ah_sensor_file), *sess.auto_due(), sess.heartbeat_due()) if live else ()):
                if rep is None:
                    continue
                try:
                    frame = tcp_channels[sock].seal(rep)
                    sock.sendall(frame)
                    log(f"-> [tcp-ah] heartbeat {len(frame)}B sealed tx#{tcp_channels[sock].tx - 1} "
                        f"{activity_host.describe(rep)[:120]}")
                    save_ah_state(sock)
                except OSError:
                    ah_sessions.pop(sock, None)
        for ev, _ in sel.select(timeout=1.0 if ah_sessions else None):
            sock = ev.fileobj

            if sock in tcp_listeners:
                client, addr = sock.accept()
                client.setblocking(False)
                tcp_clients[client] = (tcp_listeners[sock], addr)
                sel.register(client, selectors.EVENT_READ)
                log(f"<- [tcp-{tcp_listeners[sock]}] accepted {addr[0]}:{addr[1]}")
                resume_state = None
                if tcp_listeners[sock] == "ah":
                    # a fresh AH connection runs its own handshake; after a savestate load the client just keeps
                    # talking on the old channel, so restore it (file resume once, else the last closed session)
                    st = ah_resume.pop("state", None) or (ah_state if args.bap_auto_resume and ah_state.get("closed") else None)
                    if st:
                        ch = bap_channel.Channel(bytes.fromhex(st["record"]), bap_conn_key)
                        ch.rx, ch.tx = st["rx"], st["tx"]
                        tcp_channels[client] = ch
                        ah_sessions[client] = activity_host.Session.restore(st)
                        ah_state.pop("closed", None)
                        log(f"   [tcp-ah] RESUMED channel rx={ch.rx} tx={ch.tx} push_seq={st.get('push_seq')}")
                elif args.bap_auto_resume and last_closed is not None:
                    prev, prev_pending = last_closed
                    resume_state = {"record": prev.record.hex(), "conn_key": bap_conn_key.hex(), "rx": prev.rx,
                                    "tx": prev.tx, "push_seq": prev.push_seq,
                                    "pending": [p.hex() for p in prev_pending]}
                    last_closed = None
                elif args.bap_resume:
                    with open(args.bap_resume) as fh:
                        resume_state = json.load(fh)
                    args.bap_resume = None   # file resume applies to the first connection only
                if resume_state is not None:
                    st = resume_state
                    ch = bap_channel.Channel(bytes.fromhex(st["record"]), bytes.fromhex(st["conn_key"]))
                    ch.rx, ch.tx = st["rx"], st["tx"]
                    ch.push_seq = st.get("push_seq", 0)
                    if "characters" in st:   # account state of a saved session (file resume only)
                        bap_channel.CHARACTERS[:] = [int(c, 16) for c in st["characters"]]
                        bap_channel.CHARACTER_IDENTITY.update(
                            {int(k, 16): tuple(v) for k, v in st.get("identities", {}).items()})
                        bap_channel.CHARACTER_CREATION.update(
                            {int(k, 16): bytes.fromhex(v) for k, v in st.get("creations", {}).items()})
                        bap_channel.FAMILY4_STATE.update(st.get("family4", {}))
                    tcp_channels[client] = ch
                    tcp_reply_index[client] = len(tcp_replies)   # chain already spent in the saved session
                    log(f"   [tcp-{tcp_listeners[sock]}] RESUMED channel rx={ch.rx} tx={ch.tx} "
                        f"pending={len(st['pending'])}")
                    tcp_channels[client] = ch
                    for ph in st["pending"]:
                        pt = bytes.fromhex(ph)
                        rep = bap_channel.reply_for(pt, bap_soid, body_503)
                        if rep is None:
                            continue
                        frame = ch.seal(rep)
                        client.sendall(frame)
                        log(f"-> [tcp-{tcp_listeners[sock]}] {addr[0]}:{addr[1]} {len(frame)}B sealed tx#{ch.tx - 1} "
                            f"(resume reply to {bap_channel.describe(pt)[:60]}) plain: {rep.hex()}")
                    if args.bap_resume_push:
                        for ptype, pbody in bap_channel.resume_pushes(bap_soid):
                            plain = bap_channel.push_frame(ch, ptype, pbody)
                            frame = ch.seal(plain)
                            client.sendall(frame)
                            log(f"-> [tcp-{tcp_listeners[sock]}] {addr[0]}:{addr[1]} {len(frame)}B sealed "
                                f"tx#{ch.tx - 1} RESUME PUSH type=0x{ptype:04x} plain: {plain.hex()}")
                        args.bap_resume_push = False   # once: later auto-resumes restate nothing
                    save_bap_state(client)
                    continue
                for greet in (tcp_greets if tcp_listeners[sock] != "ah" else []):
                    try:
                        client.sendall(greet)
                        log(f"-> [tcp-{tcp_listeners[sock]}] {addr[0]}:{addr[1]} {len(greet)}B (greet) {hx(greet)}")
                    except OSError as e:
                        log(f"   [tcp-{tcp_listeners[sock]}] greet failed: {e}")
                        break
                continue

            if sock in tcp_clients:
                role, addr = tcp_clients[sock]
                try:
                    data = sock.recv(4096)
                except OSError as e:
                    log(f"<- [tcp-{role}] {addr[0]}:{addr[1]} recv failed: {e}")
                    data = b""
                if data:
                    log(f"<- [tcp-{role}] {addr[0]}:{addr[1]} {len(data)}B  "
                        f"{hx(data)}")
                    chan = tcp_channels.get(sock)
                    plains = []
                    if chan is not None and (chan.buf or data[:2] == b"\x01\x01"):
                        try:
                            plains = chan.feed(data)
                        except Exception as e:  # tag failure = our channel model is wrong
                            log(f"   [tcp-{role}] mode-1 decrypt FAILED ({type(e).__name__}); rx={chan.rx}")
                        for pt in plains:
                            what = activity_host.describe(pt) if role == "ah" else bap_channel.describe(pt)
                            log(f"   [tcp-{role}] plain rx#{chan.rx - 1}: {what}")
                        save_bap_state(sock)
                    reply_index = tcp_reply_index.get(sock, 0)
                    if role == "ah" and data[:2] == b"\x01\x02":
                        record = next(r[14:] for r in tcp_replies if r[6:8] == b"\x00\x1a")
                        rep = activity_host.handshake_reply(data, record)
                        if rep is None:
                            log(f"   [tcp-ah] unknown plaintext handshake type 0x{data[6:8].hex()}")
                        else:
                            sock.sendall(rep)
                            log(f"-> [tcp-ah] {addr[0]}:{addr[1]} {len(rep)}B  {hx(rep)}")
                            if rep[6:8] == b"\x00\x1a":
                                tcp_channels[sock] = ch = bap_channel.Channel(record, bap_conn_key)
                                log(f"   [tcp-ah] channel derived: key={ch.key.hex()} nonce={ch.recv_base.hex()}")
                    elif role != "ah" and reply_index < len(tcp_replies):
                        tcp_reply = tcp_replies[reply_index]
                        sock.sendall(tcp_reply)
                        tcp_reply_index[sock] = reply_index + 1
                        log(f"-> [tcp-{role}] {addr[0]}:{addr[1]} {len(tcp_reply)}B  {hx(tcp_reply)}")
                        if args.bap_channel and tcp_reply[6:8] == b"\x00\x1a":
                            tcp_channels[sock] = ch = bap_channel.Channel(tcp_reply[14:], bap_conn_key)
                            log(f"   [tcp-{role}] channel derived: key={ch.key.hex()} "
                                f"nonce={ch.recv_base.hex()}")
                            save_bap_state(sock)
                    elif plains and role == "ah":
                        sess = ah_sessions.setdefault(sock, activity_host.Session())
                        for pt in plains:
                            reps = sess.replies(pt)
                            if reps is None:
                                log(f"   [tcp-ah] no reply for this message (not modelled yet)")
                                # message 8 is a notification (no reply expected): only notify for other types
                                if args.notify_unanswered and pt[:2] != b"\x00\x08":
                                    notify_unanswered(pt, ah=True)
                                continue
                            for rep in reps:
                                frame = chan.seal(rep)
                                sock.sendall(frame)
                                log(f"-> [tcp-ah] {addr[0]}:{addr[1]} {len(frame)}B sealed tx#{chan.tx - 1} "
                                    f"{activity_host.describe(rep)[:160]} plain: {rep.hex()}")
                        save_ah_state(sock)
                    elif plains:
                        for pt in plains:
                            rep = bap_channel.reply_for(pt, bap_soid, body_503)
                            inv = bap_channel.investment_id(pt)
                            if rep is not None and inv is not None and str(inv) in args.bap_silent_investment.split(","):
                                log(f"   [tcp-{role}] investment {inv}: left unanswered (--bap-silent-investment)")
                                bap_pending.setdefault(sock, []).append(pt)
                                continue
                            if rep is None:
                                log(f"   [tcp-{role}] no reply for this message (not modelled yet)")
                                if args.notify_unanswered:
                                    notify_unanswered(pt)
                                if bap_channel.investment_id(pt) is not None:
                                    bap_pending[sock] = [pt]   # latest unanswered request only
                                continue
                            bap_pending[sock] = []
                            frame = chan.seal(rep)
                            sock.sendall(frame)
                            log(f"-> [tcp-{role}] {addr[0]}:{addr[1]} {len(frame)}B sealed tx#{chan.tx - 1} "
                                f"plain: {rep.hex()}")
                            for ptype, pbody in bap_channel.pushes_after(pt, bap_soid):
                                plain = bap_channel.push_frame(chan, ptype, pbody)
                                frame = chan.seal(plain)
                                sock.sendall(frame)
                                log(f"-> [tcp-{role}] {addr[0]}:{addr[1]} {len(frame)}B sealed tx#{chan.tx - 1} "
                                    f"PUSH type=0x{ptype:04x} plain: {plain.hex()}")
                        save_bap_state(sock)
                    else:
                        log(f"   [tcp-{role}] silent by design (BAP response not guessed)")
                else:
                    sel.unregister(sock)
                    del tcp_clients[sock]
                    tcp_reply_index.pop(sock, None)
                    if sock in tcp_channels and role != "ah":
                        last_closed = (tcp_channels[sock], list(bap_pending.get(sock, [])))
                    tcp_channels.pop(sock, None)
                    if role == "ah" and ah_state:
                        ah_state["closed"] = True
                    ah_sessions.pop(sock, None)
                    sock.close()
                    log(f"<- [tcp-{role}] {addr[0]}:{addr[1]} closed")
                continue

            role, changed_port = socks[sock]
            data, addr = sock.recvfrom(2048)
            endpoint = f"{role}{'+port' if changed_port else ''}"

            if len(data) < 3:
                log(f"<- [{endpoint}] {addr[0]}:{addr[1]} {len(data)}B (short) {hx(data)}")
                continue

            key = data[:4]
            seen[key] = seen.get(key, 0) + 1

            log(f"<- [{endpoint}] {addr[0]}:{addr[1]} {len(data)}B  "
                f"{hx(data[:8] if data[0] in (0, 1) and role != 'peer' else data[:220])}{' ...' if len(data) > 8 else ''}  (#{seen[key]})")

            if peer_sock is not None and len(data) == 29 and data[0] in (0x0A, 0x0D) and args.peer_reply:   # 0x0C accepted (run pubnat2)
                # bdNATTravClient packet {u8 type, u16 version, hmac[10], u32 ident, src addr, dest addr}: 0x0A = request
                # to the introducer (seen), 0x0D = direct request to the peer (seen, run pubnat1), reply type [U] - the peer echoes the rest
                rep = bytes([args.peer_reply]) + data[1:]
                peer_sock.sendto(rep, addr)
                log(f"-> [peer] {addr[0]}:{addr[1]} {len(rep)}B  {hx(rep)}")
                continue
            if role == "peer":
                if data[0] in (1, 3, 6) and len(data) > 1 and data[1] == 2:
                    import dtls_peer
                    peer = dtls_peers.get(addr)
                    if peer is None:
                        peer = dtls_peers[addr] = dtls_peer.Peer(bytes(range(0xB0, 0xC0)), log)
                    try:
                        outs, app = peer.handle(data, addr)
                    except Exception as e:   # a wrong layout guess must not take the stand-in down
                        log(f"   [dtls] error handling type {data[0]}: {e!r}")
                        outs, app = [], None
                    for o in outs:
                        peer_sock.sendto(o, addr)
                        log(f"-> [peer] {addr[0]}:{addr[1]} {len(o)}B  {hx(o)}")
                    if app is not None:
                        import peer_channel
                        chan = getattr(peer, "chan", None)
                        if len(app) > 2 and not app[2] & 0xC0 and chan is not None:
                            # established-channel packet: acknowledge (and deliver our connect-establish)
                            rep, h = chan.reply(app[2:], time.monotonic(), force=bool(app[2] & 0x08))
                            key = (h["payload"], h["ack"], chan.acked) if h else None
                            if h and (h["payload"] or key != getattr(peer, "chan_key", None)):
                                peer.chan_key = key
                                log(f"   [chan] rx {h} acked_ours={chan.acked} plain={app[2:].hex()}")
                            host = getattr(peer, "host", None)
                            for t, size, bits in chan.receive(app[2:]):
                                if host:
                                    host.on_message(t, size, bits)
                            if rep is not None:
                                peer_sock.sendto(peer.seal(rep), addr)
                                if h and (h["payload"] or rep[2] & 0x08) and len(rep) > 8:
                                    log(f"-> [chan] {rep[2:].hex()[:160]} delivered={chan.delivered}")
                            continue
                        jr = peer_channel.join_request(app)
                        if "time" in args.peer_host:
                            if not hasattr(peer, "clock0"):
                                peer.clock0 = None
                            def clock(origin, peer=peer):
                                if peer.clock0 is None:
                                    peer.clock0 = origin - int(time.monotonic() * 1000)
                                return peer.clock0 + int(time.monotonic() * 1000)
                            tr = peer_channel.time_reply(app, clock)
                            if tr:
                                peer_sock.sendto(peer.seal(tr), addr)
                                log(f"-> [peer] time-synchronize stage 1 {tr[2:].hex()}")
                                continue
                        if jr and chan is not None and chan.acked and args.peer_host and \
                                getattr(chan, "join_nonce", None) != jr["nonce"]:
                            chan.join_nonce = jr["nonce"]
                            ep = socket.inet_aton(args.primary) + struct.pack("<H", args.peer_port)
                            addr36 = ep + bytes.fromhex("00ff00ff0000") * 2 + ep + ep + b"\x02" + bytes(5)
                            hm = args.peer_host.split(",")
                            log(f"   [host] join-request nonce={jr['nonce'].hex()} mode={hm}")
                            peer.host = peer_channel.Host(chan, jr, addr36, hm[0], log, values="values" in hm,
                                                          ah=int(args.ah_public, 0) if "ah" in hm else None, flags=hm)
                        if jr and chan is not None and chan.acked and args.peer_membership and \
                                getattr(chan, "join_nonce", None) != jr["nonce"]:
                            chan.join_nonce = jr["nonce"]
                            ep = socket.inet_aton(args.primary) + struct.pack("<H", args.peer_port)
                            addr36 = ep + bytes.fromhex("00ff00ff0000") * 2 + ep + ep + b"\x02" + bytes(5)
                            mode = args.peer_membership.split(",")
                            if mode[0] == "est":   # transport control: a second connect-establish as a reliable message
                                st, ck = "est", 0
                                body = peer_channel.establish(chan.client_counter, chan.our_counter)
                            else:
                                st = tuple(int(x) for x in mode[:2])
                                host_id = (ep + bytes(2)) if "hostid" in mode else bytes(8)
                                body, ck = peer_channel.membership_probe(jr["sid"], jr["address"], addr36, jr["peer_id"],
                                                                         jr["nonce"], states=st, host_id=host_id)
                            chan.send(body)
                            if args.peer_params is not None and mode[0] != "est":
                                chan.send(peer_channel.parameters_probe(jr["sid"], int(args.peer_params, 0)))
                            log(f"   [chan] join-request {dict((k, v.hex() if isinstance(v, bytes) else v) for k, v in jr.items())}"
                                f" -> queued membership-update states={st} checksum=0x{ck:08x} bits={len(body.s)}")
                        if jr and getattr(peer, "jr_logged", None) == jr["nonce"]:
                            continue
                        if jr:
                            peer.jr_logged = jr["nonce"]
                        log(f"   [dtls] plain rx[{len(app)}]={app.hex()} | {peer_channel.describe(app)}")
                        req = peer_channel.connect_request(app)
                        if req and args.peer_connect:
                            ep = socket.inet_aton(args.primary) + struct.pack("<H", args.peer_port)
                            addr36 = ep + bytes.fromhex("00ff00ff0000") * 2 + ep + ep + b"\x02" + bytes(5)
                            vals = {"R": req[0], "I": req[1], "O": 0x5AFE}
                            fields = [vals[c] if c in vals else int(c, 0) for c in args.peer_connect.split(",")]
                            rep = peer_channel.connect_response(fields, addr36)
                            o = peer.seal(rep)
                            peer_sock.sendto(o, addr)
                            log(f"-> [peer] connect-response {fields} plain={rep.hex()} ({len(o)}B)")
                            if fields[3] == 0x5AFE:
                                peer.chan = peer_channel.Channel(req[0], req[1], our_counter=fields[2])
                continue
            if not (should_answer(role, changed_port, data) or args.answer_all):
                log(f"   [{endpoint}] silent by design")
                continue

            if data[0] == 0x00:
                # The 2.x probe echoes its own header back; it does NOT use the beta's opcode+1.
                reply = build_reply_2x(data,
                                       args.public_ip or addr[0],
                                       args.map_port or addr[1])
            else:
                reply = build_reply(data,
                                    args.public_ip or addr[0],
                                    args.map_port or addr[1],
                                    args.secondary)
            sock.sendto(reply, addr)
            log(f"-> [{endpoint}] {addr[0]}:{addr[1]} {len(reply)}B  {hx(reply)}")


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        log("stopped")
