"""Activity-host (AH) connection for the local stand-in (dwstun.py --ah-listen PORT).

After LAUNCH the client asks the primary connection for the activity-host proxy (16 -> 17, address from
--bap-ah-proxy) and opens a second BAP connection there. Its transport is the primary's: the chain greet (0x1f),
0x1e start (-> 0x1f), then a plaintext 0x19 secure hello carrying the security token (-> 0x1a with the key
record, the same mode-1 channel keys as the primary), then sealed frames. The sign-in chain's steps do not belong
here: its early 0x1a + 0x7a ack left 0x19 in flight, and its 303 answered message 6 (HONEYDEW).

First sealed message: 6 c->ah manager request, 4111 bytes (PS4 sibling layout, d1-bap activity_host.rs, matches
PS3 01.24 byte for byte): u8 inner type (1 = with args, 3 = without), [u16 args_len, char[0x200] args],
u16 nested_len + u8[0x200] (an encoded BAP message), u16 bitstream_len + u8[0xC00], u64 trailing id (the
account SOID). Reply 7: u8 2, u64 ah_id (non-zero), char[128] session id (sibling registry.rs: delivered to
the activity client as user_defined_type 10 start_activity_host_response {u64 ah_id, char session_id[]}).
"""
from __future__ import annotations

import struct
import time

STATUS_OK = 0x00C8
TYPE_AH_MANAGER_REQUEST = 0x0006
TYPE_AH_MANAGER_RESPONSE = 0x0007
TYPE_CLIENT_TO_AH_NOTIFICATION = 0x0008
TYPE_AH_TO_CLIENT_NOTIFICATION = 0x0064
TYPE_START_REQUEST = 0x001E          # 140-byte DESTINY packet
TYPE_START_RESPONSE = 0x001F
TYPE_SECURE_HELLO_REQUEST = 0x0019   # {1: security token, 2: 2}
TYPE_SECURE_HELLO_RESPONSE = 0x001A  # sealed key record (the chain's 0x1a body)
AH_ID = 0xD1A0000000000001   # PS4 sibling observed-live value (FIRST_ACTIVITY_HOST_ID); 0xA4..01 got HONEYDEW
SESSION_ID = b"d1-local-ah-session-1"
TYPE_BAP_TO_CLIENT_NOTIFICATION = 0x0009   # the AH -> client push the client delivers (100 is only relayed as 9)
UDT_JOIN_REQUEST = 3
UDT_JOIN_RESULT = 4
TAG_JOIN_REQUEST = 0x80800E98
TAG_JOIN_RESULT = 0x80800A58
TAG_ENTITY_SLOTS = 0x80800D64        # udt 0: 384 x u32 mask (12288 entity indices)
TAG_GLOBAL_ACTIVITY_STATE = 0x80800E76   # udt 1: {0: 0x80800B8F}
TAG_REPLICATE_MEMBERSHIP = 0x808009ED    # udt 11
UDT_ENTITY_SLOTS = 0
UDT_GLOBAL_ACTIVITY_STATE = 1
UDT_REPLICATE_MEMBERSHIP = 11
# The LAUNCH matchmaking request names activity hash 0x09fa9d74 = record 90 of the activity table (0130 entry 3487,
# the content's activity table) "patrol_deltas_com01", content hash 0xd07bb2d7.
ACTIVITY_NAME = "patrol_deltas_com01"    # --ah-activity-name
ACTIVITY_INDEX = 90                      # --ah-activity-index
ACTIVITY_CHECKSUM = 0x6A556A7F           # --ah-activity-checksum ([8], +0x5C, read from the running game)
UDT1_BOOL_BITS = 1            # --ah-udt1-bool-bits
UDT11_BOOL_BITS = 1           # --ah-udt11-bool-bits
UDT11_PRESENCE_BIT = True
UDT11_FIELD_BIAS = True        # narrow signed fields arrived as -1 (run launch_ah34: MANTIS 0.24 s after udt 11)
# Bubble count (+0x10) must equal the destination scenario record's +0x34 (0 -> "invalid host activity
# state", else "activity client bubble count mismatch"). Per-bubble state (+0x14, i8[64]): -1 = not chosen (sibling: the
# -1 branch unregisters the region), 0 = chosen (legal only for bubbles with sub-bubbles).
BUBBLE_COUNT = 22             # --ah-bubble-count (scenario record +0x34 for patrol_deltas_com01, read live)
START_REGION, START_SPAWN = 8, 0x811C9DC5   # --ah-start REGION[,SPAWNHASH] (region id = bubble * 8, sibling)
BUBBLE_CHOSEN = tuple(range(22))   # all 22 have one flagged sub-bubble (read live, run launch_ah30); --ah-bubble-chosen
PUSHES = (4,)                 # --ah-pushes: udts pushed on the join. Anything after 4 in the same burst -> GRAPEFRUIT
REFRESH_PUSHES = (0, 1, 11)   # --ah-refresh-pushes: udts pushed on the client's udt 17 request_state_refresh
UDT_REQUEST_STATE_REFRESH = 17
SLICE_REGION, SLICE_TOKEN, SLICE_PEER = 8, 1, 0   # udt 11 region record (token 0 = none)
HEARTBEAT_S = 5.0   # host heartbeat period (0 = off)
KEEPALIVE_MS = 2000      # ours to choose; the client has no default (sibling messages.rs)
GRACE_MS = 10000
UDT_NAMES = {5: "sensor_auth_update", 14: "peer_leave_request", 21: "client_authoritative_data_update", 0: "entity_slots_allocated", 1: "global_activity_state", 3: "join_request", 4: "join_result",
             11: "replicate_membership", 15: "activity_client_keepalive_request",
             17: "activity_client_request_state_refresh", 19: "allocate_entity_indices",
             35: "connectivity_failure", 36: "membership_acknowledgement", 37: "send_client_heartbeat",
             47: "high_water"}
TYPE_NAMES = {
    0x0009: "bap_to_client_notification",
    0x0006: "client_to_activity_host_manager_request",
    0x0007: "activity_host_manager_response",
    0x0008: "client_to_activity_host_notification",
    0x0064: "activity_host_to_client_notification",
    0x0066: "activity_host_to_client_log_notification",
}


def handshake_reply(frame: bytes, record: bytes) -> bytes | None:
    """Reply to a plaintext (mode 2) handshake frame, echoing its sequence. The client matches replies against the
    head of its in-flight queue by type, then sequence (sibling d1-bap lib.rs), so 0x19 must get a 0x1a; the
    sign-in chain instead sends the 0x1a early (to 0x1e) and acks 0x19 with 0x7a, which leaves 0x19 in flight."""
    t, seq = struct.unpack(">HI", frame[6:12])
    if t == TYPE_START_REQUEST:
        payload = struct.pack(">HIH", TYPE_START_RESPONSE, seq, STATUS_OK) + bytes(128)
    elif t == TYPE_SECURE_HELLO_REQUEST:
        payload = struct.pack(">HIH", TYPE_SECURE_HELLO_RESPONSE, seq, STATUS_OK) + record
    else:
        return None
    return b"\x01\x00" + struct.pack(">I", len(payload)) + payload


_SELECTED = None
FOLLOW_ACTIVITY = True   # --ah-activity-fixed: keep answering with the default activity whatever was launched
ACTIVITIES_FILE = "private/activities.json"   # index -> {name, hash, [checksum, public_checksum, bubbles, sensor, start]}
LOG = print


def select_activity(index: int) -> None:
    """Answer for the activity the client launched (manager request, nested i16) instead of the default one. Known
    per activity (config/activities.json): name and hash from the content's activity table; the two activity checksums
    and the bubble count are read from the running game or from the content (tools/activity_records.py); the spawn fixture is made
    per bubble. Missing checksums leave the client on the loading flight (stage 33 check)."""
    global ACTIVITY_INDEX, ACTIVITY_NAME, ACTIVITY_CHECKSUM, PUBLIC_CHECKSUM, SENSOR_AUTO, BUBBLE_COUNT, START_REGION
    global _SELECTED
    if index == _SELECTED:   # (the built-in default activity is loaded from the file too, the first time)
        return
    _SELECTED = index
    if not FOLLOW_ACTIVITY:
        LOG(f"   [ah] launched activity index {index}; answering as {ACTIVITY_NAME} (--ah-activity-fixed)")
        return
    import json, os
    acts = json.load(open(ACTIVITIES_FILE)) if os.path.exists(ACTIVITIES_FILE) else {}
    a = acts.get(str(index))
    if a is None:
        LOG(f"   [ah] launched activity index {index} is not in {ACTIVITIES_FILE}; answering as {ACTIVITY_NAME}")
        return
    ACTIVITY_INDEX, ACTIVITY_NAME = index, a["name"]
    missing = [k for k in ("checksum", "public_checksum", "bubbles") if k not in a]
    if "checksum" in a:
        ACTIVITY_CHECKSUM = int(a["checksum"], 0)
    if "public_checksum" in a:
        PUBLIC_CHECKSUM = int(a["public_checksum"], 0)
    if "bubbles" in a:
        BUBBLE_COUNT = a["bubbles"]
    START_REGION = a.get("start", 8)   # bubble 1 until the activity's landing zone is known
    if "public" in a:
        # the public base regions differ per activity (Cosmodrome 0,48,56,88,96,160; Venus 32,72,80,120,160,224)
        PUBLIC_REGIONS.clear()
        PUBLIC_REGIONS.update(a["public"])
    SENSOR_AUTO = json.load(open(a["sensor"])) if a.get("sensor") and os.path.exists(a["sensor"]) else None
    LOG(f"   [ah] launched activity {index} = {a['name']}" + (
        f"; NOT KNOWN YET: {', '.join(missing)} - see tools/activity_records.py"
        if missing else "") + ("" if SENSOR_AUTO else "; no spawn fixture"))


def manager_request(body: bytes) -> dict:
    inner = body[0]
    args, cur = b"", 1
    if inner == 1:
        (n,) = struct.unpack_from(">H", body, 1)
        args, cur = body[3:3 + n], 0x203
    (n,) = struct.unpack_from(">H", body, cur)
    nested = body[cur + 2:cur + 2 + n]
    cur += 2 + 0x200
    (n,) = struct.unpack_from(">H", body, cur)
    bits = body[cur + 2:cur + 2 + n]
    cur += 2 + 0xC00
    (trailing,) = struct.unpack_from(">Q", body, cur)
    return {"inner": inner, "args": args, "nested": nested, "bitstream": bits, "trailing": trailing}


def client_notification(pt: bytes) -> dict:
    """Message 8 (header class 3: type, seq, u64 ah_id): u8 inner type, u32 udt, i32 size, [u32 aux if type 1],
    payload."""
    ah_id, = struct.unpack_from(">Q", pt, 6)
    b = pt[14:]
    inner, udt, size = b[0], *struct.unpack_from(">Ii", b, 1)
    off = 13 if inner == 1 else 9
    return {"ah_id": ah_id, "inner": inner, "udt": udt, "payload": b[off:off + size]}


def notification_body(recipient: int, udt: int, payload: bytes) -> bytes:
    """Body shared by messages 9 and 100: u8 1, u64 recipient (the AH id), u32 udt, i32 size, payload."""
    return b"\x01" + struct.pack(">QIi", recipient, udt, len(payload)) + payload


def join_result(join_request_payload: bytes) -> bytes:
    import rsat
    req, _ = rsat.decode(TAG_JOIN_REQUEST, join_request_payload)
    sid = list(SESSION_ID) + [0] * (128 - len(SESSION_ID))
    return rsat.encode(TAG_JOIN_RESULT, {0: req, 1: 0, 2: {0: sid}, 3: 0, 4: 0, 5: 0, 6: 0, 7: 0,
                                         8: GRACE_MS, 9: KEEPALIVE_MS, 10: 0, 11: 0, 12: 0})


def _chars(text: str, n: int) -> list[int]:
    b = text.encode()[:n - 1]
    return list(b) + [0] * (n - len(b))


def entity_slots_allocated(grant: bool = True) -> bytes:
    """udt 0: the replication entity indices newly granted to the client (384 x u32 bitmask = 12288 indices; the
    client's allocator takes the first free one). The first publication grants every index (the client's own
    offline branch memsets the pool to 0xFF; sibling entity.rs); later ones grant nothing. Re-granting on the second
    state refresh marked index 0 free again while the player entity already held it, the body then got the same
    index, and deleting the corpse left the player entity with an unmapped index -> the in-world crash
    (run sens1, PROJECT_LOG 2026-10-04)."""
    import rsat
    return rsat.encode(TAG_ENTITY_SLOTS, {0: [0xFFFFFFFF if grant else 0] * 384})


PUBLIC_CHECKSUM = 0xE354F1EA   # --ah-public-checksum: the activity checksum the PUBLIC activity client expects
# (the client compares against record word +8 + 4 * client[+16]; client[+16] = 1 for "PUBLIC CURRENT");
#   a mismatch leaves the public world object inactive -> no body


def global_activity_state(checksum=None) -> bytes:
    """udt 1, inner 0x80800B8F (sibling messages.rs, PS4 offsets): [0] bool flag 0 (+0x00, must be non-zero),
    [4] bubble count (+0x10), [5] i8[64] per-bubble chosen state (+0x14), [8] activity checksum (+0x5C), [9][7] activity
    index (+0x680), [9][10] activity name char[40] (+0x688). Everything else zero (an activity where nothing happens)."""
    import rsat
    inner = {0: 1, 8: ACTIVITY_CHECKSUM if checksum is None else checksum, 9: {7: ACTIVITY_INDEX, 10: {0: _chars(ACTIVITY_NAME, 40)}}}
    if START_REGION is not None:
        # [6] (+0x54, i10) / [7] (+0x58): the region and spawn hash the initial slice-set transition starts with
        # (the client reads blob+84/+88). Unset they arrived as -1 / 0 (blob read live, run launch_ah31), so the
        # 10-bit field is taken to be value + 1 on the wire [U]; rsat's type-5 bias is 0 at this width.
        inner[6], inner[7] = START_REGION + 1, START_SPAWN
    if BUBBLE_COUNT:
        inner[4] = BUBBLE_COUNT
        inner[5] = [0 if i in BUBBLE_CHOSEN else -1 for i in range(BUBBLE_COUNT)] + [0] * (64 - BUBBLE_COUNT)
    # the client's decode of udt 1 with 0-bit bools ran to bit 1562 of 1560 and failed (hook run launch_ah20)
    saved, rsat.BOOL_BITS = rsat.BOOL_BITS, UDT1_BOOL_BITS
    try:
        return rsat.encode(TAG_GLOBAL_ACTIVITY_STATE, {0: inner})
    finally:
        rsat.BOOL_BITS = saved


PUBLIC_REGIONS = {0, 48, 56, 88, 96, 160}   # patrol_deltas_com01 bubbles 0, 6, 7, 11, 12, 20 (ah_bubble_probe.py)
# udt 11 [0] is the membership id, not a member count: the client rescans the region records only when it changes
# (compared with A+944) and acks it in udt 36 (run travel5: a second udt 11 with id 1 was ignored)
MEMBERSHIP_ID = 1
TRAVEL = True   # answer the client's bubble-travel request (udt 21) with a new udt 11 region record
PUBLIC_ADDR = ("127.0.0.1", 3074)   # where the public AH's bdCommonAddr points (--public-ip, UDP)
PUBLIC_MODE = 1   # --ah-public-mode: region record [2][1] (the client accepts 1 or 2; 1 = join the session of the blob)
SENSOR_ROUTE = "all"   # --ah-sensor-route: which AH connection carries udt 5 with a public AH: all | first | public
PUBLIC_AH = 0   # --ah-public ID: 64-bit public activity-host id for the region record (0 = private)


def replicate_membership(req: dict, payload: bytes | None = None) -> bytes:
    """udt 11: one member, the client, echoed from its join_request (sibling messages.rs ReplicateMembership::solo):
    [0] member count 1, [1] generation 0 (a difference zeroes the client's peer table), [2] 20 members {0 identity =
    join_request[2], 1 properties {0 = join_request[3] (carries the fireteam id)}, 2 i4}, [3] PAH region data {0 40
    regions (id -1 terminates), 3 acknowledged session host = member 0's first identity qword}, [4] simulation
    occupancy bit 0, [5] occupancy bit 0."""
    import rsat
    saved, saved_bias = rsat.BOOL_BITS, rsat.FIELD_BIAS
    rsat.BOOL_BITS, rsat.FIELD_BIAS = UDT11_BOOL_BITS, UDT11_FIELD_BIAS
    try:
        if payload is not None:
            req, _ = rsat.decode(TAG_JOIN_REQUEST, payload)   # same bias mode as the encode below
        return _replicate_membership(req)
    finally:
        rsat.BOOL_BITS, rsat.FIELD_BIAS = saved, saved_bias


def _replicate_membership(req: dict) -> bytes:
    import rsat
    members = [{0: req[2], 1: {0: req[3]}, 2: 0}] + [{} for _ in range(19)]
    # one region record {0 region id, 4 {2 20 per-peer token bytes}} then the -1 terminator (sibling set_pah_region:
    # the client copies the record whose id is its PENDING region and whose token byte for our peer slot equals its
    # transition token, 1 on a first transition; without it stage 34 waits forever, run launch_ah29)
    # [2][2] -1 as in the client's own empty record (ac+0xE08+11848 read live: ffffffff 00000000 0000ff00)
    regions = [{0: SLICE_REGION, 2: {2: -1}, 4: {2: [SLICE_TOKEN if i == SLICE_PEER else 0 for i in range(20)]}}] \
        if SLICE_TOKEN else []
    if regions and PUBLIC_AH and SLICE_REGION in PUBLIC_REGIONS:
        # public bubble: the transition waits for "public AH instance ready" (A+321 == 2); the client starts the join
        # only with [4][3] = {78, 60 non-zero bytes} (A+1244) and [4][4] != 0 (A+1376) [U content]
        # the 60 bytes look like a DemonWare session: 8 B security id | 36 B bdCommonAddr (same layout as the client's
        # own address in BAP 0x12e; the client sends bytes 8..43 back in BAP 0x12c, run public12b) | 16 B key [U]
        import socket as _s
        ip, port = PUBLIC_ADDR
        ep = _s.inet_aton(ip) + port.to_bytes(2, "little")   # bdAddr: the port is little-endian (0x12e: 04 0c = 3076)
        blob = (bytes(range(0xA1, 0xA9)) + ep + bytes.fromhex("00ff00ff0000") * 2 + ep + ep + b"\x02" + bytes(5)
                + bytes(range(0xB0, 0xC0)))
        regions[0][4].update({3: {0: 78, 1: list(blob) + [0] * 18}, 4: PUBLIC_AH})
        regions[0][2] = {1: PUBLIC_MODE, 2: -1}   # the client requests the join (A+138 bit 4) only with [2][1] == 1 (A+1177)
    pah = {0: regions + [{0: -1, 2: {2: -1}} for _ in range(40 - len(regions))], 3: list(req[2][0])}
    # each region record holds a bool ([3][0][i][2][3]); with 0-bit bools the message is 40 bits short and the client
    # keeps an empty membership (ac+0xE08 read live, run launch_ah32: no members, local peer index -1)
    if True:
        values = {0: MEMBERSHIP_ID, 1: 0, 2: members, 3: pah, 4: 1, 5: 1, 6: 0}
        # udt 11 is a seeded decode (the client copies the current membership first): one presence bit, then the plain
        # object (sibling activity-host.md 6.3). Without the bit the client reads "no change" and keeps its seed.
        if not UDT11_PRESENCE_BIT:
            return rsat.encode(TAG_REPLICATE_MEMBERSHIP, values)
        n = rsat.encoded_bits(TAG_REPLICATE_MEMBERSHIP, values)
        body = int.from_bytes(rsat.encode(TAG_REPLICATE_MEMBERSHIP, values), "big") >> (-n % 8)
        return (((1 << n) | body) << (-(n + 1) % 8)).to_bytes((n + 8) // 8, "big")


TAG_SENSOR_NAME_REF = 0x808004B1   # {u32 group hash, i7, i16 sub}
TAG_SENSOR_VALUE = 0x808008A3      # the activity-lifetime value (0x504 B image); [0] = phase (i4)
UDT_SENSOR_AUTH_UPDATE = 5
FNV_EMPTY = 0x811C9DC5


REGRANT_ENTITY_SLOTS = False   # --ah-regrant-slots: the old behaviour (every udt 0 grants all indices)
SENSOR_AUTO = None   # --ah-sensor-auto FILE
AUTO_DELAY_S = 6.0   # --ah-sensor-delay
SENSOR_TYPE_BITS = {35: 64}   # leaf type 35 (8-byte player key) taken as 64 raw bits [U]


def _intkeys(v):
    if isinstance(v, dict):
        return {int(k): _intkeys(x) for k, x in v.items()}
    return [_intkeys(x) for x in v] if isinstance(v, list) else v


def _bits(data: bytes, n: int) -> str:
    return bin(int.from_bytes(data, "big") >> (len(data) * 8 - n))[2:].zfill(n) if n else ""


def sensor_auth_update(gen: int, name_hash: int, name_sub: int, phase: int, name_i7: int = 16, stamp: int = 0,
                       second: bool = False, value: dict | None = None, init=None, entries=None,
                       skip_main: bool = False) -> bytes:
    """udt 5: one named-globals entry assigning the activity-lifetime phase (sibling d1-oracle sensor.rs): gen(8, must equal world-object+17) | has_sensor_block(1)=0 | stamp(32) | init(1)=1 |
    has_entry(1)=1 | name-ref(55) | body_bit_length(32) | fresh(1)=1 | presence(1)=1 | value(339) | [second-schema
    bit 0 when the record's definition has one (def+8 != -1)] | terminator(1)=0."""
    import rsat
    saved = rsat.BOOL_BITS, rsat.FIELD_BIAS
    rsat.BOOL_BITS, rsat.FIELD_BIAS = 1, True
    try:
        name = {0: name_hash, 1: name_i7, 2: name_sub}
        val = {0: phase, 1: -1, 2: 1, 3: -1, 4: FNV_EMPTY, 5: -1, 6: {0: 0, 1: []}, 7: 0, 8: -1, 9: FNV_EMPTY, 10: 0,
               11: 0, 12: -1, 13: {0: FNV_EMPTY, 1: -1, 2: -1}, 14: FNV_EMPTY, 15: {0: 0, 1: []}}
        val.update(value or {})
        nb = _bits(rsat.encode(TAG_SENSOR_NAME_REF, name), rsat.encoded_bits(TAG_SENSOR_NAME_REF, name))
        vb = _bits(rsat.encode(TAG_SENSOR_VALUE, val), rsat.encoded_bits(TAG_SENSOR_VALUE, val))
    finally:
        rsat.BOOL_BITS, rsat.FIELD_BIAS = saved
    body = "1" + "1" + vb + ("0" if second else "")
    bits = f"{gen & 0xFF:08b}" + "0" + f"{stamp & 0xFFFFFFFF:032b}" + "1"
    if not skip_main:
        bits += "1" + nb + f"{len(body):032b}" + body
    # further entries [hash, i7, sub, has_a, has_b]: "initial value = the default" (fresh 1, presence 0; a second-schema
    # bit 0). The post-pass that applies replicas to the records runs only once no in-scope definition still awaits
    # its initial value (def+21), run launch_ah39: 239 of 750 awaiting.
    saved = rsat.BOOL_BITS, rsat.FIELD_BIAS
    rsat.BOOL_BITS, rsat.FIELD_BIAS = 1, True
    try:
        for h, i7, sub, has_a, has_b in init or ():
            ref = {0: h, 1: i7, 2: sub}
            b = ("10" if has_a else "") + ("0" if has_b else "")
            bits += "1" + _bits(rsat.encode(TAG_SENSOR_NAME_REF, ref), 55) + f"{len(b):032b}" + b
    finally:
        rsat.BOOL_BITS, rsat.FIELD_BIAS = saved
    # generic entries {"hash", "i7", "sub", "tag": schema A, "value": {...}, "second": bool} (e.g. a player-slot record)
    saved = rsat.BOOL_BITS, rsat.FIELD_BIAS, dict(rsat.TYPE_BITS)
    rsat.BOOL_BITS, rsat.FIELD_BIAS = 1, True
    rsat.TYPE_BITS.update(SENSOR_TYPE_BITS)
    try:
        for e in entries or ():
            ref = {0: e["hash"], 1: e.get("i7", 16), 2: e["sub"]}
            val = _intkeys(e.get("value", {}))
            b = "11" + _bits(rsat.encode(e["tag"], val), rsat.encoded_bits(e["tag"], val)) + ("0" if e.get("second") else "")
            bits += "1" + _bits(rsat.encode(TAG_SENSOR_NAME_REF, ref), 55) + f"{len(b):032b}" + b
    finally:
        rsat.BOOL_BITS, rsat.FIELD_BIAS = saved[:2]
        rsat.TYPE_BITS.clear()
        rsat.TYPE_BITS.update(saved[2])
    bits += "0"
    bits += "0" * (-len(bits) % 8)
    return int(bits, 2).to_bytes(len(bits) // 8, "big")


class Session:
    """One AH connection: server-originated push sequence numbers."""

    def __init__(self) -> None:
        self.push_seq = 0
        self.req = None   # decoded join_request
        self.last_tx = None   # monotonic time of our last push once the state has been published
        self.refreshes, self.auto_at, self.auto_step = 0, None, 0

    def state(self) -> dict:
        """What a resumed connection needs (dwstun saves it with the channel counters)."""
        return {"push_seq": self.push_seq, "join_payload": getattr(self, "join_payload", b"").hex(),
                "slots_granted": getattr(self, "slots_granted", False), "refreshes": self.refreshes,
                "auto_step": self.auto_step, "published": self.last_tx is not None}

    @classmethod
    def restore(cls, st: dict) -> "Session":
        import rsat
        s = cls()
        s.push_seq, s.refreshes, s.auto_step = st.get("push_seq", 0), st.get("refreshes", 0), st.get("auto_step", 0)
        s.slots_granted = st.get("slots_granted", False)
        if st.get("join_payload"):
            s.join_payload = bytes.fromhex(st["join_payload"])
            s.req, _ = rsat.decode(TAG_JOIN_REQUEST, s.join_payload)
        if st.get("published"):
            s.last_tx = time.monotonic()
        if s.refreshes >= 2 and s.auto_step < 2:
            s.auto_at = time.monotonic()
        return s

    def push(self, udt: int, payload: bytes) -> bytes:
        self.push_seq += 1
        return struct.pack(">HI", TYPE_BAP_TO_CLIENT_NOTIFICATION, self.push_seq) + \
            notification_body(getattr(self, "ah_id", AH_ID), udt, payload)

    def _entity_slots(self) -> bytes:
        first, self.slots_granted = not getattr(self, "slots_granted", False), True
        return entity_slots_allocated(first or REGRANT_ENTITY_SLOTS)

    def build(self, udt: int) -> bytes:
        return {UDT_JOIN_RESULT: lambda: join_result(self.join_payload),
                UDT_ENTITY_SLOTS: self._entity_slots,
                UDT_GLOBAL_ACTIVITY_STATE: lambda: global_activity_state(
                    PUBLIC_CHECKSUM if PUBLIC_AH and getattr(self, "ah_id", AH_ID) == PUBLIC_AH else None),
                UDT_REPLICATE_MEMBERSHIP: lambda: replicate_membership(self.req, self.join_payload)}[udt]()

    def replies(self, pt: bytes) -> list[bytes] | None:
        """Plaintexts to send for a decrypted client frame; None = not modelled."""
        t, seq = struct.unpack(">HI", pt[:6])
        if t == TYPE_AH_MANAGER_REQUEST:
            m = manager_request(pt[6:])
            if len(m["nested"]) >= 4:
                # nested = 05 17 | i16 activity index + 0x8000 | 40 (Earth patrol 805a = 90, Venus patrol 805e = 94)
                select_activity(int.from_bytes(m["nested"][2:4], "big") - 0x8000)
            return [struct.pack(">HIH", TYPE_AH_MANAGER_RESPONSE, seq, STATUS_OK) + manager_response_body()]
        if t == TYPE_CLIENT_TO_AH_NOTIFICATION:
            n = client_notification(pt)
            if n["ah_id"]:
                self.ah_id = n["ah_id"]   # the public activity host is a second connection with its own id
            if n["udt"] == UDT_JOIN_REQUEST:
                import rsat
                req, _ = rsat.decode(TAG_JOIN_REQUEST, n["payload"])
                # the client polls for all four together (sibling state.rs); sent in its own ladder order 4, 0, 1, 11
                self.req, self.join_payload = req, n["payload"]
                return [self.push(u, self.build(u)) for u in PUSHES]
            if n["udt"] == UDT_REQUEST_STATE_REFRESH and self.req is not None:
                # the client asks for the state once it has accepted join_result (48 ms later, run launch_ah9);
                # 0/1/11 sent in the same burst as 4 are fatal (GRAPEFRUIT, runs launch_ah10-13)
                self.last_tx = time.monotonic()
                self.refreshes += 1
                if self.refreshes == 2:
                    self.auto_at = time.monotonic() + AUTO_DELAY_S
                return [self.push(u, self.build(u)) for u in REFRESH_PUSHES]
            if n["udt"] == 21 and self.req is not None and TRAVEL:
                # client_authoritative_data_update (RSAT 0x80800c56 behind one leading presence bit, a delta of the
                # client's state): [1][0] current region record, [1][1] DESIRED region record {0 region, ...,
                # 6 public carrier}, [1][2] transition token, [1][4] transition stage. A changed desired region is the
                # travel request (13 bytes between private bubbles; a full ~120-byte state after a udt 17 refresh when
                # the target is public - there the token is omitted = unchanged). Answer with its region record.
                global SLICE_REGION, SLICE_TOKEN
                import rsat
                bits = "".join(f"{x:08b}" for x in n["payload"])[1:]
                bits += "0" * (-len(bits) % 8)
                saved = rsat.BOOL_BITS, rsat.FIELD_BIAS
                rsat.BOOL_BITS, rsat.FIELD_BIAS = 1, True
                try:
                    v, _ = rsat.decode(0x80800C56, bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)))
                except Exception:
                    return []
                finally:
                    rsat.BOOL_BITS, rsat.FIELD_BIAS = saved
                state = v.get(1) or {}
                desired = state.get(1) or {}
                region = desired.get(0)
                if region is not None and region >= 0:
                    token = state.get(2) if state.get(2) is not None else SLICE_TOKEN
                    if (region, token) != (SLICE_REGION, SLICE_TOKEN) and (
                            region not in PUBLIC_REGIONS or PUBLIC_AH):
                        global MEMBERSHIP_ID
                        MEMBERSHIP_ID += 1
                        SLICE_REGION, SLICE_TOKEN = region, token
                        self.travel = (region, token)
                        return [self.push(UDT_REPLICATE_MEMBERSHIP, self.build(UDT_REPLICATE_MEMBERSHIP))]
                return []
        return None

    def _routed(self) -> bool:
        mine_public = getattr(self, "ah_id", AH_ID) == PUBLIC_AH
        return SENSOR_ROUTE == "all" or not PUBLIC_AH or (SENSOR_ROUTE == "public") == mine_public

    def sensor_due(self, path: str | None) -> bytes | None:
        """udt 5 from a JSON file written mid-run ({"gen", "hash", "sub", "phase", ...}; the per-boot inputs are read
        live); sent once per file change."""
        import json, os
        if not path or self.last_tx is None or not os.path.exists(path):
            return None
        m = os.stat(path).st_mtime
        if m == getattr(self, "sensor_mtime", None):
            return None
        self.sensor_mtime = m
        if not self._routed():
            return None
        c = json.load(open(path))
        SENSOR_TYPE_BITS.update({int(k): v for k, v in c.get("type_bits", {}).items()})
        payload = sensor_auth_update(c["gen"], c.get("hash", 0), c.get("sub", 0), c.get("phase", 3), c.get("i7", 16), c.get("stamp", 0),
                                     c.get("second", False), {int(k): v for k, v in c.get("value", {}).items()},
                                     c.get("init"), c.get("entries"), c.get("skip_main", False))
        return self.push(UDT_SENSOR_AUTH_UPDATE, payload)

    def auto_due(self) -> list[bytes]:
        """The spawn sequence without live memory (fixture SENSOR_AUTO, see config/ah_sensor_*.json): AUTO_DELAY_S after
        the client's second state refresh (it follows the initial region load) the lifetime phase + default initial
        values, 3 s later the claim of player slot 0 for the joining character (identity [3], = player+24)."""
        out = []
        if not SENSOR_AUTO or self.auto_at is None or not self._routed() or (
                "regions" in SENSOR_AUTO and str(START_REGION) not in SENSOR_AUTO["regions"]):
            return out
        c, now = SENSOR_AUTO, time.monotonic()
        if self.auto_step == 0 and now >= self.auto_at:
            self.auto_step = 1
            out.append(self.push(UDT_SENSOR_AUTH_UPDATE, sensor_auth_update(
                c["gen"], c["hash"], c["sub"], c.get("phase", 3),
                init=c.get("regions", {}).get(str(START_REGION), c.get("init")))))
        elif self.auto_step == 1 and now >= self.auto_at + 3:
            self.auto_step = 2
            slot = dict(c["slot"], tag=0x808022A5, second=True,
                        value={0: {0: -1, 1: FNV_EMPTY, 2: 1}, 2: {0: self.req[2][3]}})
            out.append(self.push(UDT_SENSOR_AUTH_UPDATE, sensor_auth_update(
                c["gen"], 0, 0, 3, entries=[slot], skip_main=True)))
        return out

    def heartbeat_due(self) -> bytes | None:
        """Unprompted global_activity_state re-publication (sibling state.rs: the client declares a host crash after
        20000 + 500 ms without a frame from us; run launch_ah28 closed 20.65 s after our last push)."""
        if self.last_tx is None or not HEARTBEAT_S or time.monotonic() - self.last_tx < HEARTBEAT_S:
            return None
        self.last_tx = time.monotonic()
        return self.push(UDT_GLOBAL_ACTIVITY_STATE, self.build(UDT_GLOBAL_ACTIVITY_STATE))


def manager_response_body() -> bytes:
    return b"\x02" + struct.pack(">Q", AH_ID) + SESSION_ID.ljust(128, b"\x00")


def describe(pt: bytes) -> str:
    t, seq = struct.unpack(">HI", pt[:6])
    body = pt[6:]
    name = TYPE_NAMES.get(t, "?")
    if t == TYPE_AH_MANAGER_REQUEST and len(body) == 0x100F:
        m = manager_request(body)
        return (f"type=0x{t:04x} ({name}) seq={seq} inner={m['inner']} args={m['args'].rstrip(bytes(1))!r} "
                f"nested[{len(m['nested'])}]={m['nested'].hex()} bitstream[{len(m['bitstream'])}]="
                f"{m['bitstream'].hex()} trailing=0x{m['trailing']:016x}")
    if t in (TYPE_CLIENT_TO_AH_NOTIFICATION, TYPE_BAP_TO_CLIENT_NOTIFICATION):
        if t == TYPE_CLIENT_TO_AH_NOTIFICATION:
            n = client_notification(pt)
        else:
            n = {"ah_id": struct.unpack_from(">Q", body, 1)[0], "inner": body[0], "udt": struct.unpack_from(">I", body, 9)[0], "payload": body[17:]}
        return (f"type=0x{t:04x} ({name}) seq={seq} ah=0x{(n['ah_id'] or 0):016x} udt={n['udt']} "
                f"({UDT_NAMES.get(n['udt'], '?')}) payload[{len(n['payload'])}]={n['payload'].hex()}")
    return f"type=0x{t:04x} ({name}) seq={seq} body[{len(body)}]={body.hex()}"
