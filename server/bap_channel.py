"""BAP secure channel (envelope mode 1) for the local stand-in.

Every key here is server-chosen (see PROJECT_LOG.md 2026-09-27 "BAP channel layer decrypted"):

* The setup-phase type-0x1a reply carries a sealed record ``u32be L || iv16 || ct || hmac32``
  (AES-128-CBC with ``conn+0x2261``, HMAC-SHA256 with ``conn+0x2271``; both come from our SignOn
  response and are zero in the local runs).
* The client installs the channel from the *decrypted* record plaintext ``pt``:
  key = ``pt[12:28]``, receive nonce = ``pt[0:12]``, send nonce = ``pt[0:12]`` with byte 11 ^= 1.
* Mode-1 frames are ``01 01 || u32be (16 + n) || tag16 || ct`` with AES-128-GCM, empty AAD, and the
  nonce's low bytes (little-endian from byte 0) advanced by one per frame in each direction.
* Plaintext is ``u16be type || u32be seq || [u16be status, responses only] || body``.
"""
from __future__ import annotations

import struct

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

TYPE_WORLD_SERVER_REQUEST = 0x000A
TYPE_WORLD_SERVER_RESPONSE = 0x000B
TYPE_ECHO_REQUEST = 0x00FA
TYPE_ECHO_RESPONSE = 0x00FB
STATUS_OK = 0x00C8
INVESTMENT_503 = 0x01F7
INVESTMENT_206 = 0x00CE
TYPE_SUBSCRIPTION_REQUEST = 0x000C
TYPE_SUBSCRIPTION_RESPONSE = 0x000D
TYPE_UNSUBSCRIBE_REQUEST = 0x000E   # client_to_bap_unsubscribe_request (body = family u8 + root u64)
TYPE_UNSUBSCRIBE_RESPONSE = 0x000F  # unanswered it stalls the in-flight queue -> WEASEL
TYPE_XETROV_REQUEST = 0x00AB      # no paired response exists (fire-and-forget)
TYPE_UPO_REQUEST = 0x0015         # client_to_bap_update_purchased_offers_request
TYPE_UPO_RESPONSE = 0x0016        # empty body = empty purchased-offer id list (valid protobuf)
TYPE_USER_MSG_REQUEST = 0x0020    # bap_to_client_user_message_request (bodyless)
TYPE_USER_MSG_RESPONSE = 0x0021   # protobuf; field 4 (varint) is REQUIRED -> minimal body 20 00
USER_MSG_RESPONSE_BODY = bytes.fromhex("2000")

# PS4 sibling's INVESTMENT_503_PINNED_RAW (d1preservation d1-bap lib.rs): the 503 argument bitstream
# built by their client's own encoder, account SOID 0xD100000000000001 at its bit offset. Accepted
# by PS3 01.24 as-is (run timing-resume503-pinned-20260927-181031): the client moved on to xetrov,
# investment 206 and the family subscription.
INVESTMENT_503_PINNED = bytes.fromhex(
    "180000000d1000000000000010000000000000000bfffffffffffffffc00000000000000020810220000000100")
# 206 fetch_family: one-byte response object = 0 encodes as 0x10 (sibling native-oracle fixed point).
# Answering a family-3 request with 0x10 alone (no QueueZ span) was followed by a guest NULL read.
INVESTMENT_206_NO_SPAN = b"\x10"
# The same reply carrying a family-3 span with an EMPTY roster for account 0xD100000000000001
# (sibling queuez_family3_empty_roster_body wrapped by fetch_family_response_body; rebuilt
# independently in Python from their source, byte-identical to the subagent's derivation):
#   span = u32 count 1 | u32 family 3 | u64 root | u32 version 0 | u8 flags 1 (baseline) |
#          u32 objects 1 | u32 ROSTER 0xA2AC2C74 | u64 soid | u32 len 9 | e880000000000000c0
#   body = 4-bit leaf 1 | presence 1 | u16 len 50 | span, MSB-first, zero-padded
# Investment messages whose response object is the single shared composite 0x80801796
# {u4 @+0, u32 @+4}; the zero object encodes as 18 00 00 00 00 (sibling native-oracle, e.g.
# investment_701_response_body). 701 is sent after Screen Bounds / brightness; unanswered it is
# retried and the client shows "Contacting Destiny Servers".
INVESTMENT_ZERO_COMPOSITE_IDS = {104, 502, 504, 505, 506, 701, 702}
INVESTMENT_402 = 402   # dismantle: args = presence bit + u64 item SOID + tail; answered with the result composite
INVESTMENT_403 = 403   # inventory_equip_item: args = u64 item SOID + u8; answered with the result composite
INVESTMENT_801 = 801   # talent node select: args = u64 item SOID + i8 node (biased, 0x86 = 6) [U] + pad
# 501 login_create_character -> {0x80801796 result = 0, u64 new character SOID} (sibling
# character_lifecycle::create_character_response_body): 4-bit leaf biased +1, 32-bit leaf biased
# by 0x80000000, then the SOID, MSB-first.
# 205 (unlocks): sibling investment_205_response_body, oracle-verified; its tail equals the tail of
# the pinned 503 body we send (the two share nested struct 0x80801941).
INVESTMENT_205 = 205
INVESTMENT_205_BODY = bytes.fromhex("1bfffffffffffffffc000000000000000208102200000001" "00")
# 0x0017 account id translation: request u16 count | u8 from 7 (platform id) | u8 to 0xFF (SOID) |
# count x 36-byte ids. Reply 0x0018 = same header, list of ids, then list of u64 SOIDs.
# 0x0012 client_config request (8 zero bytes, sent at setup:orbit) -> 0x0013 protobuf with two
# REQUIRED varints: field 1 cookie, field 2 social_matchmaking_id (sibling client_config_response_body).
TYPE_CLIENT_CONFIG_REQUEST = 0x0012
TYPE_CLIENT_CONFIG_RESPONSE = 0x0013
# 0x002A matchmaking-core request (42; protobuf {1 version, 2 kind (4 = matchmaking configuration), 3 u64 nonce,
# 11 {1 activity hash, 2 matchmaking content hash}}) -> 0x002B response {1 kind, 2 nonce, 4 configuration}; for
# kind 4 the client only tests the presence of field 4 (sibling d1-bap matchmaking.rs). Sent after LAUNCH.
TYPE_MM_REQUEST = 0x002A
TYPE_MM_RESPONSE = 0x002B
# 0x0010 get_activity_host_proxy request (16; u64 BE activity-host id, 0 = "the proxy") -> 0x0011 (17): 16 bytes
# {u64 BE id echo (a mismatch is dropped silently), u32 BE IPv4, u32 BE port}; the client then opens a second
# BAP connection to that address (sibling d1-bap activity_host.rs; BE is the order that connected).
TYPE_AH_PROXY_REQUEST = 0x0010
TYPE_AH_PROXY_RESPONSE = 0x0011
PEER_ADDR_REPLY = False   # --bap-peer-addr-reply: answer 0x12c with a bare OK (run public12c: WEASEL 0.25 s later [U cause])
AH_PROXY = ("127.0.0.1", 3074)   # --bap-ah-proxy IP:PORT
CLIENT_CONFIG_RESPONSE_BODY = bytes.fromhex("08001000")


def social_config(base_delta: bytes, activities, max_groups: int = 16) -> None:
    """Serve an engine-config delta in 0x0013 field 3 (same decoder as SignOn f4.3; it resets the
    config to defaults first, so ``base_delta`` = the SignOn delta is repeated). Adds the matchmaking overrides for up
    to five activity indices: key 1177 = activity per slot, 1181 = maximum group count (C+0xc0, zero in the Tower's
    content record -> compatibility status 12), 1201 = its enable bytes (settings +0xafb; an earlier note's
    1203 / +0xb05 is the enable of a later field). LE32 magic 0x123456, LE32 key + fixed payload,
    LE32 0 terminator."""
    global CLIENT_CONFIG_RESPONSE_BODY
    acts = list(activities)[:5]
    pad = [0x811C9DC5] * (5 - len(acts))
    assert base_delta[:4] == bytes.fromhex("56341200") and base_delta[-4:] == b"\0\0\0\0"
    delta = (base_delta[:-4] + struct.pack("<I5I", 1177, *(acts + pad))
             + struct.pack("<I5I", 1181, *([max_groups] * len(acts) + pad))
             + struct.pack("<I", 1201) + bytes([1] * len(acts) + [0] * (5 - len(acts))) + b"\0\0\0\0")
    CLIENT_CONFIG_RESPONSE_BODY = bytes.fromhex("08001000") + b"\x1a" + _varint(len(delta)) + delta
# Families the client subscribes to that we answer with an empty (object_count 0) baseline right
# after the 0x000D ack; unanswered they time out ("Failed peer-subscription validation").
EMPTY_FAMILIES = {0, 2, 6}   # family 6 is subscribed from the character screen; answered empty
TYPE_ACCOUNT_ID_XLAT_REQUEST = 0x0017
TYPE_ACCOUNT_ID_XLAT_RESPONSE = 0x0018
INVESTMENT_501 = 501
NEW_CHARACTER_SOID = 0xD100000000000101
# Characters the account owns; 501 appends. Family-3 answers (206) list them in the roster.
CHARACTERS: list[int] = []
CHARACTER_IDENTITY = {}           # soid -> (race, gender, class) from the 501 request
CHARACTER_CREATION = {}           # soid -> raw 501 arguments (0x80801860: identity, customization, name)
# Family-3 slot 1 (character) checksum on PS3 01.24 (PS4 01.29: 0x3431F1BA).
CHARACTER_INSTANCE_TYPE = 0x7D473C17
# Family-4 slot 1 profile: PS3 wrapper 0x80801743 checksum 0xEB4B8439 -> inner 0x80801714, 18 fields.
PROFILE_INSTANCE_TYPE = 0xEB4B8439
PROFILE_FIELD_COUNT = 18
PROFILE_SOID = 0xD100000000000201
QUEUEZ_FLAG_DELTA = 0x00
# version: the client's family-4 registry version is the Director's "epoch" (invctx+0x4370). The node container
# (class D) starts with consumed epoch 0 and only runs its node pass when the manager's consumed
# epoch differs from it (gate), so a baseline at version 0 never produces activity nodes: start at 1.
FAMILY4_STATE = {"version": 1, "pushed_character": False}
INVESTMENT_ZERO_COMPOSITE_BODY = bytes.fromhex("1800000000")
INVESTMENT_206_FAMILY3_EMPTY_ROSTER = bytes.fromhex(
    "180190000000080000001e880000000000000800000000080000000d156163a688000000000000080000004f440000000000000600")

TYPE_QUEUEZ_OBJECT = 0x007B       # queuez_to_client_update_notification (server push, no status)
QUEUEZ_FAMILY_CHARACTER = 3
QUEUEZ_FAMILY_ACCOUNT = 4
QUEUEZ_FLAG_BASELINE = 0x01
# The wire instance_type is checked per family against the checksums of the family's six object
# slots. PS3 01.24 family-4 slot 0 resolves to the account
# WRAPPER schema 0x80801803, whose record checksum is 0xB5DF2907 (record: 1 field, child
# 0x808018c7). 0xB1AD1C50 is the inner schema 0x808018c7 (26 fields) and fails with error 3 (PIGEON),
# as does the PS4 value 0x64AE75BF (absent from the PS3 image). The payload is the inner RSAT: the
# wrapper's single field carries no presence bit.
ACCOUNT_INSTANCE_TYPE = 0xB5DF2907
ACCOUNT_INSTANCE_TYPE_INNER = 0xB1AD1C50
ACCOUNT_INSTANCE_TYPE_PS4 = 0x64AE75BF
ROSTER_INSTANCE_TYPE = 0xA2AC2C74
ACCOUNT_FIELD_COUNT = 26   # PS3 inner account schema 0x808018c7 (PS4 01.29: 25)
ROSTER_FIELD_COUNT = 4


def _pack_bits(bits: list[int]) -> bytes:
    bits = bits + [0] * (-len(bits) % 8)
    return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))


def _character_list_bits(key: int, characters: list[int]) -> list[int]:
    """RSAT fields 0-1 shared by the roster and the account (sibling character_list_bits)."""
    bits = [1] + [(key >> i) & 1 for i in reversed(range(64))]
    bits += [1] + [(len(characters) >> i) & 1 for i in reversed(range(4))]
    for c in characters:
        bits += [(c >> i) & 1 for i in reversed(range(64))]
    return bits


def roster_rsat(account_soid: int, characters: list[int]) -> bytes:
    return _pack_bits(_character_list_bits(account_soid, characters) + [0] * (ROSTER_FIELD_COUNT - 2))


def account_rsat_no_profile(account_soid: int, characters: list[int]) -> bytes:
    """Account object with field 2 and fields 3.. (the profile SOID) absent - 0 characters and no
    profile is the state the sibling found makes the client run character creation."""
    return _pack_bits(_character_list_bits(account_soid, characters) + [0] + [0] * (ACCOUNT_FIELD_COUNT - 3))


def set_account_field_count(n: int) -> None:
    global ACCOUNT_FIELD_COUNT
    ACCOUNT_FIELD_COUNT = n


def queuez_object_body(family: int, root: int, instance_type: int, soid: int, payload: bytes) -> bytes:
    return (struct.pack(">IIQIBI", 1, family, root, 0, QUEUEZ_FLAG_BASELINE, 1)
            + struct.pack(">IQI", instance_type, soid, len(payload)) + payload)


TYPE_NAMES = {
    0x0079: "setup (0x79)",
    0x012E: "setup (0x12e)",
    0x012C: "peer address request (0x12c)",
    TYPE_WORLD_SERVER_REQUEST: "client_to_world_server_request",
    TYPE_ECHO_REQUEST: "client_to_bap_echo_request",
    TYPE_SUBSCRIPTION_REQUEST: "client_to_bap_subscription_request",
    TYPE_UNSUBSCRIBE_REQUEST: "client_to_bap_unsubscribe_request",
    TYPE_XETROV_REQUEST: "client_to_xetrov_request (no response)",
    TYPE_UPO_REQUEST: "client_to_bap_update_purchased_offers_request",
    TYPE_USER_MSG_REQUEST: "bap_to_client_user_message_request",
    TYPE_ACCOUNT_ID_XLAT_REQUEST: "client_to_bap_account_id_translation_request",
    TYPE_CLIENT_CONFIG_REQUEST: "client_to_bap_client_config_request",
    TYPE_MM_REQUEST: "client_to_bap_update_matchmaking_core_request",
    TYPE_AH_PROXY_REQUEST: "client_to_bap_get_activity_host_proxy_request",
}


def _varint(v: int) -> bytes:
    out = bytearray()
    while True:
        b, v = v & 0x7F, v >> 7
        out.append(b | (0x80 if v else 0))
        if not v:
            return bytes(out)


def _proto_varints(buf: bytes) -> dict:
    """Top-level varint fields of a protobuf message (length-delimited fields are skipped)."""
    out, i = {}, 0
    while i < len(buf):
        tag = 0
        for sh in range(0, 64, 7):
            tag |= (buf[i] & 0x7F) << sh
            i += 1
            if not buf[i - 1] & 0x80:
                break
        val = 0
        if tag & 7 == 0:
            for sh in range(0, 64, 7):
                val |= (buf[i] & 0x7F) << sh
                i += 1
                if not buf[i - 1] & 0x80:
                    break
            out[tag >> 3] = val
        elif tag & 7 == 2:
            n = 0
            for sh in range(0, 64, 7):
                n |= (buf[i] & 0x7F) << sh
                i += 1
                if not buf[i - 1] & 0x80:
                    break
            i += n
        else:
            break
    return out


def mm_response_body(kind: int, nonce: int) -> bytes:
    """Message 43: echo kind and nonce; kind 4 (configuration) -> field 4 with an empty tuning submessage, kind 2
    (update_advertisement, sent when the client hosts a social space) -> field 5 {1: u64} advertisement ack [U]."""
    if kind == 2:
        tail = b"\x2a" + _varint(len(MM_AD_ID)) + MM_AD_ID
    else:   # f4 {1: tuning {field: varint}}; the client copies every tuning value, 0 when absent
        tuning = b"".join(_varint(f << 3) + _varint(v) for f, v in sorted(MM_TUNING.items()))
        tuning = b"\x0a" + _varint(len(tuning)) + tuning
        tail = b"\x22" + _varint(len(tuning)) + tuning
    return b"\x08" + _varint(kind) + b"\x10" + _varint(nonce) + tail


MM_AD_ID = b"\x08\x01"   # field 5 body: {1: advertisement id 1}
MM_TUNING = {}            # --mm-tuning FIELD=VALUE,...: 0x002b f4.1 varint fields (1..9)


def _nonce(base: bytes, counter: int) -> bytes:
    """Add ``counter`` to the nonce as a little-endian integer starting at byte 0."""
    n = bytearray(base)
    carry = counter
    for i in range(len(n)):
        if not carry:
            break
        v = n[i] + (carry & 0xFF)
        n[i] = v & 0xFF
        carry = (carry >> 8) + (v >> 8)
    return bytes(n)


def investment_fields(fields: list[tuple[int, int]]) -> bytes:
    """Bit-packed investment argument stream: per field ``1`` then ``bits`` of value, MSB first."""
    bits: list[int] = []
    for value, width in fields:
        bits.append(1)
        bits.extend((value >> i) & 1 for i in reversed(range(width)))
    while len(bits) % 8:
        bits.append(0)
    return bytes(int("".join(map(str, bits[i:i + 8])), 2) for i in range(0, len(bits), 8))


class Channel:
    """One client connection's mode-1 channel, derived from the 0x1a record we sent."""

    def __init__(self, record: bytes, conn_key: bytes = bytes(16)) -> None:
        self.record = bytes(record)
        (length,) = struct.unpack(">I", record[:4])
        clen = length - 48
        iv, ct = record[4:0x14], record[0x14:0x14 + clen]
        dec = Cipher(algorithms.AES(conn_key), modes.CBC(iv)).decryptor()
        self.plaintext = dec.update(ct) + dec.finalize()
        self.key = self.plaintext[12:28]
        self.recv_base = self.plaintext[0:12]          # client -> us uses the toggled copy
        send = bytearray(self.plaintext[0:12])
        send[11] ^= 1
        self.client_send_base = bytes(send)
        self.gcm = AESGCM(self.key)
        self.rx = 0   # frames received from the client
        self.tx = 0   # frames we sent
        self.buf = b""
        self.push_seq = 0   # sequence numbers of server-originated pushes

    def feed(self, data: bytes) -> list[bytes]:
        """Buffer raw TCP bytes; return the decrypted plaintext of each complete mode-1 frame."""
        self.buf += data
        out = []
        while len(self.buf) >= 6 and self.buf[:2] == b"\x01\x01":
            (size,) = struct.unpack(">I", self.buf[2:6])
            if len(self.buf) < 6 + size:
                break
            rec, self.buf = self.buf[6:6 + size], self.buf[6 + size:]
            tag, ct = rec[:16], rec[16:]
            out.append(self.gcm.decrypt(_nonce(self.client_send_base, self.rx), ct + tag, None))
            self.rx += 1
        return out

    def seal(self, plaintext: bytes) -> bytes:
        sealed = self.gcm.encrypt(_nonce(self.recv_base, self.tx), plaintext, None)
        self.tx += 1
        ct, tag = sealed[:-16], sealed[-16:]
        return b"\x01\x01" + struct.pack(">I", 16 + len(ct)) + tag + ct


def describe(pt: bytes) -> str:
    t, seq = struct.unpack(">HI", pt[:6])
    body = pt[6:]
    extra = ""
    if t == TYPE_WORLD_SERVER_REQUEST and len(body) >= 2:
        extra = f" investment_msg={struct.unpack('>H', body[:2])[0]}"
    printable = "".join(chr(c) if 32 <= c < 127 else "." for c in body)
    return (f"type=0x{t:04x} ({TYPE_NAMES.get(t, '?')}) seq={seq}{extra} "
            f"body[{len(body)}]={body.hex()} |{printable}|")


def investment_id(pt: bytes) -> int | None:
    t = struct.unpack(">H", pt[:2])[0]
    if t == TYPE_WORLD_SERVER_REQUEST and len(pt) >= 8:
        return struct.unpack(">H", pt[6:8])[0]
    return None


def reply_for(pt: bytes, account_soid: int, body_503: bytes | None = None) -> bytes | None:
    """Plaintext reply for a decrypted client frame, or None to stay silent.

    ``account_soid`` is only used by the fallback 503 body (present bit + u64), which PS3 rejects;
    the default is the sibling's pinned body, whose SOID is 0xD100000000000001.
    """
    t, seq = struct.unpack(">HI", pt[:6])
    body = pt[6:]
    if t == TYPE_ECHO_REQUEST:
        return struct.pack(">HIH", TYPE_ECHO_RESPONSE, seq, STATUS_OK) + body
    if t == TYPE_SUBSCRIPTION_REQUEST:
        return struct.pack(">HIH", TYPE_SUBSCRIPTION_RESPONSE, seq, STATUS_OK)
    if t == TYPE_UNSUBSCRIBE_REQUEST:
        return struct.pack(">HIH", TYPE_UNSUBSCRIBE_RESPONSE, seq, STATUS_OK)
    if t == 0x012C and PEER_ADDR_REPLY:   # public AH: {u16 36, bdCommonAddr of the peer, u16}; reply modelled on 0x12e -> 0x12f [U]
        return struct.pack(">HIH", 0x012D, seq, STATUS_OK)
    if t == TYPE_AH_PROXY_REQUEST and len(body) >= 8:
        import socket as _s
        ip, port = AH_PROXY
        return (struct.pack(">HIH", TYPE_AH_PROXY_RESPONSE, seq, STATUS_OK) + body[:8]
                + _s.inet_aton(ip) + struct.pack(">I", port))
    if t == TYPE_MM_REQUEST:
        f = _proto_varints(body)
        return struct.pack(">HIH", TYPE_MM_RESPONSE, seq, STATUS_OK) + mm_response_body(f.get(2, 4), f.get(3, 0))
    if t == TYPE_CLIENT_CONFIG_REQUEST:
        return struct.pack(">HIH", TYPE_CLIENT_CONFIG_RESPONSE, seq, STATUS_OK) + CLIENT_CONFIG_RESPONSE_BODY
    if t == TYPE_ACCOUNT_ID_XLAT_REQUEST and len(body) >= 4:
        count = struct.unpack(">H", body[:2])[0]
        ids = [body[4 + 36 * i:4 + 36 * (i + 1)].ljust(36, b"\0") for i in range(count)]
        return (struct.pack(">HIH", TYPE_ACCOUNT_ID_XLAT_RESPONSE, seq, STATUS_OK)
                + struct.pack(">HBB", count, 7, 0xFF) + b"".join(ids)
                + b"".join(struct.pack(">Q", account_soid) for _ in ids))
    if t == TYPE_UPO_REQUEST:
        return struct.pack(">HIH", TYPE_UPO_RESPONSE, seq, STATUS_OK)
    if t == TYPE_USER_MSG_REQUEST:
        return struct.pack(">HIH", TYPE_USER_MSG_RESPONSE, seq, STATUS_OK) + USER_MSG_RESPONSE_BODY
    if t == TYPE_WORLD_SERVER_REQUEST and len(body) >= 2:
        (msg,) = struct.unpack(">H", body[:2])
        head = struct.pack(">HIHH", TYPE_WORLD_SERVER_RESPONSE, seq, STATUS_OK, msg)
        if msg == INVESTMENT_503:
            return head + (body_503 if body_503 is not None else unlock_body(503))
        if msg == INVESTMENT_206:
            # request args: 4-bit leaf (family + 1), then the key; serve only what was asked for
            family = (body[2] >> 4) - 1 if len(body) > 2 else -1
            if family == 3:
                return head + fetch_family_response_body(family3_baseline_body())
            return head + INVESTMENT_206_NO_SPAN
        if msg == INVESTMENT_205:
            return head + unlock_body(205)
        if msg == INVESTMENT_501:
            bits = [0, 0, 0, 1] + [(0x80000000 >> i) & 1 for i in reversed(range(32))]
            bits += [(NEW_CHARACTER_SOID >> i) & 1 for i in reversed(range(64))]
            if NEW_CHARACTER_SOID not in CHARACTERS:
                CHARACTERS.append(NEW_CHARACTER_SOID)
            CHARACTER_IDENTITY[NEW_CHARACTER_SOID] = identity_from_501(body[2:])
            CHARACTER_CREATION[NEW_CHARACTER_SOID] = bytes(body[2:])   # replayed as identity + customization
            return head + _pack_bits(bits)
        if msg == INVESTMENT_402 and len(body) >= 11:
            bits = int.from_bytes(body[2:11], "big")
            dismantle_item((bits >> 7) & ((1 << 64) - 1))
            return head + INVESTMENT_ZERO_COMPOSITE_BODY
        if msg == INVESTMENT_403 and len(body) >= 10:
            equip_item(struct.unpack(">Q", body[2:10])[0])
            return head + INVESTMENT_ZERO_COMPOSITE_BODY
        if msg == INVESTMENT_801 and len(body) >= 11:
            select_talent_node(struct.unpack(">Q", body[2:10])[0], body[10] - 0x80)
            return head + INVESTMENT_ZERO_COMPOSITE_BODY
        if msg in INVESTMENT_ZERO_COMPOSITE_IDS:
            return head + INVESTMENT_ZERO_COMPOSITE_BODY
    return None


FAMILY4_PUSH_MODE = "account"   # "account" | "empty" (object_count 0 probe) | "none"


def pushes_after(pt: bytes, account_soid: int = 0xD100000000000001) -> list[tuple[int, bytes]]:
    """Server pushes to send right after answering ``pt``, as (type, body) pairs.

    After acknowledging the family-4 (account) subscription the client waits for a QueueZ
    baseline for that family; without one it times out ("character servers" CHICKEN, run
    timing-resume-206-family3-20260927-222149). The sibling pushes the account-only body here.
    """
    t = struct.unpack(">H", pt[:2])[0]
    body = pt[6:]
    if (t == TYPE_WORLD_SERVER_REQUEST and len(body) >= 10
            and struct.unpack(">H", body[:2])[0] in (INVESTMENT_402, INVESTMENT_403, INVESTMENT_801) and ITEMS):
        # the server is authoritative for the equipped state: re-state family 4 (profile + items)
        # and the family-0 peer view whose equipment summary mirrors it
        out = [(TYPE_QUEUEZ_OBJECT, family4_inventory_delta(account_soid))]
        if SERVE_PEER:
            FAMILY_VERSIONS[0] += 1
            out.append((TYPE_QUEUEZ_OBJECT, family_body(0, account_soid, FAMILY_VERSIONS[0], QUEUEZ_FLAG_DELTA,
                                                         family_objects(0, account_soid))))
        return out
    if (t == TYPE_WORLD_SERVER_REQUEST and len(body) >= 2 and struct.unpack(">H", body[:2])[0] == INVESTMENT_501
            and CHARACTERS and not FAMILY4_STATE["pushed_character"]):
        FAMILY4_STATE["pushed_character"] = True
        return [(TYPE_QUEUEZ_OBJECT, family4_character_delta(account_soid))]
    if t == TYPE_SUBSCRIPTION_REQUEST and len(body) == 9:
        family, root = body[0], struct.unpack(">Q", body[1:9])[0]
        if family in EMPTY_FAMILIES and SERVE_PEER:
            return [(TYPE_QUEUEZ_OBJECT, family_body(family, root, 0, QUEUEZ_FLAG_BASELINE,
                                                     family_objects(family, root)))]
        if family in EMPTY_FAMILIES:
            return [(TYPE_QUEUEZ_OBJECT, struct.pack(">IIQIBI", 1, family, root, 0, QUEUEZ_FLAG_BASELINE, 0))]
        if family == QUEUEZ_FAMILY_ACCOUNT and FAMILY4_PUSH_MODE == "empty":
            return [(TYPE_QUEUEZ_OBJECT, struct.pack(">IIQIBI", 1, QUEUEZ_FAMILY_ACCOUNT, root, 0,
                                                     QUEUEZ_FLAG_BASELINE, 0))]
        if family == QUEUEZ_FAMILY_ACCOUNT and FAMILY4_PUSH_MODE == "account" and CHARACTERS:
            # existing characters (--bap-account-from): the baseline already carries the account, the
            # profile and the inventory that the creation delta would otherwise deliver
            FAMILY4_STATE["pushed_character"] = True
            return [(TYPE_QUEUEZ_OBJECT, family4_existing_baseline(root))]
        if family == QUEUEZ_FAMILY_ACCOUNT and FAMILY4_PUSH_MODE == "account":
            # new account: this baseline carries version 0, so the creation delta must be version 1 (a gap makes
            # the client drop the connection, PORPOISE)
            FAMILY4_STATE["version"] = 0
            return [(TYPE_QUEUEZ_OBJECT, queuez_object_body(
                QUEUEZ_FAMILY_ACCOUNT, root, ACCOUNT_INSTANCE_TYPE, root, account_rsat_no_profile(root, [])))]
    return []


def push_frame(ch: "Channel", msg_type: int, body: bytes) -> bytes:
    plain = struct.pack(">HI", msg_type, ch.push_seq) + body
    ch.push_seq += 1
    return plain


def fetch_family_response_body(span: bytes | None) -> bytes:
    """206 reply body: 4-bit leaf (biased +1), presence bit, u16 span length, span; MSB-first."""
    bits = [0, 0, 0, 1]
    if span is None:
        bits.append(0)
    else:
        bits.append(1)
        bits += [(len(span) >> i) & 1 for i in reversed(range(16))]
        for b in span:
            bits += [(b >> i) & 1 for i in reversed(range(8))]
    return _pack_bits(bits)


def family3_roster_body(account_soid: int = 0xD100000000000001) -> bytes:
    roster = roster_rsat(account_soid, CHARACTERS)
    return queuez_object_body(QUEUEZ_FAMILY_CHARACTER, account_soid, ROSTER_INSTANCE_TYPE, account_soid, roster)


def character_rsat(soid: int, identity: tuple[int, int, int]) -> bytes:
    """Sibling character_rsat (oracle vector e880000000000080f0181c0000 for 0xD1..0101, (0, 1, 0)):
    1 + u64 soid, identity block present, 3 x (1 + u8 value+0x80), 4 absent fields."""
    bits = [1] + [(soid >> i) & 1 for i in reversed(range(64))] + [1]
    for v in identity:
        bits += [1] + [((v + 0x80) >> i) & 1 for i in reversed(range(8))]
    return _pack_bits(bits + [0, 0, 0, 0])


def identity_from_501(args: bytes) -> tuple[int, int, int]:
    """First 27 bits of the 501 request: {race, gender, class}, each presence bit + u8 biased 0x80."""
    bits = [(x >> i) & 1 for x in args[:4] for i in reversed(range(8))]
    return tuple(int("".join(map(str, bits[9 * k + 1:9 * k + 9])), 2) - 0x80 for k in range(3))


def family3_baseline_body(account_soid: int = 0xD100000000000001) -> bytes:
    """Roster (+ one character object per created character) for family 3."""
    objs = [(ROSTER_INSTANCE_TYPE, account_soid, roster_rsat(account_soid, CHARACTERS))]
    for c in CHARACTERS:
        ident = CHARACTER_IDENTITY.get(c, (0, 0, 0))
        objs.append((CHARACTER_INSTANCE_TYPE, c,
                     character_card_rsat(c, ident) if CHAR_STATS else character_rsat(c, ident)))
    b = struct.pack(">IIQIBI", 1, QUEUEZ_FAMILY_CHARACTER, account_soid, 0, QUEUEZ_FLAG_BASELINE, len(objs))
    for t, soid, payload in objs:
        b += struct.pack(">IQI", t, soid, len(payload)) + payload
    return b


def profile_rsat(profile_soid: int) -> bytes:
    """Sibling profile_rsat: field 0 = profile SOID, the other 17 fields absent."""
    return _pack_bits([1] + [(profile_soid >> i) & 1 for i in reversed(range(64))] + [0] * (PROFILE_FIELD_COUNT - 1))


def account_rsat(account_soid: int, characters: list[int], profile_soid: int) -> bytes:
    """Account with its character list and field 3 = profile SOID (sibling account_rsat; PS3 has
    26 fields, so 22 trailing absent bits instead of PS4's 21)."""
    if UNLOCK_FLAGS or ACCOUNT_DENSE or ACCOUNT_DENSE10:   # field 12 sparse {u64, flags {u7 n; 64 x flag}, values}; 14 dense
        import rsat
        values = {0: account_soid, 1: {0: len(characters), 1: list(characters)}, 3: profile_soid,
                  12: {1: {0: len(UNLOCK_FLAGS), 1: [{0: i, 1: UNLOCK_OWNED_RAW} for i in UNLOCK_FLAGS]},
                       2: {0: len(UNLOCK_VALUES), 1: [{0: i, 1: v} for i, v in UNLOCK_VALUES]}}}
        if ACCOUNT_DENSE10:
            values[10] = [UNLOCK_OWNED_RAW if i in ACCOUNT_DENSE10 else None for i in range(2560)]
        if ACCOUNT_DENSE:
            values[14] = {1: [UNLOCK_OWNED_RAW if i in ACCOUNT_DENSE else None for i in range(256)]}
        if any(it["scope"] == "a" for it in ITEMS):   # field 6: {u32 count, 326 x 0x808016E0} account slots
            slots = [{0: -1} for _ in range(ACCOUNT_SLOTS)]
            for it in ITEMS:
                if it["scope"] == "a":
                    slots[it["slot"]] = {0: it["ci"], 1: it["soid"]}
                    if it.get("qty") is not None:
                        slots[it["slot"]][2] = it["qty"]
            values[6] = {0: ACCOUNT_SLOTS, 1: slots}
        return rsat.encode(0x808018C7, values)
    bits = _character_list_bits(account_soid, characters) + [0]
    bits += [1] + [(profile_soid >> i) & 1 for i in reversed(range(64))]
    return _pack_bits(bits + [0] * (ACCOUNT_FIELD_COUNT - 4))


def family4_character_delta(account_soid: int = 0xD100000000000001) -> bytes:
    """Family-4 delta after character creation: account listing the characters + the profile."""
    FAMILY4_STATE["version"] += 1
    if ITEMS or PROGRESSIONS:   # inventory rides the creation delta (the profile it names is born with it)
        FAMILY4_STATE["version"] -= 1
        return family4_inventory_delta(account_soid)
    objs = [(ACCOUNT_INSTANCE_TYPE, account_soid, account_rsat(account_soid, CHARACTERS, PROFILE_SOID)),
            (PROFILE_INSTANCE_TYPE, PROFILE_SOID, profile_rsat(PROFILE_SOID))]
    b = struct.pack(">IIQIBI", 1, QUEUEZ_FAMILY_ACCOUNT, account_soid, FAMILY4_STATE["version"],
                    QUEUEZ_FLAG_DELTA, len(objs))
    for t, soid, payload in objs:
        b += struct.pack(">IQI", t, soid, len(payload)) + payload
    return b


# ---- Character appearance: level, Light, emblem (descriptor-driven, server/rsat.py) ------------
# The 0x80801855 block (level u32 @+0, stat table [12] 16 x {i8 key, i32 value}, 20 x 48 B
# equipment summary [6]) is carried by the family-3/1 select card at +0x68 and the family-0/1 peer
# view at +0x30; the orbit character screen reads family 0 (mode 4), the select
# tiles read family 3. Sentinels: content index / arrangement -1 (0xFFFF) = empty, stat key -1
# (0xFF) = unused entry (a 0 key would overwrite Light with 0). Emblem = equipment slot 12.
CHAR_STATS = None           # {"level": 40, "light": 385, "emblem": 1512} when enabled
SERVE_PEER = False          # populate families 0 and 2 instead of empty baselines
CARD_KEY = 0xD100000000000501   # family 0/1 + 2/1 key; the 0/0 and 2/0 contacts link to it
CONTACT_NAME = "guardian"
EMBLEM_SLOT = 12
CARD_TAG, PEER_TAG = 0x80801954, 0x808017FD
PEER_CONTACT_TAG, DIRECTORY_CONTACT_TAG, DIRECTORY_CARD_TAG = 0x80801921, 0x808018B7, 0x80801810
FAMILY_VERSIONS = {0: 0, 2: 0}


def appearance_block(level: int, light: int, emblem: int | None) -> dict:
    equipment = [{1: -1, 3: -1} for _ in range(20)]
    if emblem is not None:
        equipment[EMBLEM_SLOT] = {1: emblem, 3: -1}
    for it in ITEMS:   # equipped inventory mirrors into the summary at its ordinal
        if it["equipped"] is not None:
            entry = {0: it["soid"], 1: it["ci"], 3: -1}
            if ITEM_ART:   # [3] art arrangement, [5] 6 x {i8 channel, i16 dye} (tools/item_art.py)
                entry[3] = art_arrangement(it["ci"])
                if ART_DYES:
                    entry[5] = item_dyes(it["ci"])
            equipment[it["equipped"]] = entry
    stats = [{0: 0, 1: light}] + [{0: -1} for _ in range(15)]
    return {0: level, 2: float(level), 6: equipment, 12: stats}


def _trailer(emblem: int | None) -> dict:
    return {2: emblem if emblem is not None else -1}


def character_card_rsat(soid: int, identity: tuple[int, int, int]) -> bytes:
    import rsat
    s = CHAR_STATS
    ident, custom = _creation(soid)
    return rsat.encode(CARD_TAG, {0: soid, 1: ident, 2: custom,
                                  4: appearance_block(s["level"], s["light"], s["emblem"]),
                                  5: _trailer(s["emblem"])})


def _creation(soid: int):
    """(identity dict, customization dict or None) replayed from the character's 501 request.
    0x80801860 = {0x808017FC identity, 0x8080181A customization, char[17] name}: the first two are
    literally fields 1 and 2 of the card / peer view / profile."""
    args = CHARACTER_CREATION.get(soid)
    if args:
        import rsat
        d, _ = rsat.decode(0x80801860, args)
        return d[0], d[1]
    return dict(enumerate(CHARACTER_IDENTITY.get(soid, (0, 0, 0)))), None


def _identity() -> tuple[int, int, int]:
    if not CHARACTERS:
        return (0, 0, 0)
    ident, _ = _creation(CHARACTERS[0])
    return (ident[0], ident[1], ident[2])


def _customization():
    return _creation(CHARACTERS[0])[1] if CHARACTERS else None


def _contact(tag: int, account_soid: int) -> bytes:
    import rsat
    name = [ord(c) for c in CONTACT_NAME[:26]]
    return rsat.encode(tag, {0: account_soid, 1: CARD_KEY, 2: name, 3: [0] * 5})


def family_objects(family: int, account_soid: int) -> list[tuple[int, int, bytes]]:
    """(instance_type, soid, payload) for the populated family 0 (peer) / 2 (directory)."""
    import rsat
    s = CHAR_STATS or {"level": 1, "light": 0, "emblem": None}
    if family == 0:
        peer = rsat.encode(PEER_TAG, {0: CARD_KEY, 1: dict(enumerate(_identity())), 2: _customization(),
                                      3: appearance_block(s["level"], s["light"], s["emblem"]),
                                      4: _trailer(s["emblem"])})
        return [(rsat.checksum(PEER_CONTACT_TAG), account_soid, _contact(PEER_CONTACT_TAG, account_soid)),
                (rsat.checksum(PEER_TAG), CARD_KEY, peer)]
    if family == 2:
        card = rsat.encode(DIRECTORY_CARD_TAG, {0: CARD_KEY, 1: -1,
                                                3: {0: s["level"], 1: s["light"], 2: _trailer(s["emblem"])}})
        return [(rsat.checksum(DIRECTORY_CONTACT_TAG), account_soid, _contact(DIRECTORY_CONTACT_TAG, account_soid)),
                (rsat.checksum(DIRECTORY_CARD_TAG), CARD_KEY, card)]
    return []


def family_body(family: int, root: int, version: int, flags: int, objs) -> bytes:
    b = struct.pack(">IIQIBI", 1, family, root, version, flags, len(objs))
    for t, soid, payload in objs:
        b += struct.pack(">IQI", t, soid, len(payload)) + payload
    return b


def resume_pushes(account_soid: int) -> list[tuple[int, bytes]]:
    """Deltas re-stating families 0/2 on a savestate resume (their baselines were already sent)."""
    out = []
    if ITEMS or PROGRESSIONS:
        out.append((TYPE_QUEUEZ_OBJECT, family4_inventory_delta(account_soid)))
    for fam in (0, 2):
        FAMILY_VERSIONS[fam] += 1
        out.append((TYPE_QUEUEZ_OBJECT, family_body(fam, account_soid, FAMILY_VERSIONS[fam], QUEUEZ_FLAG_DELTA,
                                                    family_objects(fam, account_soid))))
    return out


# ---- Inventory: profile slot array + family-4/3 item elements ------------------------------------
# Profile (inner 0x80801714) field 3 = {i32 count, 320 x 0x808016E0 {i16 content index, u64 item
# SOID, 3 x u32}}; the slot index picks the bucket (content table: 93-102 Primary, 103-112 Special,
# 113-122 Heavy, 43-92 armor). Field 5 = 20 x u64 equipped item SOIDs. Each named SOID must resolve
# to a family-4 item object 0x80801732 (instance type = its checksum 0x0EB6AC38, [I]).
ITEMS = []                  # [{"soid", "ci", "slot", "scope" p/a, "equipped", "qty"}]
ACCOUNT_SLOTS = 326         # account field 6 = {u32 count, 326 x 0x808016E0} (sibling: account+0x4C8)
PROGRESSIONS = []           # [(ordinal, progress points)]; sibling: 117 = character_level, 346000 = 40
ITEM_TAG = 0x80801732
PROFILE_INNER_TAG = 0x80801714
PROFILE_SLOTS = 320
ITEM_SOID_BASE = 0xD100000000000301


# Art from the item definitions (an item appearance table, private/item_art.tsv): ci -> ([(class, arr)],
# [(channel, dye)]). Gear record 0x8080030A {i8 class (-1 any), u8, u16 arrangement}: Gjallarhorn
# -> 1229, the PS4 sibling's measured value. 0x808018EA {i8 channel, u8, u16 dye} is read as the
# default dyes (channels 0-2 armour/shader, 5-6 weapon, 10-11 ship, 14 sparrow, 15 ghost) [U].
ITEM_ART = {}
ART_DYES = False            # also fill appearance equipment [5]
# Talent grids (item_art.tsv column 5): item field 4 [2] = grid
# index into 012f entry 4650, [3] = 36 node states, [4] = 8 step rolls; top-level [5]/[6] = 8 stat
# keys / values. ITEM_GRIDS: None = send -1 (no grid), "grid" = real index, "full" = + zeroed arrays.
ITEM_GRID = {}
ITEM_GRIDS = None
ITEM_NODES = {}             # soid -> 36 node states (0 = not unlocked, k = k-th step), set by 801


def select_talent_node(soid: int, node: int) -> None:
    """Investment 801: unlock/select one talent-grid node of an item (no currency cost modelled)."""
    print(f"   [bap] talent node select soid={soid:#x} node={node}", flush=True)
    if 0 <= node < 36:
        ITEM_NODES.setdefault(soid, [0] * 36)[node] = 1
DYE_SLOTS = 6


def load_item_art(path: str) -> None:
    with open(path) as fh:
        for line in fh:
            f = line.rstrip("\n").split("\t")
            if not f[0].isdigit() or len(f) < 4:
                continue
            pairs = lambda s: [tuple(int(v) for v in x.split(":")) for x in s.split(",") if x != "-"]
            ITEM_ART[int(f[0])] = (pairs(f[2]), pairs(f[3]))
            if len(f) > 4 and f[4].lstrip("-").isdigit():
                ITEM_GRID[int(f[0])] = int(f[4])


def art_arrangement(ci: int) -> int:
    """First gear-record entry for the character's class or any class (sibling FUN_00289E80);
    -1 (no art) when the item has none. Identity = (race, gender, class), Titan = 0."""
    cls = _identity()[2]
    for c, arr in ITEM_ART.get(ci, ([], []))[0]:
        if c in (-1, cls):
            return arr
    return -1


ARMOUR_DYE_KEYS = (0, 1, 2)
DYE_CLASS_FILTER = False    # keys 0/1/2 read as class (keep only the character's) instead of channel


def item_dyes(ci: int) -> list:
    pairs = ITEM_ART.get(ci, ([], []))[1]
    if DYE_CLASS_FILTER:
        cls = _identity()[2]
        pairs = [(k, d) for k, d in pairs if k not in ARMOUR_DYE_KEYS or k == cls]
    dyes = [{0: ch, 1: dye} for ch, dye in pairs[:DYE_SLOTS]]
    return dyes + [{0: -1, 1: -1}] * (DYE_SLOTS - len(dyes))


def parse_items(spec: str) -> None:
    """'2221@93e6,2229@103,869@163q500' -> content index @ profile slot; 'eN' = equipped at equipment
    ordinal N; 'qN' = stack quantity N (slot element field 2, summed per bucket by the client - how
    currencies such as Glimmer, ci 869, are held). The equipped array is indexed by the item
    definition's own ordinal (sibling: Primary 6, Special 7, Heavy 8, Helmet 1..Class 5, Ghost 11,
    emblem 12), not by list order.
    A slot written 'aN' is account slot N (account field 6, 326 slots; account-wide items such as
    Glimmer); otherwise it is a profile (character) slot."""
    for i, tok in enumerate(t for t in spec.split(",") if t):
        ci, rest = tok.split("@")
        scope = "a" if rest.startswith("a") else "p"
        rest, _, qty = rest.lstrip("a").partition("q")
        slot, _, eq = rest.partition("e")
        ITEMS.append({"soid": ITEM_SOID_BASE + i, "ci": int(ci), "slot": int(slot), "scope": scope,
                      "equipped": int(eq) if eq else None, "qty": int(qty) if qty else None})


def profile_inventory_rsat() -> bytes:
    import rsat
    slots = [{0: -1} for _ in range(PROFILE_SLOTS)]
    for it in ITEMS:
        if it["scope"] != "p":
            continue
        slots[it["slot"]] = {0: it["ci"], 1: it["soid"]}
        if it.get("qty") is not None:
            slots[it["slot"]][2] = it["qty"]
    custom = _customization()
    if DESTINATION is not None:   # 0x8080181A [10]: last_orbited_destination (PS4 name) [U] on PS3
        custom = {**(custom or {}), 10: DESTINATION}
    values = {0: PROFILE_SOID, 1: dict(enumerate(_identity())), 2: custom,
              3: {0: PROFILE_SLOTS, 1: slots}}
    if CURRENT_ACTIVITY is not None:   # field 6 [0] u16 at +0x29A0: read by the client [U] semantics
        values[6] = {0: CURRENT_ACTIVITY}
    if PROFILE_DENSE:   # field 11: 2048 x 2-bit dense unlock flags (kind 3)
        values[11] = [UNLOCK_OWNED_RAW if i in PROFILE_DENSE else None for i in range(2048)]
    if PROGRESSIONS:   # field 8: {u7 count; 127 x {progress, daily, weekly, i16 ordinal}}
        values[8] = {0: len(PROGRESSIONS), 1: [{0: pts, 1: 0, 2: 0, 3: ordinal}
                                               for ordinal, pts in PROGRESSIONS]}
    if any(it["equipped"] is not None for it in ITEMS):
        equipped = [0] * 20
        for it in ITEMS:
            if it["equipped"] is not None:
                equipped[it["equipped"]] = it["soid"]
        values[5] = equipped
    return rsat.encode(PROFILE_INNER_TAG, values)


def item_rsat(soid: int, ci: int, level: int = 40) -> bytes:
    """Sibling ItemSpec::resolved defaults: level 40, equip-min 0, state bits 1, progression ordinal
    and talent grid -1 (0 would name entry 0), flag 1; stats absent."""
    import rsat
    inst = {0: {3: -1}, 2: -1, 5: 1}
    values = {0: soid, 1: {0: 0, 1: 1}, 2: {0: level, 1: 0, 2: 0}, 3: ci, 4: inst}
    if ITEM_GRIDS and ITEM_GRID.get(ci, -1) >= 0:
        inst[2] = ITEM_GRID[ci]
        if ITEM_GRIDS == "full":
            inst[3], inst[4] = list(ITEM_NODES.get(soid, [0] * 36)), [0] * 8
            values[5], values[6] = [-1] * 8, [0] * 8
    return rsat.encode(ITEM_TAG, values)


def _family4_extra(account_soid: int) -> list[tuple[int, int, bytes]]:
    """Family-4 type 2 (0x80801046, 72 B, key account SOID) and type 4 (0x8080103C 'unlocks', 3984 B,
    key 0x7FFFFFFFFFFFFFFE): looked up by the client after its gates;
    key-only payloads, byte-identical to the PS4 sibling's."""
    if not FAMILY4_EXTRA:
        return []
    import rsat
    return [(FAMILY42_INSTANCE_TYPE, account_soid,
             rsat.encode(0x80801046, {0: {0: account_soid, 1: [0] * 27, 2: [0] * 5}})),
            (UNLOCKS_INSTANCE_TYPE, UNLOCKS_KEY, rsat.encode(0x8080103C, {0: {0: UNLOCKS_KEY}}))]


def family4_existing_baseline(account_soid: int) -> bytes:
    """Family-4 baseline for an account whose characters already exist (cold boot to character select)."""
    import rsat
    objs = [(ACCOUNT_INSTANCE_TYPE, account_soid, account_rsat(account_soid, CHARACTERS, PROFILE_SOID)),
            (PROFILE_INSTANCE_TYPE, PROFILE_SOID,
             profile_inventory_rsat() if ITEMS or PROGRESSIONS or DESTINATION is not None else profile_rsat(PROFILE_SOID))]
    objs += [(rsat.checksum(ITEM_TAG), it["soid"], item_rsat(it["soid"], it["ci"])) for it in ITEMS]
    objs += _family4_extra(account_soid)
    return family_body(QUEUEZ_FAMILY_ACCOUNT, account_soid, FAMILY4_STATE["version"], QUEUEZ_FLAG_BASELINE, objs)


def family4_inventory_delta(account_soid: int) -> bytes:
    import rsat
    FAMILY4_STATE["version"] += 1
    objs = [(ACCOUNT_INSTANCE_TYPE, account_soid, account_rsat(account_soid, CHARACTERS, PROFILE_SOID)),
            (PROFILE_INSTANCE_TYPE, PROFILE_SOID, profile_inventory_rsat())]
    objs += [(rsat.checksum(ITEM_TAG), it["soid"], item_rsat(it["soid"], it["ci"])) for it in ITEMS]
    objs += _family4_extra(account_soid)
    return family_body(QUEUEZ_FAMILY_ACCOUNT, account_soid, FAMILY4_STATE["version"], QUEUEZ_FLAG_DELTA, objs)


# ---- Unlock flags (205/503 unlock object 0x80801941 field 3: {u6 count; 50 x {i16 index, 2-bit}}) --
# The 205 and 503 bodies share the object and must carry the same list (205 re-answers overwrite
# 503). Wire raw 3 = owned (sibling client-encoded references reproduce byte-for-byte). Candidate bucket flags: 1639 Primary, 1640 Special,
# 1638 Heavy (bucket-def +0x24, [U] semantics). Never blanket-set: {306, 3872, 3876, 3877} poison.
UNLOCK_FLAGS = []
# Unlock VALUES (account field 12 [2] = {u7 n; 64 x {i16 index, i32 value}}) land in the 2048 x u32
# value table read by unlock-VM op 10. Index 34 is read by talent-node cost checks and the
# inventory screen (hook run 2026-09-29) - the Glimmer candidate [U].
UNLOCK_VALUES = []          # [(index, value)]
DESTINATION = None          # profile customization field [10], 32-bit hash (--bap-destination)
CURRENT_ACTIVITY = None     # profile field 6 [0], activity index (--bap-current-activity)
FAMILY4_EXTRA = False       # serve family-4 types 2 and 4 (--bap-family4-extra)
FAMILY42_INSTANCE_TYPE = 0x0ECCD1F8
UNLOCKS_INSTANCE_TYPE = 0xC4060975
UNLOCKS_KEY = 0x7FFFFFFFFFFFFFFE
UNLOCK_OWNED_RAW = 3
# Dense unlock stores, indexed by the flag's sub-index (its position in the kind directory; master
# table 0x808018B8 and directories in 012f entries 4682 / 4681 of the CURRENT generation - the old copy
# in block 162 is stale): kind 1 = account field 10 (arm 4), kind 2 = account field 14 [1] (arm 3),
# kind 3 = profile field 11 (arm 7). The dense arm copies every position, so a kind-1/2 flag set only in
# the sparse list is overwritten with 0: 3262 (Eververse license) = kind 1 sub 1386, 2147 = kind 2 sub 174.
PROFILE_DENSE = []          # sub-indices into profile field 11 (kind 3)
ACCOUNT_DENSE = []          # sub-indices into account field 14 [1] (kind 2)
ACCOUNT_DENSE10 = []        # sub-indices into account field 10 (kind 1)


def unlock_body(msg: int) -> bytes:
    if not UNLOCK_FLAGS:
        return INVESTMENT_503_PINNED if msg == 503 else INVESTMENT_205_BODY
    import rsat
    tag, base = (0x80801825, INVESTMENT_503_PINNED) if msg == 503 else (0x80801827, INVESTMENT_205_BODY)
    d, _ = rsat.decode(tag, base)
    obj = d[4] if msg == 503 else d[1]
    obj[3] = {0: len(UNLOCK_FLAGS), 1: [{0: i, 1: UNLOCK_OWNED_RAW} for i in UNLOCK_FLAGS]}
    return rsat.encode(tag, d)


# Profile slot ranges per equip ordinal (content bucket table, ps3_investment_globals_012f)
ORDINAL_SLOT_RANGES = {0: (40, 3), 1: (43, 10), 2: (53, 10), 3: (63, 10), 4: (73, 10), 5: (83, 10),
                       6: (93, 10), 7: (103, 10), 8: (113, 10), 9: (123, 10), 10: (143, 10), 11: (153, 10),
                       12: (210, 10), 13: (220, 10),   # emblems 0x19, shaders 0x1b (012c bucket table)
                       14: (230, 10), 15: (240, 10)}   # emotes 0x1c, sparrow horns 0x1d (measured by placement)


def _ordinal_of_slot(slot: int):
    for ordinal, (first, n) in ORDINAL_SLOT_RANGES.items():
        if first <= slot < first + n:
            return ordinal
    return None


def equip_item(soid: int) -> None:
    """Investment 403: equip the item at its bucket's ordinal; the previous occupant is unequipped
    (it stays in its backpack slot)."""
    item = next((it for it in ITEMS if it["soid"] == soid), None)
    if item is None:
        return
    ordinal = _ordinal_of_slot(item["slot"])
    if ordinal is None:
        return
    for it in ITEMS:
        if it["equipped"] == ordinal:
            it["equipped"] = None
    item["equipped"] = ordinal


def dismantle_item(soid: int) -> None:
    """Investment 402: the item leaves the inventory (its profile slot empties). Materials / glimmer
    rewards are not modelled."""
    ITEMS[:] = [it for it in ITEMS if it["soid"] != soid]
