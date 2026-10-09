"""Bungie channel messages carried in bdDTLS Data on the public activity host peer link (run pubdtls3).

Framing inside the application payload (after the LE16 N prefix of dtls_peer): per message one byte 0xC0 | type, BE16
size of the message struct, then the bit-packed body; a clear bit ends the list. Registered message types: 4 connect-request (44), 5 connect-response (52),
6 connect-refuse (12), 7 connect-establish (8), 8 connect-closed (12); 9 = join-request (2856), 12 seen with the
security id + a nonce [U name]. connect-request = u32, u32, 36 raw bytes (secure address);
connect-response = u32 x4, 36 raw bytes."""
import struct

NAMES = {0: "ping", 1: "pong", 4: "connect-request", 5: "connect-response", 6: "connect-refuse", 7: "connect-establish",
         8: "connect-closed", 9: "join-request", 12: "type12"}


def describe(app: bytes) -> str:
    """Best-effort listing of the messages in one decrypted payload (only byte-aligned types are walked)."""
    body, out, i = app[2:], [], 0
    while i < len(body) and body[i] & 0x80:
        t, size = body[i] & 0x3F, struct.unpack_from(">H", body, i + 1)[0]
        if t == 4:
            a, b = struct.unpack_from(">2I", body, i + 3)
            out.append(f"connect-request [0]=0x{a:x} [4]=0x{b:x} addr={body[i + 11:i + 47].hex()}")
            i += 47
        elif t == 5:
            out.append(f"connect-response {struct.unpack_from('>4I', body, i + 3)} addr={body[i + 19:i + 55].hex()}")
            i += 55
        elif t == 7:
            out.append(f"connect-establish {struct.unpack_from('>2I', body, i + 3)}")
            i += 11
        else:
            out.append(f"{NAMES.get(t, 'type%d' % t)} size={size} rest={body[i + 3:].hex()}")
            break
    return "; ".join(out) or f"? {body.hex()}"


def connect_request(app: bytes):
    body = app[2:]
    if len(body) >= 47 and body[0] == 0xC4:
        return struct.unpack_from(">2I", body, 3) + (body[11:47],)
    return None


def connect_response(fields, address36: bytes) -> bytes:
    msg = b"\xC5" + struct.pack(">H", 52) + struct.pack(">4I", *fields) + address36 + b"\0"
    return struct.pack("<H", len(msg)) + msg


# --- established channel (packet() reproduces both captured client
# packets byte for byte) ----------------------------------------------------------------------------------------------
class Bits:
    def __init__(self):
        self.s = ""

    def put(self, value, width):
        assert 0 <= value < (1 << width)
        self.s += f"{value:0{width}b}"
        return self

    def raw(self, value):
        self.s += "".join(f"{x:08b}" for x in value)
        return self

    def bytes(self):
        s = self.s + "0" * (-len(self.s) % 8)
        return bytes(int(s[i:i + 8], 2) for i in range(0, len(s), 8))


def envelope(kind, size, body):
    b = Bits().put(kind, 6).put(size, 16)
    b.s += body.s
    return b


def packet(seq, ack, payload=None, tag=0, window=1, index=1, age=1023):
    """Channel packet: 00 | sender counter & 3 | payload sequence present | seq (10) | seq - acked seq (7) | receive
    high-water (7) | ack history 00 + 0 | ack age (10) | [stream 1: fragments {01, index 11, short 1 + 0 + len-1 (8) |
    256 bits}, 00] | second stream absent | extended data absent. Returns (bytes, next fragment index)."""
    b = Bits().put(0, 2).put(tag & 3, 2).put(int(payload is not None), 1)
    b.put(seq & 1023, 10).put(window, 7).put(ack & 127, 7)
    b.put(0, 2).put(0, 1).put(age, 10)
    if payload is not None:
        b.put(1, 1)
        for off in range(0, len(payload.s), 256):
            chunk = payload.s[off:off + 256]
            b.put(1, 2).put(index & 2047, 11)
            if len(chunk) == 256:
                b.put(0, 1)
            else:
                b.put(1, 1).put(0, 1).put(len(chunk) - 1, 8)
            b.s += chunk
            index += 1
        b.put(0, 2)
        b.put(0, 1)
    b.put(0, 1)
    return b.bytes(), index


def establish(receiver_counter, sender_counter):
    return envelope(7, 8, Bits().put(receiver_counter, 32).put(sender_counter, 32))


def parse_header(body: bytes):
    """Header of a channel packet from the client (first two bits 00): dict or None."""
    s = "".join(f"{x:08b}" for x in body[:6])
    if len(body) < 5 or s[:2] != "00":
        return None
    return {"tag": int(s[2:4], 2), "payload": s[4] == "1", "seq": int(s[5:15], 2), "window": int(s[15:22], 2),
            "ack": int(s[22:29], 2)}


class Channel:
    """Our side of one established channel: acknowledge the client's payload sequence and deliver our
    connect-establish until the client acknowledges the packet that carried it."""

    def __init__(self, client_counter, client_seq0, our_counter=0, our_seq0=0x5AFE):
        self.client_counter, self.our_counter = client_counter, our_counter
        self.client_first, self.seq = client_seq0 + 1, our_seq0 + 1
        self.acked = False
        self.last_reply = 0.0
        self.queue = []          # (payload Bits, first fragment index) still to deliver after the establish
        self.index = self.next_index = 2
        self.acked_seq, self.carried, self.last_payload, self.delivered = self.seq, [], 0.0, 0
        self.rx_frags, self.rx_next = {}, 1

    def reply(self, body: bytes, now: float, force=False):
        h = parse_header(body)
        if h is None:
            return None, None
        client_seq = self.client_first + ((h["seq"] - self.client_first) & 1023)
        if not self.acked and h["ack"] == (self.seq & 127):
            self.acked = True
        if not force and now - self.last_reply < 0.1:
            return None, h
        self.last_reply = now
        if not self.acked:
            pkt, _ = packet(self.seq, client_seq, establish(self.client_counter, self.our_counter),
                            tag=self.our_counter, window=1, index=1)
        elif self.queue:
            # one reliable payload at a time: every transmission takes a new payload sequence until the client's
            # ack base reaches a sequence that carried it
            payload, first = self.queue[0]
            if self.carried and h["ack"] in {x & 127 for x in self.carried}:
                self.queue.pop(0)
                self.acked_seq, self.carried, self.delivered = self.seq, [], self.delivered + 1
                pkt, _ = packet(self.seq, client_seq, tag=self.our_counter, window=0)
            elif now - self.last_payload >= 0.3 or not self.carried:
                self.last_payload = now
                self.seq += 1
                self.carried.append(self.seq)
                pkt, nxt = packet(self.seq, client_seq, payload, tag=self.our_counter,
                                  window=min(self.seq - self.acked_seq, 127), index=first)
                self.index = max(self.index, nxt)
            else:
                pkt, _ = packet(self.seq, client_seq, tag=self.our_counter, window=min(self.seq - self.acked_seq, 127))
        else:
            pkt, _ = packet(self.seq, client_seq, tag=self.our_counter, window=0)
        return struct.pack("<H", len(pkt)) + pkt, h

    def receive(self, body: bytes):
        """Messages of the client's first stream completed by this packet: [(type, struct size, body bit string)].
        Fragment index forms: 01 absolute (11 bits), 10 gap (4 bits) + 1, 11 next; a short fragment ends a message."""
        s = "".join(f"{x:08b}" for x in body)
        if len(s) < 46 or s[:2] != "00" or s[4] != "1" or s[42] != "1":
            return []
        p, idx = 43, None
        while s[p:p + 2] not in ("00", "", "0", "1"):
            k = s[p:p + 2]; p += 2
            if k == "01":
                idx = int(s[p:p + 11], 2); p += 11
            elif idx is None:
                return []
            elif k == "10":
                idx += int(s[p:p + 4], 2) + 1; p += 4
            else:
                idx += 1
            if s[p] == "0":
                n = 256; p += 1
            else:
                n = int(s[p + 2:p + 10], 2) + 1; p += 10
            if idx >= self.rx_next:
                self.rx_frags.setdefault(idx, s[p:p + n])
            p += n
        out = []
        while True:
            i, msg = self.rx_next, ""
            while i in self.rx_frags:
                msg += self.rx_frags[i]
                i += 1
                if len(self.rx_frags[i - 1]) < 256:
                    break
            else:
                break
            for j in range(self.rx_next, i):
                del self.rx_frags[j]
            self.rx_next = i
            out.append((int(msg[:6], 2), int(msg[6:22], 2), msg[22:]))
        return out

    def send(self, payload):
        """Queue a message (envelope Bits) for the first stream."""
        n = (len(payload.s) + 255) // 256
        self.queue.append((payload, self.next_index))
        self.next_index += n


# --- session join (the membership probe is a diagnostic candidate) -------
MASK = 0xFFFFFFFF


def _rot(x, n):
    return ((x << n) | (x >> (32 - n))) & MASK


def membership_checksum(state: bytes) -> int:
    """978 x 12-byte loop over the reconstructed membership state."""
    assert len(state) == 11736
    a = b = c = 0xDEADECC6   # lis -8531 ; ori 60614
    for x, y, z in struct.iter_unpack(">III", state):
        a = (a + x) & MASK; b = (b + y) & MASK; c = (c + z) & MASK
        a = ((a - c) & MASK) ^ _rot(c, 4); c = (c + b) & MASK
        b = ((b - a) & MASK) ^ _rot(a, 6); a = (a + c) & MASK
        c = ((c - b) & MASK) ^ _rot(b, 8); b = (b + a) & MASK
        a = ((a - c) & MASK) ^ _rot(c, 16); c = (c + b) & MASK
        b = ((b - a) & MASK) ^ _rot(a, 19); a = (a + c) & MASK
        c = ((c - b) & MASK) ^ _rot(b, 4); b = (b + a) & MASK
    return c


def join_request(app: bytes):
    """OOB type 9: {sid, nonce, peer address 36 B, peer id 8 B} (bit offsets after the 24-bit type/size header)."""
    body = app[2:]
    if len(body) < 80 or body[0] != 0xC9:
        return None
    s = "".join(f"{x:08b}" for x in body[3:])
    f = lambda off, bits: int(s[off:off + bits], 2).to_bytes(bits // 8, "big")
    return {"protocol": int(s[0:16], 2), "version": int(s[16:48], 2), "kind": int(s[80:83], 2), "sid": f(83, 64),
            "nonce": f(147, 64), "address": f(216, 288), "peer_id": f(504, 64), "player_id": f(595, 64)}


def membership_probe(sid, client_addr, server_addr, client_id, nonce, states=(10, 5), sequence=1, host_id=bytes(8)):
    """Full membership update (type 29): host = peer 0, the joiner = peer 1 with its join nonce, no players [U]."""
    m = bytearray(25344)

    def w(off, value):
        struct.pack_into(">I", m, off, value & MASK)

    w(8, sequence); w(12, 0); w(16, 0); w(40, 2); w(44, 3)
    for i in range(20):
        w(396 + 360 * i, -1)
    peers = [(server_addr, host_id, bytes(8), states[0]), (client_addr, client_id, nonce, states[1])]
    for i, (addr, pid, nn, state) in enumerate(peers):
        p = 48 + 360 * i
        m[p:p + 36] = addr
        m[p + 36:p + 44] = pid
        w(p + 44, state)
        m[p + 328:p + 336] = nn
    checksum = membership_checksum(bytes(m[8:11744]))
    b = Bits().raw(sid).put(sequence, 32).put(1, 1).put(2, 5).put(0, 5)
    for i, (addr, pid, nn, state) in enumerate(peers):
        b.put(i, 5).put(1, 1).put(state, 4).put(1, 1)
        b.raw(addr).raw(pid).raw(bytes(8)).put(0, 32).put(0, 64)
        b.put(1, 1).raw(nn).put(0, 1).put(0, 1).put(0, 1)
    b.put(0, 1)
    b.put(1, 1).put(0, 5)
    b.put(1, 1).put(0, 5)
    b.put(0, 1).put(0, 1)
    b.put(checksum, 32)
    return envelope(29, 13200, b), checksum


def parameters_probe(sid, first_mask=1, reset=1):
    """Type 37 parameters-update without parameter bodies: reset flag, sid,
    two 2-bit group masks (groups of 16 over 23 parameters), then one presence bit per parameter of each selected
    group. first_mask = the first expanded mask (bit i = parameter i); the second mask (the one with data) is empty.
    A non-empty mask makes the client set its parameters-ready bit (session+33876 bit 0), the missing condition of
    session state 2 -> 4."""
    groups = sum(1 << g for g in range(2) if (first_mask >> (16 * g)) & 0xFFFF)
    b = Bits().put(reset, 1).raw(sid).put(groups, 2).put(0, 2)
    for i in range(23):
        if groups >> (i // 16) & 1:
            b.put(first_mask >> i & 1, 1)
    return envelope(37, 44064, b)


# --- session host after the joiner reached session state 4 ---------------------
PROP_FIELDS = (("u8", 8), ("u6", 6), ("u32a", 32), ("pair", 128), ("desc", 68), ("u32b", 32))


def player_props(s, pos):
    """Player properties codec at bit pos: nine presence-gated fields -> ({name: bit string}, next pos).
    name = UTF-16 units through NUL (max 17), identity = 36 raw bytes, game = the "full" bit (1 would add 3808 bits,
    not handled), then PROP_FIELDS."""
    f = {}
    if s[pos] == "1":
        n = 0
        while int(s[pos + 1 + 16 * n:pos + 17 + 16 * n], 2) and n < 16:
            n += 1
        f["name"] = s[pos + 1:pos + 17 + 16 * n]
        pos += 16 * (n + 1)
    pos += 1
    if s[pos] == "1":
        f["identity"] = s[pos + 1:pos + 289]
        pos += 288
    pos += 1
    if s[pos] == "1":
        f["game"] = s[pos + 1]
        assert f["game"] == "0", "full game block not handled"
        pos += 1
    pos += 1
    for name, width in PROP_FIELDS:
        if s[pos] == "1":
            f[name] = s[pos + 1:pos + 1 + width]
            pos += width
        pos += 1
    return f, pos


def player_state(f):
    """(full property wire with every gate set, reconstructed 136-byte state) of a complete field set."""
    from tiger import tiger
    u = lambda k, a=0, n=None: int(f[k][a:a + n] if n else f[k][a:], 2)
    wire = "1" + f["name"] + "1" + f["identity"] + "1" + f["game"] + "".join("1" + f[k] for k, _ in PROP_FIELDS)
    pm = bytearray(136)
    for i in range(len(f["name"]) // 16):
        struct.pack_into(">H", pm, 2 * i, u("name", 16 * i, 16))
    identity = u("identity").to_bytes(36, "big")
    pm[40:76] = identity
    # platform handle: Tiger/192 of the lowercased name, first 8 bytes reversed
    struct.pack_into(">Q", pm, 80, int.from_bytes(tiger(identity.split(b"\0")[0].lower())[:8], "little"))
    struct.pack_into(">H", pm, 88, u("u8"))
    pm[90] = (u("u6") - 1) & 255
    struct.pack_into(">I", pm, 96, u("u32a"))
    struct.pack_into(">QQ", pm, 104, u("pair", 0, 64), u("pair", 64, 64))
    struct.pack_into(">IhhB", pm, 120, u("desc", 0, 32), u("desc", 32, 16) - 32768, u("desc", 48, 16) - 32768,
                     u("desc", 64, 4))
    struct.pack_into(">I", pm, 132, u("u32b"))
    return wire, bytes(pm)


def _extra(bits):
    e = bytearray(16)
    struct.pack_into(">II", e, 0, int(bits[0:20], 2), int(bits[20:40], 2))
    e[8:11] = bytes([int(bits[40:45], 2), int(bits[45:47], 2), int(bits[47], 2)])
    assert not e[8] & 16
    return bytes(e)


def captured_player(s):
    """The joiner's type 33 player-add body (bit string: sid, slot, player id, revision u32, kind u3, properties,
    extra 48) -> the player record the host keeps."""
    assert s[64] == "0", "slot"
    f, pos = player_props(s, 164)
    assert len(s) == pos + 48 and len(f) == 9, (len(s), pos, sorted(f))
    wire, props = player_state(f)
    return dict(pid=int(s[65:129], 2).to_bytes(8, "big"), slot=0, revision=int(s[129:161], 2), kind=int(s[161:164], 2),
                fields=f, wire=wire, props=props, extra_wire=s[pos:], extra=_extra(s[pos:]))


def player_update(player, s):
    """Apply the joiner's type 36 player-properties body (sid, slot, revision u32, kind u3, gated properties, gate +
    raw32 [U meaning, not stored], extra 48) to the record. Returns the names of the changed fields."""
    f, pos = player_props(s, 100)
    pos += 33 if s[pos] == "1" else 1
    assert len(s) == pos + 48, (len(s), pos)
    changed = [k for k in f if player["fields"].get(k) != f[k]]
    player["fields"].update(f)
    player["revision"], player["kind"] = int(s[65:97], 2), int(s[97:100], 2)
    player["wire"], player["props"] = player_state(player["fields"])
    player["extra_wire"], player["extra"] = s[pos:], _extra(s[pos:])
    return changed


def membership(sid, client_addr, server_addr, client_id, nonce, sequence, states=(10, 9), player=None, host=0):
    """Full type 29 update: host = peer 0, joiner = peer 1 (its nonce is cleared at state 10), optionally the joiner's
    player (captured_player) as player 0 owned by peer 1. Returns (envelope, checksum)."""
    m = bytearray(25344)

    def w(off, value):
        struct.pack_into(">I", m, off, value & MASK)

    w(8, sequence); w(12, host); w(16, host); w(40, 2); w(44, 3)
    for i in range(20):
        w(396 + 360 * i, -1)
    peers = [(server_addr, bytes(8), bytes(8), states[0]),
             (client_addr, client_id, bytes(8) if states[1] == 10 else nonce, states[1])]
    for i, (addr, pid, nn, state) in enumerate(peers):
        p = 48 + 360 * i
        m[p:p + 36] = addr
        m[p + 36:p + 44] = pid
        w(p + 44, state)
        m[p + 328:p + 336] = nn
    if player:
        w(7248, 1); w(7252, 1)
        p = 7256
        w(p, player["revision"])
        m[p + 4:p + 12] = player["pid"]
        w(p + 12, 1); w(p + 16, player["slot"]); w(p + 20, 0); w(p + 28, player["kind"])
        m[p + 32:p + 168] = player["props"]
        m[p + 168], m[p + 169] = 0, 255
        m[p + 208:p + 224] = player["extra"]
        w(48 + 360 + 344, 1); w(48 + 360 + 348 + 4 * player["slot"], 0)
    checksum = membership_checksum(bytes(m[8:11744]))
    b = Bits().raw(sid).put(sequence, 32).put(1, 1).put(2, 5).put(int(bool(player)), 5)
    for i, (addr, pid, nn, state) in enumerate(peers):
        b.put(i, 5).put(1, 1).put(state, 4).put(1, 1).raw(addr).raw(pid).raw(bytes(8)).put(0, 32).put(0, 64)
        b.put(1, 1).raw(nn).put(0, 1).put(0, 1).put(0, 1)
    if player:
        b.put(0, 5).put(1, 1).put(1, 1).raw(player["pid"]).put(1, 5).put(player["slot"], 1).put(0, 20).put(0, 1)
        b.put(1, 1).put(player["revision"], 32).put(player["kind"] + 1, 4)
        b.s += player["wire"]
        b.put(0, 1).put(0, 1).put(0, 1)
        b.s += player["extra_wire"]
    b.put(0, 1).put(1, 1).put(host, 5).put(1, 1).put(host, 5).put(0, 1).put(0, 1).put(checksum, 32)
    return envelope(29, 13200, b), checksum


def parameters(sid, values, first_mask=None, reset=0):
    """Type 37 with descriptor bodies: values = {parameter index: body Bits}."""
    second = sum(1 << i for i in values)
    first = second if first_mask is None else first_mask
    groups = lambda mask: sum(1 << g for g in range(2) if mask >> (16 * g) & 0xFFFF)
    g0, g1 = groups(first), groups(second)
    b = Bits().put(reset, 1).raw(sid).put(g0, 2).put(g1, 2)
    for i in range(23):
        if g0 >> (i // 16) & 1:
            b.put(first >> i & 1, 1)
    for i in range(23):
        if g1 >> (i // 16) & 1:
            b.put(second >> i & 1, 1)
        if i in values:
            b.s += values[i].s
    return envelope(37, 44064, b)


def goal(a, b, c):                      # parameter 0 world-controller-goal-data
    return Bits().put(a + 1, 6).put(b + 1, 9).put(c, 8)


def join_controls(a=20, b=1, c=0, d=0, e=0, f=0, g=0):   # parameter 1 active-join-controls
    return Bits().put(a, 5).put(b, 5).put(c, 5).put(d, 1).put(e, 1).put(f, 5).put(g, 2)


def activity_host(host_id, peer_mask=3, key=bytes(8)):
    """Parameter 3 activity-host body: raw64 (must equal the u64 of the parameter object at
    session+28512, 0 while that one is unavailable), u64 activity-host id (must be valid), raw32 read as a big-endian
    peer mask (the joiner's own peer bit must be set), u32, u16 - the conditions of the game-level slot tick."""
    return Bits().raw(key).put(host_id, 64).raw(peer_mask.to_bytes(4, "big")).put(0, 32).put(0, 16)


def activity(key, number=0xb50c28c1e76c6096, word=0xb5f479b7, index=90):
    """Parameter 8 activity body: RSAT 0x8080198e {i3, i16, i8, 40 x i8, hash} then raw64 (the id
    the activity-host parameter must repeat), u64, u32. Values as read from the client's own private session
    (run pubhost8): {0, 90, -1, zeros, 0x811c9dc5}; the u64 / u32 are that session's, meaning unknown [U]."""
    import rsat
    v = {0: 0, 1: index, 2: -1, 3: {0: [0] * 40}, 4: 0x811C9DC5}
    b = Bits()
    b.s += "".join(f"{x:08b}" for x in rsat.encode(0x8080198E, v))[:rsat.encoded_bits(0x8080198E, v)]
    return b.raw(key).put(number, 64).put(word, 32)


def time_reply(app: bytes, clock):
    """OOB type 28 stage 0 (decrypted payload) -> stage 1 payload {sid, 1, origin, host receive, host send}, or None.
    clock(origin) -> host milliseconds."""
    body = app[2:]
    if len(body) < 20 or body[0] != 0xC0 | 28:
        return None
    s = "".join(f"{x:08b}" for x in body[3:])
    if s[64] != "0":
        return None
    origin = int(s[65:129], 2)
    now = clock(origin)
    b = Bits().put(0xC0 | 28, 8).put(48, 16)
    b.s += s[:64]
    b.put(1, 1).put(origin, 64).put(now, 64).put(now, 64).put(0, 1)
    out = b.bytes()
    return struct.pack("<H", len(out)) + out


class Host:
    """What the session host does for one joiner. mode: 'noplayer' = state 9 once the joiner sent peer-establish,
    'player' = state 9 together with its player on the first player-add; then state 10 on join-complete."""

    def __init__(self, chan, jr, server_addr, mode, log, values=False, ah=None, flags=()):
        self.chan, self.jr, self.server_addr, self.mode, self.log, self.values = chan, jr, server_addr, mode, log, values
        self.ah, self.mode_flags = ah, flags
        self.seq, self.state, self.player, self.host_index = 0, 7, None, 0
        self.publish(7)
        chan.send(parameters_probe(jr["sid"], 1))

    def publish(self, state):
        self.seq += 1
        self.state = state
        j = self.jr
        body, ck = membership(j["sid"], j["address"], self.server_addr, j["peer_id"], j["nonce"], self.seq,
                              (10, state), self.player, host=self.host_index)
        self.chan.send(body)
        self.log(f"   [host] membership seq={self.seq} joiner state={state} player={bool(self.player)} "
                 f"checksum=0x{ck:08x} bits={len(body.s)}")

    def on_message(self, t, size, bits):
        key = (t, len(bits))
        self.seen = getattr(self, "seen", {})
        self.seen[key] = self.seen.get(key, 0) + 1
        if self.seen[key] <= 2 or t == 11:
            self.log(f"   [host] rx type {t} ({NAMES.get(t, '?')}) size={size} bits={len(bits)} #{self.seen[key]}")
        if t == 25 and self.mode == "noplayer" and self.state == 7:
            self.publish(9)
        elif t == 33 and self.mode == "player" and self.player is None:
            try:
                self.player = captured_player(bits)
            except AssertionError as e:
                self.log(f"   [host] player-add variant not handled: {e!r}")
                return
            self.publish(9)
            if self.values:
                self.chan.send(parameters(self.jr["sid"], {0: goal(36, 0, 2), 1: join_controls()}))
                self.log("   [host] parameters 0 (goal 36,0,2) and 1 (join controls 20,1,0...) queued")
        elif t == 30 and "handoff1" in self.mode_flags and self.state == 10 and 500 < len(bits) < 1000 \
                and not self.host_index:
            # experiment: the joiner's 602-bit peer-properties (sent once the public region is current, ~14 s after
            # the join, before the spawn) -> hand the session to it
            self.host_index = 1
            self.publish(10)
        elif t == 36 and self.player is not None:
            try:
                changed = player_update(self.player, bits)
            except AssertionError as e:
                self.log(f"   [host] player-properties variant not handled: {e!r}")
                return
            self.log(f"   [host] player-properties revision={self.player['revision']} changed={changed}")
            if "reflect" in self.mode_flags and self.state == 10:
                if "handoff" in self.mode_flags and "u8" in changed:
                    self.host_index = 1      # experiment: declare the joiner leader and host once it is in the world
                self.publish(10)
        elif t == 11 and self.state != 10:
            self.log(f"   [host] JOIN-COMPLETE body={int(bits, 2):x}")
            self.publish(10)
            if self.ah:
                key = b"PUBACT01"
                self.chan.send(parameters(self.jr["sid"], {3: activity_host(self.ah, key=key), 8: activity(key)},
                                          first_mask=0))
                self.log(f"   [host] parameters 3 activity-host id=0x{self.ah:x} mask=3 and 8 activity queued")
            if "handoff0" in self.mode_flags:
                self.host_index = 1          # experiment: hand the session to the joiner right after its join
                self.publish(10)
