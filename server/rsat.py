"""Descriptor-driven RSAT codec for PS3 01.24 investment objects.

The schema descriptors are read out of the decrypted EBOOT (private/EBOOT.elf, git-ignored)
so field order, widths and fixed-array counts come from the client itself rather than from hand
layouts. Grammar (verified against the pinned character oracle vector and the sibling's family-0/2
fixtures):

  record: anchor bytes 80 80 00 50 80 80 01 0A; RB = anchor - 0x34; RB+0x04 checksum,
          RB+0x3C field count, RB+0x40 self tag, RB+0x50 fixed-array count (0 = not an array).
  field k at F = RB + 0x64 + k*0x28: u32 kind (byte0 type, byte1 presence width),
          F+4 child tag (0xFFFFFFFF = leaf), F+0xC leaf width in bits (0 for f32 -> 32). Type 2 (bool) has width
          0 and carries no bits: encoding it as 1 bit shifts join_result past the embedded join_request bool and the
          client rejects it at once (GRAPEFRUIT, runs launch_ah10-14; 0 bits: accepted, launch_ah9).
  per field: presence bit when the presence width is 1 (0 = absent, nothing follows);
          leaf: `width` bits MSB-first, signed types biased (3: +0x80, 4: +0x8000, 5: +0x80000000);
          composite: the child's fields, or for a fixed array `count` repetitions of its one field;
          a DYNAMIC array (field word F+8 high byte == 1) carries only as many elements as the
          preceding sibling leaf says (e.g. the 205/503 unlock flags {u6 count; 50 x flag}).

Values: dict {field index: value}; None/missing = absent; lists for arrays; dicts for children.
"""
import os
import struct

ELF = os.environ.get("D1_EBOOT_ELF", os.path.join(os.path.dirname(__file__), "..", "private", "EBOOT.elf"))
ANCHOR = bytes.fromhex("808000508080010A")
BIAS = {3: 0x80, 4: 0x8000, 5: 0x80000000}
FIELD_BIAS = False   # signed leaves: use the descriptor's own bias (field word F+8: 0x80000000 at 32 bits, 0x80 at 8,
#                      1 on narrow fields, so wire 0 = -1) instead of BIAS. Off for the investment objects, whose
#                      values were calibrated as wire values; on for activity_host udt 11 (run launch_ah34)
TYPE_BITS = {}       # wire width of leaf types whose descriptor width is 0 (e.g. 35, an 8-byte id) [U] experiment knob
BOOL_BITS = 0   # bits written for a type-2 (bool) leaf; [U] experiment knob (activity_host udt 1)
LEAF = 0xFFFFFFFF

_data = None
_rec = {}


def _load():
    global _data
    if _data is None:
        with open(ELF, "rb") as fh:
            _data = fh.read()
        j = _data.find(ANCHOR)
        while j >= 0:
            rb = j - 0x34
            _rec[_u32(rb + 0x40)] = rb
            j = _data.find(ANCHOR, j + 1)
    return _data


def _u32(o):
    return struct.unpack_from(">I", _data, o)[0]


def rec(tag):
    _load()
    return _rec[tag]


def checksum(tag):
    return _u32(rec(tag) + 4)


def fields(tag):
    rb = rec(tag)
    out = []
    for k in range(_u32(rb + 0x3C)):
        f = rb + 0x64 + k * 0x28
        kind = _u32(f)
        width = _u32(f + 0xC)
        typ = (kind >> 24) & 0xFF
        out.append({"type": typ, "presence": (kind >> 16) & 0xFF, "child": _u32(f + 4),
                    "width": width or (32 if typ == 0x0B else 0), "dyn": (_u32(f + 8) >> 24) == 1,
                    "bias": _u32(f + 8)})
    return out


def array_count(tag):
    return _u32(rec(tag) + 0x50)


class _W:
    def __init__(self):
        self.bits = []

    def put(self, v, n):
        self.bits += [(v >> i) & 1 for i in reversed(range(n))]

    def bytes(self):
        b = self.bits + [0] * (-len(self.bits) % 8)
        return bytes(int("".join(map(str, b[i:i + 8])), 2) for i in range(0, len(b), 8))


def _enc_field(w, f, v, count=None):
    if f["presence"]:
        w.put(0 if v is None else 1, 1)
        if v is None:
            return
    if f["type"] == 1:
        # a dynamic array's length is its preceding sibling leaf; unset means 0, as the decoder reads it
        _enc_struct(w, f["child"], v if v is not None else {}, (count or 0) if f["dyn"] else None)
        return
    if v is None:
        v = 0
    if isinstance(v, float):
        v = struct.unpack(">I", struct.pack(">f", v))[0]
    n = f["width"] or (BOOL_BITS if f["type"] == 2 else TYPE_BITS.get(f["type"], 0))
    bias = f["bias"] if FIELD_BIAS and f["type"] in BIAS else BIAS.get(f["type"], 0)
    v = (v + bias) & ((1 << n) - 1)
    w.put(v, n)


def _enc_struct(w, tag, v, dyn_count=None):
    fs = fields(tag)
    n = array_count(tag) if dyn_count is None else dyn_count
    if n or dyn_count is not None:
        elems = list(v or [])
        for i in range(n):
            _enc_field(w, fs[0], elems[i] if i < len(elems) else None)
        return
    for k, f in enumerate(fs):
        prev = v.get(k - 1) if isinstance(v, dict) and k else None
        _enc_field(w, f, v.get(k) if isinstance(v, dict) else None, prev)


def encode(tag, values):
    w = _W()
    _enc_struct(w, tag, values)
    return w.bytes()


def encoded_bits(tag, values):
    w = _W()
    _enc_struct(w, tag, values)
    return len(w.bits)


def decode(tag, payload):
    """Inverse of encode (absent -> None). Returns (values, bits consumed)."""
    bits = [(b >> i) & 1 for b in payload for i in reversed(range(8))]
    pos = [0]

    def take(n):
        v = int("".join(map(str, bits[pos[0]:pos[0] + n])) or "0", 2)
        pos[0] += n
        return v

    def field(f, count=None):
        if f["presence"] and not take(1):
            return None
        if f["type"] == 1:
            return struct_(f["child"], count if f["dyn"] else None)
        n = f["width"] or (BOOL_BITS if f["type"] == 2 else TYPE_BITS.get(f["type"], 0))
        v = take(n)
        if FIELD_BIAS and f["type"] in BIAS:
            v -= f["bias"]
        elif f["type"] in BIAS:
            v = (v - BIAS[f["type"]]) & ((1 << n) - 1)
            if v >> (n - 1):
                v -= 1 << n
        return v

    def struct_(tag, dyn_count=None):
        fs = fields(tag)
        n = array_count(tag) if dyn_count is None else dyn_count
        if n or dyn_count is not None:
            return [field(fs[0]) for _ in range(n)]
        out = {}
        for k, f in enumerate(fs):
            out[k] = field(f, out.get(k - 1))
        return out

    return struct_(tag), pos[0]
