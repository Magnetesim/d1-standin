#!/usr/bin/env python3
# Vendored from oodle-lzh (python/oodle_lzh.py), licensed MIT OR Apache-2.0; the open-source LZH decoder this
# project uses when the faster oodle-lzh command-line decoder is not installed. Keep in sync with upstream.
"""A pure-Python decoder for Oodle's LZH compressed format.

This is an independent implementation written from ``spec/LZH_FORMAT.md`` and the
public test vectors only.  It is intentionally readable rather than fast, and it
doubles as an executable description of the format.

    decompress(data: bytes, size: int) -> bytes
    python3 python/oodle_lzh.py decompress SIZE [IN [OUT]]
"""

from __future__ import annotations

import sys

# ---------------------------------------------------------------------------
# Constants from the specification
# ---------------------------------------------------------------------------

BLOCK_SIZE = 0x40000          # 262144 bytes of output per block
QUANTUM_SIZE = 0x4000         # 16384 bytes of output per quantum
NUM_SYMBOLS = 713
NB = 10                       # bits used for a symbol index (713 <= 2^10)

# Recent-distance base lengths / extra bits (spec section 4.2).
RECENT_BASE = (2, 3, 4, 5, 6, 7, 8, 9, 11, 13, 15, 17, 21, 25, 29, 37,
               45, 61, 93, 157)
RECENT_EXTRA = (0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 4, 5, 6, 0)

# Explicit-distance length classes (spec section 4.2).
CLASS_BASE = (3, 4, 5, 6, 7, 8, 9, 11, 13, 15, 17, 21, 25, 29, 37, 45,
              61, 93, 157)
CLASS_EXTRA = (0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 3, 3, 4, 5, 6, 0)

# Distance slots (spec section 4.3).
DIST_BASE = (0, 16, 32, 64, 128, 256, 512, 768, 1024, 1536, 2048, 3072,
             4096, 5120, 6144, 8192, 12288, 16384, 24576, 32768, 49152,
             65536, 98304)
DIST_EXTRA = (4, 4, 5, 6, 7, 8, 8, 8, 9, 9, 10, 10, 10, 10, 11, 12, 12,
              13, 13, 14, 14, 15, 15)

MAX_DISTANCE = 131072

KRAFT_TOTAL = 1 << 16


class LZHError(ValueError):
    """Raised when compressed input is malformed or unsupported."""


# ---------------------------------------------------------------------------
# Bit reader (MSB-first, as described in the specification)
# ---------------------------------------------------------------------------

class _Bits:
    """Reads bits from data[start:end], bit 0 being 0x80 of the first byte."""

    __slots__ = ("data", "bitpos", "endbit")

    def __init__(self, data: bytes, start: int = 0, end: int | None = None):
        self.data = data
        self.bitpos = start * 8
        self.endbit = (len(data) if end is None else end) * 8

    def remaining(self) -> int:
        return self.endbit - self.bitpos

    def read(self, n: int) -> int:
        if n == 0:
            return 0
        if n < 0 or self.bitpos + n > self.endbit:
            raise LZHError("bit stream exhausted")
        data = self.data
        pos = self.bitpos
        value = 0
        while n:
            byte = data[pos >> 3]
            avail = 8 - (pos & 7)
            take = avail if avail < n else n
            value = (value << take) | ((byte >> (avail - take)) &
                                       ((1 << take) - 1))
            pos += take
            n -= take
        self.bitpos = pos
        return value

    def peek(self, n: int) -> int:
        if self.bitpos + n > self.endbit:
            raise LZHError("bit stream exhausted")
        data = self.data
        pos = self.bitpos
        value = 0
        while n:
            byte = data[pos >> 3]
            avail = 8 - (pos & 7)
            take = avail if avail < n else n
            value = (value << take) | ((byte >> (avail - take)) &
                                       ((1 << take) - 1))
            pos += take
            n -= take
        return value

    def skip(self, n: int) -> None:
        if self.bitpos + n > self.endbit:
            raise LZHError("bit stream exhausted")
        self.bitpos += n

    def align(self) -> None:
        self.bitpos = (self.bitpos + 7) & ~7
        if self.bitpos > self.endbit:
            raise LZHError("bit stream exhausted")


# ---------------------------------------------------------------------------
# Huffman table construction and decoding (spec section 3)
# ---------------------------------------------------------------------------

class _Huffman:
    __slots__ = ("one_symbol", "lookup", "by_code")

    def __init__(self, lengths: list[int], one_symbol: int | None):
        self.one_symbol = one_symbol
        self.lookup = ()
        self.by_code = {}
        if one_symbol is not None:
            return

        max_len = 0
        for ln in lengths:
            if ln > max_len:
                max_len = ln
        if max_len == 0:
            return                       # no codes at all

        # Kraft equality: the code must be complete.
        total = 0
        for ln in lengths:
            if ln:
                total += 1 << (16 - ln)
        if total != KRAFT_TOTAL:
            raise LZHError("Huffman table violates the Kraft equality")

        count = [0] * (max_len + 1)
        for ln in lengths:
            if ln:
                count[ln] += 1
        next_code = [0] * (max_len + 1)
        code = 0
        for length in range(1, max_len + 1):
            code = (code + count[length - 1]) << 1
            next_code[length] = code

        lookup = [None] * (1 << NB)
        by_code = {}
        for sym, ln in enumerate(lengths):
            if not ln:
                continue
            c = next_code[ln]
            next_code[ln] = c + 1
            by_code[(ln, c)] = sym
            if ln <= NB:
                start = c << (NB - ln)
                entry = (sym, ln)
                for suffix in range(1 << (NB - ln)):
                    lookup[start + suffix] = entry
        self.lookup = lookup
        self.by_code = by_code

    def decode(self, bits: _Bits) -> int:
        if self.one_symbol is not None:
            return self.one_symbol
        if not self.by_code:
            raise LZHError("Huffman table has no codes")
        if bits.remaining() >= NB:
            entry = self.lookup[bits.peek(NB)]
            if entry is not None:
                sym, ln = entry
                bits.skip(ln)
                return sym
        # Long codes (and the tail of a payload shorter than NB bits).
        code = 0
        for ln in range(1, 17):
            code = (code << 1) | bits.read(1)
            sym = self.by_code.get((ln, code))
            if sym is not None:
                return sym
        raise LZHError("invalid Huffman code")


def _gamma(bits: _Bits) -> int:
    """spec 3.2/3.3: unary zero count (z <= 9), then z+1 payload bits; >= 1."""
    z = 0
    while bits.read(1) == 0:
        z += 1
        if z > 9:                     # gamma codes a run length <= 713
            raise LZHError("gamma code out of range")
    data = bits.read(z + 1)
    return (1 << (z + 1)) + data - 1


def _rice(bits: _Bits, k: int) -> int:
    # spec 1.2 3.2/3.3: rice codes a code-length delta, not a run length, so
    # z <= 30 for k=0 and z <= (30 >> k) otherwise; u itself is <= 30.
    z = 0
    max_z = 30 >> k
    while bits.read(1) == 0:
        z += 1
        if z > max_z:
            raise LZHError("rice code out of range")
    rem = bits.read(k)
    u = (z << k) | rem
    if u > 30:
        raise LZHError("rice code out of range")
    return u


def _zigzag(u: int) -> int:
    return (u >> 1) ^ -(u & 1)


def _parse_huffman(bits: _Bits) -> tuple[_Huffman, int]:
    """Parse a table description and return ``(table, first_token_byte)``."""
    lengths = [0] * NUM_SYMBOLS
    mode = bits.read(1)

    if mode == 0:                     # simple encoding (3.1)
        got = bits.read(NB)
        one_symbol = None
        if got == 0:
            pass                       # no codes; token decoding will fail
        elif got == 1:
            sym = bits.read(NB)
            if sym >= NUM_SYMBOLS:
                raise LZHError("symbol index out of range")
            one_symbol = sym           # code length 0: consumes no bits
        else:
            if got > NUM_SYMBOLS:
                raise LZHError("too many symbols")
            k = bits.read(3)
            if k > 5:
                raise LZHError("simple-table length bits out of range")
            prev = -1
            for _ in range(got):
                sym = bits.read(NB)
                ln = bits.read(k) + 1
                if sym >= NUM_SYMBOLS:
                    raise LZHError("symbol index out of range")
                if sym <= prev:
                    raise LZHError("symbols are not strictly increasing")
                if ln < 1 or ln > 16:
                    raise LZHError("code length out of range")
                lengths[sym] = ln
                prev = sym
        bits.align()
        return _Huffman(lengths, one_symbol), bits.bitpos // 8

    # complex encoding (3.2)
    k = bits.read(2)
    first = bits.read(1)
    pred = NB * 4
    pos = 0
    zero_run = first == 0
    while pos < NUM_SYMBOLS:
        if zero_run:
            n = _gamma(bits)
            if n > NUM_SYMBOLS - pos:
                raise LZHError("zero run writes past symbol 712")
            pos += n
            if pos == NUM_SYMBOLS:
                break
            zero_run = False
        else:
            n = _gamma(bits)
            if n > NUM_SYMBOLS - pos:
                raise LZHError("value run writes past symbol 712")
            for _ in range(n):
                u = _rice(bits, k)
                d = _zigzag(u)
                value = ((pred + 2) >> 2) + d
                if value < 1 or value > 16:
                    raise LZHError("code length out of range")
                lengths[pos] = value
                pos += 1
                pred = ((pred * 3 + 2) >> 2) + value
            if pos == NUM_SYMBOLS:
                break
            zero_run = True

    bits.align()
    return _Huffman(lengths, None), bits.bitpos // 8


# ---------------------------------------------------------------------------
# Match lengths and copies
# ---------------------------------------------------------------------------

def _decode_length(bits: _Bits, base: int, extra: int) -> int:
    if base != 157:
        return base + bits.read(extra)
    # The tiered escape of section 4.4.
    if bits.read(1) == 0:
        return 157 + bits.read(6)
    if bits.read(1) == 0:
        return 221 + bits.read(7)
    if bits.read(1) == 0:
        return 349 + bits.read(8)
    if bits.read(1) == 0:
        return 605 + bits.read(10)
    return 1629 + bits.read(14)


def _copy(out: bytearray, distance: int, length: int) -> None:
    """Append an overlapping LZ copy from ``distance`` bytes back."""
    start = len(out)
    if distance >= length:
        out.extend(out[start - distance:start - distance + length])
        return
    if distance == 1:
        out.extend(bytes((out[-1],)) * length)
        return
    pattern = bytes(out[start - distance:start])
    reps = (length + distance - 1) // distance
    out.extend((pattern * reps)[:length])


# ---------------------------------------------------------------------------
# Block and quantum parsing
# ---------------------------------------------------------------------------

class _BlockHeader:
    __slots__ = ("uncompressed", "restart", "checksums", "payload")

    def __init__(self, uncompressed, restart, checksums, payload):
        self.uncompressed = uncompressed
        self.restart = restart
        self.checksums = checksums
        self.payload = payload


def _parse_block_header(data: bytes, pos: int) -> _BlockHeader:
    if pos >= len(data):
        raise LZHError("truncated block header")
    b0 = data[pos]

    if (b0 & 0x0F) == 0x0C:           # modern two-byte header (1.1)
        if pos + 2 > len(data):
            raise LZHError("truncated block header")
        b1 = data[pos + 1]
        if (b0 >> 4) & 0x03:
            raise LZHError("invalid modern block header class")
        uncompressed = bool(b0 & 0x40)
        restart = bool(b0 & 0x80)
        checksums = bool(b1 & 0x80)
        decode_type = b1 & 0x3F
        if decode_type in (8, 9):
            raise LZHError("LZH subcode %d is unsupported" %
                           (decode_type - 7))
        if decode_type != 7:
            raise LZHError("not LZH (decode type %d)" % decode_type)
        return _BlockHeader(uncompressed, restart, checksums, pos + 2)

    # Legacy one-byte header (1.2).
    cls = b0 & 3
    if cls != 3:
        raise LZHError("invalid legacy block header class")
    z = b0 >> 2
    if z < 16:                        # uncompressed legacy block
        return _BlockHeader(True, False, False, pos + 1)
    z -= 16
    uncompressed = False
    restart = bool(z & 1)
    checksums = bool((z >> 1) & 1)
    decode_type = z >> 2
    if decode_type >= 7:
        subcode = decode_type - 7
        decode_type = 7
        if subcode != 0:
            raise LZHError("LZH subcode %d is unsupported" % subcode)
    if decode_type != 7:
        raise LZHError("not LZH (decode type %d)" % decode_type)
    return _BlockHeader(uncompressed, restart, checksums, pos + 1)


def _read_whole_match_distance(data: bytes, pos: int) -> tuple[int, int]:
    """spec 2.3: LZNA-style big-endian whole-match distance."""
    if pos + 2 > len(data):
        raise LZHError("truncated whole-match distance")
    w = (data[pos] << 8) | data[pos + 1]
    pos += 2
    if w >= 0x8000:
        return w - 0x8000 + 1, pos
    x = 0
    shift = 0
    while True:
        if pos >= len(data):
            raise LZHError("truncated whole-match distance")
        b = data[pos]
        pos += 1
        if b & 0x80:
            break
        x += (b + 0x80) << shift
        shift += 7
        if shift > 42:
            raise LZHError("whole-match distance out of range")
    x += (b - 128) << shift
    return 0x8000 + w + (x << 15) + 1, pos


def _decode_tokens(data: bytes, start: int, end: int, out: bytearray,
                   qsize: int, huff: _Huffman) -> None:
    """Decode one data quantum's token stream from payload[start:end]."""
    if start > end:
        raise LZHError("Huffman table runs past the quantum payload")
    bits = _Bits(data, start, end)
    quantum_start = len(out)
    recent = [20, 24, 28, 32]

    if huff.one_symbol is not None and huff.one_symbol < 256:
        # A one-symbol literal table consumes no bits at all.
        out.extend(bytes((huff.one_symbol,)) * qsize)
        return

    while len(out) - quantum_start < qsize:
        sym = huff.decode(bits)
        if sym < 256:
            if len(out) - quantum_start + 1 > qsize:
                raise LZHError("literal overruns the quantum")
            out.append(sym)
            continue

        if sym < 276:                 # recent-distance code
            t = sym - 256
            idx = bits.read(2)
            dist = recent[idx]
            for i in range(idx, 0, -1):
                recent[i] = recent[i - 1]
            recent[0] = dist
            length = _decode_length(bits, RECENT_BASE[t], RECENT_EXTRA[t])
        else:                         # explicit-distance code
            t = sym - 276
            cls, slot = divmod(t, 23)
            dist = DIST_BASE[slot] + 1 + bits.read(DIST_EXTRA[slot])
            if DIST_BASE[slot] != 0:
                recent[3] = recent[2]
                recent[2] = recent[1]
                recent[1] = dist
            length = _decode_length(bits, CLASS_BASE[cls],
                                    CLASS_EXTRA[cls])

        produced = len(out) - quantum_start
        # Token matches are resolved against the whole output produced so far
        # (spec 1.1 2.4/5.3); restart=1 is only an encoder promise.
        if dist < 1 or dist > MAX_DISTANCE or dist > len(out):
            raise LZHError("invalid match distance")
        if produced + length > qsize:
            raise LZHError("match overruns the quantum")
        _copy(out, dist, length)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def decompress(data: bytes, size: int) -> bytes:
    """Decode ``data`` into exactly ``size`` bytes."""
    return _decompress(data, size)[0]


def _decompress(data: bytes, size: int) -> tuple[bytes, int]:
    """Decode and return ``(output, input_bytes_consumed)``."""
    if not isinstance(data, (bytes, bytearray, memoryview)):
        raise TypeError("data must be bytes-like")
    if size < 0:
        raise ValueError("size must be non-negative")
    data = bytes(data)
    if size == 0:
        # Spec 1.1 2.5: a zero-byte request succeeds without inspecting the
        # stream, but a zero-length (or one-byte) input is still rejected.
        if len(data) < 2:
            raise LZHError("truncated input")
        return b"", 0

    out = bytearray()
    pos = 0
    total = size
    huff = None

    while len(out) < total:
        header = _parse_block_header(data, pos)
        pos = header.payload
        block_start = len(out)
        block_end = min(block_start + BLOCK_SIZE, total)

        if header.uncompressed:
            n = block_end - block_start
            if pos + n > len(data):
                raise LZHError("truncated uncompressed block")
            out.extend(data[pos:pos + n])
            pos += n
            huff = None
            continue

        huff = None                    # a block always starts without a table

        while len(out) < block_end:
            if pos + 2 > len(data):
                raise LZHError("truncated quantum header")
            v = (data[pos] << 8) | data[pos + 1]
            pos += 2
            qsize = min(QUANTUM_SIZE, block_end - len(out))
            size_field = v & 0x3FFF

            if size_field != 0x3FFF:  # normal data quantum (2.1)
                compressed_size = size_field + 1
                if compressed_size > qsize:
                    raise LZHError("data quantum larger than its output")
                if header.checksums:
                    if pos + 3 > len(data):
                        raise LZHError("truncated checksum")
                    pos += 3
                payload_end = pos + compressed_size
                if payload_end > len(data):
                    raise LZHError("truncated quantum payload")
                if (v >> 14) & 1:
                    huff, token_start = _parse_huffman(
                        _Bits(data, pos, payload_end))
                else:
                    if huff is None:
                        raise LZHError("no Huffman table before data")
                    token_start = pos
                _decode_tokens(data, token_start, payload_end, out, qsize,
                               huff)
                pos = payload_end
                continue

            # Special quanta (2.2). Spec 1.1: only stored quanta carry
            # checksum bytes; memset and whole-match do not.
            kind = v >> 14
            if kind == 1:             # memset
                if pos + 1 > len(data):
                    raise LZHError("truncated memset quantum")
                out.extend(bytes((data[pos],)) * qsize)
                pos += 1
            elif kind == 2:           # stored: checksum then body
                if header.checksums:
                    if pos + 3 > len(data):
                        raise LZHError("truncated checksum")
                    pos += 3
                if pos + qsize > len(data):
                    raise LZHError("truncated stored quantum")
                out.extend(data[pos:pos + qsize])
                pos += qsize
            elif kind == 0:           # whole match
                dist, pos = _read_whole_match_distance(data, pos)
                # Whole-match distances are not limited to 131072. They must
                # be at least 2 and no farther than this block's output
                # (restart=1) or the whole stream output.
                limit = len(out) - block_start if header.restart else len(out)
                if dist < 2 or dist > limit:
                    raise LZHError("invalid whole-match distance")
                _copy(out, dist, qsize)
            else:
                raise LZHError("invalid special quantum header")

    return bytes(out), pos


def decompress_into(data: bytes, output: bytearray | memoryview) -> int:
    """Decode into ``output``; return the number of input bytes consumed."""
    result, consumed = _decompress(data, len(output))
    if len(result) != len(output):
        raise LZHError("internal output-size mismatch")
    output[:] = result
    return consumed


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def _usage() -> int:
    sys.stderr.write("usage: oodle_lzh.py decompress SIZE [IN [OUT]]\n")
    return 2


def main(argv: list[str]) -> int:
    if len(argv) < 3 or argv[1] != "decompress":
        return _usage()
    try:
        size = int(argv[2], 0)
    except ValueError:
        sys.stderr.write("invalid SIZE: %r\n" % argv[2])
        return 2
    if size < 0:
        sys.stderr.write("invalid SIZE: %r\n" % argv[2])
        return 2
    infile = argv[3] if len(argv) > 3 else None
    outfile = argv[4] if len(argv) > 4 else None
    try:
        if infile is None or infile == "-":
            data = sys.stdin.buffer.read()
        else:
            with open(infile, "rb") as f:
                data = f.read()
        result = decompress(data, size)
        if outfile is None or outfile == "-":
            sys.stdout.buffer.write(result)
            sys.stdout.buffer.flush()
        else:
            with open(outfile, "wb") as f:
                f.write(result)
    except (LZHError, OSError) as exc:
        sys.stderr.write("oodle_lzh: %s\n" % exc)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
