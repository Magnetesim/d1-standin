"""MurmurHash3 128-bit, both reference variants, with selectable word byte order (the PS3 is big-endian and the
reference code reads blocks and writes the result as native words)."""
import struct

M32, M64 = 0xFFFFFFFF, (1 << 64) - 1


def _rotl32(x, r):
    return ((x << r) | (x >> (32 - r))) & M32


def _rotl64(x, r):
    return ((x << r) | (x >> (64 - r))) & M64


def _fmix32(h):
    h ^= h >> 16
    h = (h * 0x85EBCA6B) & M32
    h ^= h >> 13
    h = (h * 0xC2B2AE35) & M32
    return h ^ (h >> 16)


def _fmix64(k):
    k ^= k >> 33
    k = (k * 0xFF51AFD7ED558CCD) & M64
    k ^= k >> 33
    k = (k * 0xC4CEB9FE1A85EC53) & M64
    return k ^ (k >> 33)


def x64_128(data: bytes, seed: int = 0, endian: str = "<", out_endian: str | None = None) -> bytes:
    h1 = h2 = seed
    c1, c2 = 0x87C37B91114253D5, 0x4CF5AD432745937F
    n = len(data) // 16
    for i in range(n):
        k1, k2 = struct.unpack_from(endian + "2Q", data, i * 16)
        k1 = (_rotl64((k1 * c1) & M64, 31) * c2) & M64
        h1 = ((_rotl64(h1 ^ k1, 27) + h2) * 5 + 0x52DCE729) & M64
        k2 = (_rotl64((k2 * c2) & M64, 33) * c1) & M64
        h2 = ((_rotl64(h2 ^ k2, 31) + h1) * 5 + 0x38495AB5) & M64
    tail = data[n * 16:]
    k1 = int.from_bytes(tail[:8], "little")
    k2 = int.from_bytes(tail[8:], "little")
    if len(tail) > 8:
        h2 ^= (_rotl64((k2 * c2) & M64, 33) * c1) & M64
    if tail:
        h1 ^= (_rotl64((k1 * c1) & M64, 31) * c2) & M64
    h1 ^= len(data)
    h2 ^= len(data)
    h1 = (h1 + h2) & M64
    h2 = (h2 + h1) & M64
    h1, h2 = _fmix64(h1), _fmix64(h2)
    h1 = (h1 + h2) & M64
    h2 = (h2 + h1) & M64
    return struct.pack((out_endian or endian) + "2Q", h1, h2)


def x86_128(data: bytes, seed: int = 0, endian: str = "<", out_endian: str | None = None) -> bytes:
    h = [seed] * 4
    c = (0x239B961B, 0xAB0E9789, 0x38B34AE5, 0xA1E38B93)
    rot_k, rot_h = (15, 16, 17, 18), (19, 17, 15, 13)
    add = (0x561CCD1B, 0x0BCAA747, 0x96CD1C35, 0x32AC3B17)
    n = len(data) // 16
    for i in range(n):
        k = struct.unpack_from(endian + "4I", data, i * 16)
        for j in range(4):
            kj = (_rotl32((k[j] * c[j]) & M32, rot_k[j]) * c[(j + 1) % 4]) & M32
            h[j] ^= kj
            h[j] = ((_rotl32(h[j], rot_h[j]) + h[(j + 1) % 4]) * 5 + add[j]) & M32
    tail = data[n * 16:]
    for j in (3, 2, 1, 0):
        part = tail[j * 4:j * 4 + 4]
        if part:
            kj = int.from_bytes(part, "little")
            h[j] ^= (_rotl32((kj * c[j]) & M32, rot_k[j]) * c[(j + 1) % 4]) & M32
    for j in range(4):
        h[j] ^= len(data)
    h[0] = (h[0] + h[1] + h[2] + h[3]) & M32
    for j in (1, 2, 3):
        h[j] = (h[j] + h[0]) & M32
    h = [_fmix32(v) for v in h]
    h[0] = (h[0] + h[1] + h[2] + h[3]) & M32
    for j in (1, 2, 3):
        h[j] = (h[j] + h[0]) & M32
    return struct.pack((out_endian or endian) + "4I", *h)
