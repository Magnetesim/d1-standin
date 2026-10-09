"""Tiger/192 (the hash DemonWare's bdHashTiger192 wraps; libtomcrypt tiger.c). The four S-boxes are read from the game
image (private/EBOOT.elf, a fixed file offset, 1024 big-endian u64) instead of being embedded."""
import os
import struct

_M = (1 << 64) - 1
_T = None


def _tables():
    global _T
    if _T is None:
        path = os.environ.get("D1_EBOOT_ELF", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "private", "EBOOT.elf"))
        with open(path, "rb") as f:
            f.seek(0x13C6E98)
            t = struct.unpack(">1024Q", f.read(8192))
        assert t[0] == 0x02AAB17CF7E90C5E
        _T = [t[i * 256:(i + 1) * 256] for i in range(4)]
    return _T


def _compress(state, block):
    t1, t2, t3, t4 = _tables()
    x = list(struct.unpack("<8Q", block))
    a, b, c = state

    def rnd(a, b, c, xv, mul):
        c ^= xv
        a = (a - (t1[c & 255] ^ t2[(c >> 16) & 255] ^ t3[(c >> 32) & 255] ^ t4[(c >> 48) & 255])) & _M
        b = (b + (t4[(c >> 8) & 255] ^ t3[(c >> 24) & 255] ^ t2[(c >> 40) & 255] ^ t1[(c >> 56) & 255])) & _M
        return a, (b * mul) & _M, c

    def ps(a, b, c, mul):
        a, b, c = rnd(a, b, c, x[0], mul)
        b, c, a = rnd(b, c, a, x[1], mul)
        c, a, b = rnd(c, a, b, x[2], mul)
        a, b, c = rnd(a, b, c, x[3], mul)
        b, c, a = rnd(b, c, a, x[4], mul)
        c, a, b = rnd(c, a, b, x[5], mul)
        a, b, c = rnd(a, b, c, x[6], mul)
        b, c, a = rnd(b, c, a, x[7], mul)
        return a, b, c

    def ks():
        x[0] = (x[0] - (x[7] ^ 0xA5A5A5A5A5A5A5A5)) & _M
        x[1] ^= x[0]
        x[2] = (x[2] + x[1]) & _M
        x[3] = (x[3] - (x[2] ^ (((~x[1]) & _M) << 19 & _M))) & _M
        x[4] ^= x[3]
        x[5] = (x[5] + x[4]) & _M
        x[6] = (x[6] - (x[5] ^ (((~x[4]) & _M) >> 23))) & _M
        x[7] ^= x[6]
        x[0] = (x[0] + x[7]) & _M
        x[1] = (x[1] - (x[0] ^ (((~x[7]) & _M) << 19 & _M))) & _M
        x[2] ^= x[1]
        x[3] = (x[3] + x[2]) & _M
        x[4] = (x[4] - (x[3] ^ (((~x[2]) & _M) >> 23))) & _M
        x[5] ^= x[4]
        x[6] = (x[6] + x[5]) & _M
        x[7] = (x[7] - (x[6] ^ 0x0123456789ABCDEF)) & _M

    a, b, c = ps(a, b, c, 5)
    ks()
    c, a, b = ps(c, a, b, 7)
    ks()
    b, c, a = ps(b, c, a, 9)
    return (a ^ state[0], (b - state[1]) & _M, (c + state[2]) & _M)


def tiger(data: bytes) -> bytes:
    state = (0x0123456789ABCDEF, 0xFEDCBA9876543210, 0xF096A5B4C3B2E187)
    msg = data + b"\x01" + bytes((55 - len(data)) % 64) + struct.pack("<Q", len(data) * 8)
    for i in range(0, len(msg), 64):
        state = _compress(state, msg[i:i + 64])
    return struct.pack("<3Q", *state)
