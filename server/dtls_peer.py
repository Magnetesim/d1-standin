"""Responder side of DemonWare 44 bdDTLS (the peer secure channel; not TLS/DTLS), for the public activity host stand-in.

Layouts and crypto from static analysis of the client, each step to be
confirmed live: header {u8 type, u8 version 2, u16 LE verification tag (the RECEIVER's tag), u32 LE sequence};
Init(1) 18 B {I, security id}; InitAck(2) 52 B; CookieEcho(3) 199 B {InitAck, bdCommonAddr 31 B, id, public key 100 B};
CookieAck(4) 116 B {public key 100 B, id}; Data(6) {MAC8, u16 N, AES-128-CBC(N bytes padded with 01), clear suffix}.
Keys: P-224 ECDH x (28 B) mixed with the 16-byte security key of the session blob (see _derive).
Algorithms as this title configures them, confirmed against the client's own key (run
pubdtls3) and its packets: hash = Tiger/192 (key derivation and IV), cipher = AES-128-CBC, MAC = HMAC built on
MurmurHash3 x64_128 with big-endian words (bdHMacMurmur3), first 8 bytes. SHA-256, the library default, is not what this title uses."""
import hmac
import os
import struct
from hashlib import sha256

import murmur3
from tiger import tiger

VERSION = 2
T_INIT, T_INITACK, T_COOKIEECHO, T_COOKIEACK, T_ERROR, T_DATA = 1, 2, 3, 4, 5, 6


def _der_int(v: int) -> bytes:
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big")   # leading 00 when the top bit is set
    return b"\x02" + bytes([len(b)]) + b


def export_public(x: int, y: int) -> bytes:
    """libtomcrypt ecc_export of a public key: SEQUENCE {BIT STRING flag 0, INTEGER 28, INTEGER x, INTEGER y}, padded
    with zeros to 100 bytes."""
    body = b"\x03\x02\x07\x00" + b"\x02\x01\x1c" + _der_int(x) + _der_int(y)
    return (b"\x30" + bytes([len(body)]) + body).ljust(100, b"\0")


def import_public(blob: bytes) -> tuple[int, int]:
    assert blob[0] == 0x30, blob[:4].hex()
    i, end, ints = 2, 2 + blob[1], []
    while i < end:
        tag, n = blob[i], blob[i + 1]
        if tag == 0x02:
            ints.append(int.from_bytes(blob[i + 2:i + 2 + n], "big"))
        i += 2 + n
    return ints[-2], ints[-1]


class Peer:
    """One association with one client endpoint."""

    def __init__(self, security_key: bytes, log=print):
        self.psk, self.log = security_key, log
        self.cookie_secret = os.urandom(16)
        self.R = 0x1234           # our tag: the client puts it in the header of what it sends us
        self.I = None             # the client's tag: goes in the header of what we send
        self.aes_key = self.hmac_key = None
        self.tx_seq, self.rx_hi, self.rx_last = 0, 0, -1
        self.priv = None
        self.established = False

    # --- handshake -----------------------------------------------------------------------------------------------
    def _init_ack(self, init: bytes, addr) -> bytes:
        import socket
        i_tag, sid = struct.unpack_from("<H", init, 8)[0], init[10:18]
        address6 = socket.inet_aton(addr[0]) + struct.pack("<H", addr[1])
        tags = (self.R, self.R, i_tag, 0, 0)
        sig = hmac.new(self.cookie_secret, struct.pack(">I5H", 0, *tags) + address6, sha256).digest()[:16]
        return (struct.pack("<BBHI", T_INITACK, VERSION, i_tag, 0) + struct.pack("<I", 0) + sig
                + struct.pack("<5H", *tags) + address6 + sid)

    def _derive(self, ecdh_x: bytes) -> None:
        # as the PS3 image does it: the suffix string is printed OVER the first bytes of the
        # ECDH value, it is not appended (verified: equals the client's HMAC key read from memory)
        b = bytearray(68)
        b[:16] = self.psk
        b[16:44] = ecdh_x
        b[16:32] = b"cypherKeySuffix\0"
        self.aes_key = tiger(bytes(b))[:16]
        b[16:40] = bytes(24)
        b[16:33] = b"SuffixForHMACKey\0"
        self.hmac_key = tiger(bytes(b))   # 24 bytes (association +0x10, length +0x30)

    def _cookie_ack(self, echo: bytes) -> bytes:
        from cryptography.hazmat.primitives.asymmetric import ec
        nested, sid, pub = echo[8:60], echo[91:99], echo[99:199]
        self.R, self.I = struct.unpack_from("<2H", nested, 30)
        x, y = import_public(pub)
        peer_key = ec.EllipticCurvePublicNumbers(x, y, ec.SECP224R1()).public_key()
        if self.priv is None:
            self.priv = ec.generate_private_key(ec.SECP224R1())
        self.ecdh_x = self.priv.exchange(ec.ECDH(), peer_key)
        self._derive(self.ecdh_x)
        self.log(f"   [dtls] ecdh_x={self.ecdh_x.hex()} psk={self.psk.hex()} client_pub={pub.hex()}")
        n = self.priv.public_key().public_numbers()
        self.established = True
        self.log(f"   [dtls] keys derived: client tag I=0x{self.I:04x} our tag R=0x{self.R:04x} sid={sid.hex()} "
                 f"client common addr={echo[60:91].hex()}")
        return struct.pack("<BBHI", T_COOKIEACK, VERSION, self.I, 0) + export_public(n.x, n.y) + sid

    def _mac(self, msg: bytes) -> bytes:
        h = lambda d: murmur3.x64_128(d, 0, ">", ">")
        k = self.hmac_key.ljust(64, b"\0")
        return h(bytes(c ^ 0x5C for c in k) + h(bytes(c ^ 0x36 for c in k) + msg))[:8]

    # --- data ----------------------------------------------------------------------------------------------------
    def _aes(self, iv: bytes, data: bytes, encrypt: bool) -> bytes:
        from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
        c = Cipher(algorithms.AES(self.aes_key), modes.CBC(iv))
        op = c.encryptor() if encrypt else c.decryptor()
        return op.update(data) + op.finalize()

    def seal(self, app: bytes) -> bytes:
        """app = LE16(N) || N bytes to encrypt || clear suffix. The first Data carries sequence 1."""
        self.tx_seq += 1
        head = struct.pack("<BBHI", T_DATA, VERSION, self.I, self.tx_seq & 0xFFFF)
        n = struct.unpack_from("<H", app)[0]
        prefix, clear = app[2:2 + n], app[2 + n:]
        iv = tiger(struct.pack("<IH", self.tx_seq & 0xFFFFFFFF, self.I))[:16]
        ct = self._aes(iv, prefix + b"\x01" * (-n % 16), True) if n else b""
        tail = struct.pack("<H", n) + ct + clear
        return head + self._mac(head + tail) + tail

    def open(self, wire: bytes) -> bytes | None:
        vtag, seq16 = struct.unpack_from("<HI", wire, 2)
        if self._mac(wire[:8] + wire[16:]) != wire[8:16]:
            self.log(f"   [dtls] Data MAC mismatch (vtag 0x{vtag:04x} seq {seq16})")
            return None
        seq16 &= 0xFFFF
        if self.rx_last >= 0 and seq16 < (self.rx_last & 0xFFFF) and (self.rx_last & 0xFFFF) - seq16 > 0x8000:
            self.rx_hi += 0x10000
        seq = self.rx_hi | seq16
        self.rx_last = max(self.rx_last, seq)
        n = struct.unpack_from("<H", wire, 16)[0]
        p = (n + 15) & ~15
        iv = tiger(struct.pack("<IH", seq & 0xFFFFFFFF, vtag))[:16]
        prefix = self._aes(iv, wire[18:18 + p], False)[:n] if n else b""
        return struct.pack("<H", n) + prefix + wire[18 + p:]

    # --- entry ---------------------------------------------------------------------------------------------------
    def handle(self, data: bytes, addr) -> tuple[list[bytes], bytes | None]:
        """(datagrams to send back, decrypted application payload or None)."""
        t = data[0]
        if t == T_INIT and len(data) == 18:
            return [self._init_ack(data, addr)], None
        if t == T_COOKIEECHO and len(data) == 199:
            return [self._cookie_ack(data)], None
        if t == T_DATA and self.established and len(data) >= 18:
            return [], self.open(data)
        self.log(f"   [dtls] unhandled type {t} len {len(data)}")
        return [], None
