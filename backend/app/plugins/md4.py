#!/usr/bin/env python3
"""md4.py - Pure-Python MD4 (RFC 1320).

Needed for NTLM hashing: OpenSSL 3 builds (Python 3.12's hashlib on most
distros) no longer expose MD4, so hashlib.new("md4") raises. This module
implements MD4 from the RFC and self-tests against the RFC 1320 test suite
plus the well-known NTLM("password") vector.
"""

import struct

_MASK = 0xFFFFFFFF


def _lrot(v, n):
    v &= _MASK
    return ((v << n) | (v >> (32 - n))) & _MASK


def _f(x, y, z):
    return (x & y) | (~x & z)


def _g(x, y, z):
    return (x & y) | (x & z) | (y & z)


def _h(x, y, z):
    return x ^ y ^ z


def md4(data: bytes) -> bytes:
    """Return the 16-byte MD4 digest of data."""
    # Padding: append 0x80, then zeros until len % 64 == 56, then bit-length.
    bit_len = (len(data) * 8) & 0xFFFFFFFFFFFFFFFF
    padded = data + b"\x80"
    while len(padded) % 64 != 56:
        padded += b"\x00"
    padded += struct.pack("<Q", bit_len)

    a, b, c, d = 0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476

    for off in range(0, len(padded), 64):
        x = struct.unpack("<16I", padded[off:off + 64])
        aa, bb, cc, dd = a, b, c, d

        # Round 1
        for i, s in zip(range(16), [3, 7, 11, 19] * 4):
            if i % 4 == 0:
                a = _lrot(a + _f(b, c, d) + x[i], s)
            elif i % 4 == 1:
                d = _lrot(d + _f(a, b, c) + x[i], s)
            elif i % 4 == 2:
                c = _lrot(c + _f(d, a, b) + x[i], s)
            else:
                b = _lrot(b + _f(c, d, a) + x[i], s)

        # Round 2
        order2 = [0, 4, 8, 12, 1, 5, 9, 13, 2, 6, 10, 14, 3, 7, 11, 15]
        for i, (k, s) in enumerate(zip(order2, [3, 5, 9, 13] * 4)):
            if i % 4 == 0:
                a = _lrot(a + _g(b, c, d) + x[k] + 0x5A827999, s)
            elif i % 4 == 1:
                d = _lrot(d + _g(a, b, c) + x[k] + 0x5A827999, s)
            elif i % 4 == 2:
                c = _lrot(c + _g(d, a, b) + x[k] + 0x5A827999, s)
            else:
                b = _lrot(b + _g(c, d, a) + x[k] + 0x5A827999, s)

        # Round 3
        order3 = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i, (k, s) in enumerate(zip(order3, [3, 9, 11, 15] * 4)):
            if i % 4 == 0:
                a = _lrot(a + _h(b, c, d) + x[k] + 0x6ED9EBA1, s)
            elif i % 4 == 1:
                d = _lrot(d + _h(a, b, c) + x[k] + 0x6ED9EBA1, s)
            elif i % 4 == 2:
                c = _lrot(c + _h(d, a, b) + x[k] + 0x6ED9EBA1, s)
            else:
                b = _lrot(b + _h(c, d, a) + x[k] + 0x6ED9EBA1, s)

        a = (a + aa) & _MASK
        b = (b + bb) & _MASK
        c = (c + cc) & _MASK
        d = (d + dd) & _MASK

    return struct.pack("<4I", a, b, c, d)


def md4_hex(data: bytes) -> str:
    return md4(data).hex()


def ntlm_hex(password: str) -> str:
    """NTLM hash = MD4 of the UTF-16LE encoding of the password."""
    return md4(password.encode("utf-16le")).hex()


# RFC 1320 test suite
_RFC_VECTORS = [
    (b"", "31d6cfe0d16ae931b73c59d7e0c089c0"),
    (b"a", "bde52cb31de33e46245e05fbdbd6fb24"),
    (b"abc", "a448017aaf21d8525fc10ae87aa6729d"),
    (b"message digest", "d9130a8164549fe818874806e1c7014b"),
    (b"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"),
    (b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
     "043f8582f241db351ce627e153e7f0e4"),
    (b"123456789012345678901234567890123456789012345678901234567890"
     b"12345678901234567890", "e33b4ddc9c38f2199c3e7b164fcc0536"),
]


def self_test() -> bool:
    for data, expected in _RFC_VECTORS:
        if md4_hex(data) != expected:
            return False
    # NTLM("password") - widely published vector
    if ntlm_hex("password") != "8846f7eaee8fb117ad06bdd830b7586c":
        return False
    return True


if __name__ == "__main__":
    print("MD4 self-test:", "PASS" if self_test() else "FAIL")
