"""Cryptography used by the chain: SHA-256, secp256k1 ECDSA, Bitcoin-style addresses.

Everything is pure Python so you can read exactly what happens. It is NOT
constant-time and must not be used to protect real money.
"""
import hashlib
import hmac
import secrets

# ---------------------------------------------------------------- hashing

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def sha256d(data: bytes) -> bytes:
    """Bitcoin hashes almost everything twice."""
    return sha256(sha256(data))


def _ripemd160_py(data: bytes) -> bytes:
    """Pure-Python RIPEMD-160, used when OpenSSL does not ship it."""
    ML = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
          7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
          3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
          1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
          4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13]
    MR = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
          6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
          15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
          8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
          12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11]
    RL = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
          7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
          11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
          11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
          9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6]
    RR = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
          9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
          9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
          15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
          8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11]
    KL = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E]
    KR = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000]
    M32 = 0xFFFFFFFF

    def f(x, y, z, i):
        return [x ^ y ^ z, (x & y) | (~x & z), (x | ~y) ^ z,
                (x & z) | (y & ~z), x ^ (y | ~z)][i]

    def rol(x, n):
        x &= M32
        return ((x << n) | (x >> (32 - n))) & M32

    def compress(h, block):
        x = [int.from_bytes(block[4 * i:4 * i + 4], "little") for i in range(16)]
        al, bl, cl, dl, el = h
        ar, br, cr, dr, er = h
        for j in range(80):
            r = j >> 4
            al = rol(al + f(bl, cl, dl, r) + x[ML[j]] + KL[r], RL[j]) + el
            al, bl, cl, dl, el = el, al, bl, rol(cl, 10), dl
            ar = rol(ar + f(br, cr, dr, 4 - r) + x[MR[j]] + KR[r], RR[j]) + er
            ar, br, cr, dr, er = er, ar, br, rol(cr, 10), dr
        return [(h[1] + cl + dr) & M32, (h[2] + dl + er) & M32, (h[3] + el + ar) & M32,
                (h[4] + al + br) & M32, (h[0] + bl + cr) & M32]

    msg = data + b"\x80" + b"\x00" * ((55 - len(data)) % 64) + (8 * len(data)).to_bytes(8, "little")
    h = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0]
    for i in range(0, len(msg), 64):
        h = compress(h, msg[i:i + 64])
    return b"".join(v.to_bytes(4, "little") for v in h)


def ripemd160(data: bytes) -> bytes:
    try:
        return hashlib.new("ripemd160", data).digest()
    except ValueError:
        return _ripemd160_py(data)


def hash160(data: bytes) -> bytes:
    return ripemd160(sha256(data))


# ---------------------------------------------------------------- secp256k1
# The same curve Bitcoin uses: y^2 = x^3 + 7 over the prime field P.

P = 2 ** 256 - 2 ** 32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def point_add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None  # point at infinity
    if a == b:
        lam = 3 * a[0] * a[0] * pow(2 * a[1], -1, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], -1, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return x, (lam * (a[0] - x) - a[1]) % P


def point_mul(k: int, point=G):
    result = None
    while k:
        if k & 1:
            result = point_add(result, point)
        point = point_add(point, point)
        k >>= 1
    return result


def new_private_key() -> int:
    return secrets.randbelow(N - 1) + 1


def public_key(priv: int) -> bytes:
    """33-byte compressed public key."""
    x, y = point_mul(priv)
    return bytes([2 + (y & 1)]) + x.to_bytes(32, "big")


def decode_public_key(pub: bytes):
    if len(pub) != 33 or pub[0] not in (2, 3):
        raise ValueError("bad public key")
    x = int.from_bytes(pub[1:], "big")
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if (y * y - x ** 3 - 7) % P:
        raise ValueError("public key not on curve")
    if (y & 1) != (pub[0] & 1):
        y = P - y
    return x, y


def sign(priv: int, msg_hash: bytes) -> bytes:
    """ECDSA signature (r || s, 64 bytes) with a deterministic nonce and low-S."""
    z = int.from_bytes(msg_hash, "big")
    counter = 0
    while True:
        # Deterministic nonce: never reuse k with a different message, or the key leaks.
        k = int.from_bytes(hmac.new(priv.to_bytes(32, "big"), msg_hash + bytes([counter]),
                                    hashlib.sha256).digest(), "big") % N
        counter += 1
        if k == 0:
            continue
        r = point_mul(k)[0] % N
        s = pow(k, -1, N) * (z + r * priv) % N
        if r and s:
            if s > N // 2:
                s = N - s  # low-S stops signature malleability
            return r.to_bytes(32, "big") + s.to_bytes(32, "big")


def verify(pub: bytes, msg_hash: bytes, sig: bytes) -> bool:
    try:
        q = decode_public_key(pub)
    except ValueError:
        return False
    if len(sig) != 64:
        return False
    r, s = int.from_bytes(sig[:32], "big"), int.from_bytes(sig[32:], "big")
    if not (0 < r < N and 0 < s <= N // 2):
        return False
    z = int.from_bytes(msg_hash, "big")
    w = pow(s, -1, N)
    point = point_add(point_mul(z * w % N), point_mul(r * w % N, q))
    return point is not None and point[0] % N == r


# ---------------------------------------------------------------- addresses

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ADDRESS_VERSION = 0x00  # same as Bitcoin, so addresses start with "1"


def b58check_encode(payload: bytes) -> str:
    data = payload + sha256d(payload)[:4]
    n = int.from_bytes(data, "big")
    out = ""
    while n:
        n, rem = divmod(n, 58)
        out = B58[rem] + out
    return "1" * (len(data) - len(data.lstrip(b"\0"))) + out


def b58check_decode(s: str) -> bytes:
    n = 0
    for c in s:
        n = n * 58 + B58.index(c)
    data = n.to_bytes((n.bit_length() + 7) // 8, "big")
    data = b"\0" * (len(s) - len(s.lstrip("1"))) + data
    payload, checksum = data[:-4], data[-4:]
    if sha256d(payload)[:4] != checksum:
        raise ValueError("bad address checksum")
    return payload


def address_from_pubkey(pub: bytes) -> str:
    return b58check_encode(bytes([ADDRESS_VERSION]) + hash160(pub))


def is_valid_address(addr: str) -> bool:
    try:
        payload = b58check_decode(addr)
    except (ValueError, IndexError):
        return False
    return len(payload) == 21 and payload[0] == ADDRESS_VERSION
