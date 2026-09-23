#!/usr/bin/env python3
"""Independent check of the transparent leg of `tests/key_derivation.rs`.

Derives the Zcash mainnet P2PKH address at BIP-44 path m/44'/133'/<account>'/0/<index>
from a BIP-39 phrase, using only the Python standard library: PBKDF2 for the seed,
HMAC-SHA512 for BIP-32, and a from-scratch secp256k1 point multiplication. It shares
no code with the Rust crates under test, so if it agrees with
`KnownWallet::default_ua_transparent` the transparent receiver of the committed
unified address was derived correctly.

    python3 tests/fixtures/verify_transparent_leg.py "abandon abandon ... art" [index] [account]

The Sapling and Orchard receivers are NOT covered here; see the module docs of
`tests/key_derivation.rs` for how to check those with a second wallet.
"""
import hashlib
import hmac
import sys

# ── secp256k1 ────────────────────────────────────────────────────────────────
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (
    0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8,
)


def _add(a, b):
    if a is None:
        return b
    if b is None:
        return a
    if a[0] == b[0] and (a[1] + b[1]) % P == 0:
        return None
    if a == b:
        lam = (3 * a[0] * a[0]) * pow(2 * a[1], P - 2, P) % P
    else:
        lam = (b[1] - a[1]) * pow(b[0] - a[0], P - 2, P) % P
    x = (lam * lam - a[0] - b[0]) % P
    return (x, (lam * (a[0] - x) - a[1]) % P)


def _mul(k, pt):
    r = None
    while k:
        if k & 1:
            r = _add(r, pt)
        pt = _add(pt, pt)
        k >>= 1
    return r


def _compress(pt):
    return bytes([2 + (pt[1] & 1)]) + pt[0].to_bytes(32, "big")


def _decompress(b):
    x = int.from_bytes(b[1:], "big")
    y = pow((x ** 3 + 7) % P, (P + 1) // 4, P)
    if (y & 1) != (b[0] & 1):
        y = P - y
    return (x, y)


# ── BIP-32 ───────────────────────────────────────────────────────────────────
def _ckd_priv(k, c, i):
    data = (b"\x00" + k.to_bytes(32, "big") if i >= 1 << 31 else _compress(_mul(k, G))) + i.to_bytes(4, "big")
    I = hmac.new(c, data, hashlib.sha512).digest()
    return (int.from_bytes(I[:32], "big") + k) % N, I[32:]


def _ckd_pub(K, c, i):
    assert i < 1 << 31
    I = hmac.new(c, _compress(K) + i.to_bytes(4, "big"), hashlib.sha512).digest()
    return _add(_mul(int.from_bytes(I[:32], "big"), G), K), I[32:]


# ── Zcash t-address ──────────────────────────────────────────────────────────
_B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def _b58check(payload):
    chk = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    n = int.from_bytes(payload + chk, "big")
    out = ""
    while n:
        n, r = divmod(n, 58)
        out = _B58[r] + out
    return "1" * (len(payload + chk) - len((payload + chk).lstrip(b"\x00"))) + out


def t_address(phrase, index=0, account=0, passphrase=""):
    seed = hashlib.pbkdf2_hmac("sha512", phrase.encode(), ("mnemonic" + passphrase).encode(), 2048)
    I = hmac.new(b"Bitcoin seed", seed, hashlib.sha512).digest()
    k, c = int.from_bytes(I[:32], "big"), I[32:]
    H = 1 << 31
    for i in (44 + H, 133 + H, account + H):   # hardened: needs the private key
        k, c = _ckd_priv(k, c, i)
    K = _mul(k, G)
    for i in (0, index):                       # external chain, then the address index
        K, c = _ckd_pub(K, c, i)
    h160 = hashlib.new("ripemd160", hashlib.sha256(_compress(K)).digest()).digest()
    return _b58check(b"\x1c\xb8" + h160)       # 0x1CB8 = mainnet P2PKH "t1"


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(__doc__)
    phrase = " ".join(sys.argv[1].split())
    index = int(sys.argv[2]) if len(sys.argv) > 2 else 0
    account = int(sys.argv[3]) if len(sys.argv) > 3 else 0
    print(t_address(phrase, index, account))
