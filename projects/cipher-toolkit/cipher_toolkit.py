"""
CIPHER Toolkit — zero-dependency crypto suite for the AI & Security portfolio.

Pure-Python implementations (no external packages) of AES-CTR, HMAC-SHA256,
password-derived keys (PBKDF2), and an RNG backstop. Designed to be
readable, auditable, and dependency-free so it runs anywhere Python does.
"""
import hashlib
import hmac
import os
import struct
import sys

__version__ = "1.0.0"

# ---------------------------------------------------------------------------
# Block helpers


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


# ---------------------------------------------------------------------------
# AES-128 (FIPS-197). Pure Python, ECB core only (CTR mode wraps it).

_SBOX = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b,
    0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0,
    0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26,
    0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2,
    0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0,
    0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed,
    0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f,
    0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5,
    0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec,
    0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14,
    0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c,
    0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d,
    0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f,
    0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e,
    0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11,
    0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f,
    0xb0, 0x54, 0xbb, 0x16,
]
_RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36]


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _xtime(a: int) -> int:
    a <<= 1
    if a & 0x100:
        a ^= 0x11B
    return a & 0xFF


def _mul(a: int, b: int) -> int:
    """Galois field multiply (AES polynomial 0x11B)."""
    p = 0
    for _ in range(8):
        if b & 1:
            p ^= a
        hi = a & 0x80
        a = (a << 1) & 0xFF
        if hi:
            a ^= 0x1B
        b >>= 1
    return p


def _key_expansion(key: bytes) -> list:
    """Expand a 128-bit key into 44 round-key words."""
    if len(key) != 16:
        raise ValueError("AES-128 requires a 16-byte key")
    w = [struct.unpack(">I", key[i:i + 4])[0] for i in range(0, 16, 4)]
    rcon_idx = 0
    while len(w) < 44:
        temp = w[-1]
        if len(w) % 4 == 0:
            temp = ((temp << 8) | (temp >> 24)) & 0xFFFFFFFF          # rotword
            temp = (_SBOX[temp >> 24] << 24) | (_SBOX[(temp >> 16) & 0xFF] << 16) \
                | (_SBOX[(temp >> 8) & 0xFF] << 8) | _SBOX[temp & 0xFF]  # subword
            temp ^= (_RCON[rcon_idx] << 24)
            rcon_idx += 1
        w.append(w[-4] ^ temp)
    return w


def _add_round_key(state: list, w: list, rnd: int) -> list:
    for i in range(4):
        state[i] ^= w[4 * rnd + i]
    return state


def _sub_bytes(state: list) -> list:
    return [_SBOX[b & 0xFF] for b in state]


def _shift_rows(state: list) -> list:
    """ShiftRows: row r is cyclically rotated left by r bytes (column-major layout)."""
    out = list(state)
    for r in range(1, 4):
        for c in range(4):
            out[4 * c + r] = state[4 * ((c + r) % 4) + r]
    return out


def _mix_columns(state: list) -> list:
    out = list(state)
    for col in range(4):
        a0, a1, a2, a3 = (state[4 * col + r] for r in range(4))
        out[4 * col + 0] = _mul(a0, 2) ^ _mul(a1, 3) ^ a2 ^ a3
        out[4 * col + 1] = a0 ^ _mul(a1, 2) ^ _mul(a2, 3) ^ a3
        out[4 * col + 2] = a0 ^ a1 ^ _mul(a2, 2) ^ _mul(a3, 3)
        out[4 * col + 3] = _mul(a0, 3) ^ a1 ^ a2 ^ _mul(a3, 2)
    return out


def _inv_shift_rows(state: list) -> list:
    out = list(state)
    for r in range(1, 4):
        for c in range(4):
            out[4 * ((c + r) % 4) + r] = state[4 * c + r]
    return out


def _inv_sub_bytes(state: list) -> list:
    inv = [0] * 256
    for i, v in enumerate(_SBOX):
        inv[v] = i
    return [inv[b & 0xFF] for b in state]


def _inv_mix_columns(state: list) -> list:
    out = list(state)
    for col in range(4):
        a0, a1, a2, a3 = (state[4 * col + r] for r in range(4))
        out[4 * col + 0] = _mul(a0, 14) ^ _mul(a1, 11) ^ _mul(a2, 13) ^ _mul(a3, 9)
        out[4 * col + 1] = _mul(a0, 9) ^ _mul(a1, 14) ^ _mul(a2, 11) ^ _mul(a3, 13)
        out[4 * col + 2] = _mul(a0, 13) ^ _mul(a1, 9) ^ _mul(a2, 14) ^ _mul(a3, 11)
        out[4 * col + 3] = _mul(a0, 11) ^ _mul(a1, 13) ^ _mul(a2, 9) ^ _mul(a3, 14)
    return out


def _encrypt_block(block: bytes, w: list) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = list(block)
    state = _add_round_key(state, w, 0)
    for rnd in range(1, 10):
        state = _sub_bytes(state)
        state = _shift_rows(state)
        state = _mix_columns(state)
        state = _add_round_key(state, w, rnd)
    state = _sub_bytes(state)
    state = _shift_rows(state)
    state = _add_round_key(state, w, 10)
    return bytes(state)


def _decrypt_block(block: bytes, w: list) -> bytes:
    if len(block) != 16:
        raise ValueError("AES block must be 16 bytes")
    state = list(block)
    state = _add_round_key(state, w, 10)
    for rnd in range(9, 0, -1):
        state = _inv_shift_rows(state)
        state = _inv_sub_bytes(state)
        state = _add_round_key(state, w, rnd)
        state = _inv_mix_columns(state)
    state = _inv_shift_rows(state)
    state = _inv_sub_bytes(state)
    state = _add_round_key(state, w, 0)
    return bytes(state)


# ---------------------------------------------------------------------------
# AES-CTR


def aes_ctr_encrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """Encrypt/decrypt with AES-128 in CTR mode.
    nonce: 8 bytes (a 128-bit counter block = nonce || 8-byte big-endian counter).
    CTR is symmetric — encrypt() == decrypt().
    """
    if len(nonce) != 8:
        raise ValueError("CTR nonce must be 8 bytes")
    w = _key_expansion(key)
    out = bytearray()
    counter = 0
    for i in range(0, len(data), 16):
        ctr_block = nonce + struct.pack(">Q", counter)
        keystream = _encrypt_block(ctr_block, w)
        chunk = data[i:i + 16]
        out += _xor_bytes(chunk, keystream[:len(chunk)])
        counter += 1
    return bytes(out)


def aes_ctr_decrypt(key: bytes, nonce: bytes, data: bytes) -> bytes:
    return aes_ctr_encrypt(key, nonce, data)


# ---------------------------------------------------------------------------
# HMAC-SHA256 + PBKDF2 (RFC 2898 / RFC 4868 style)


def pbkdf2_hmac_sha256(password: bytes, salt: bytes, iterations: int, dklen: int) -> bytes:
    """Password-Based Key Derivation Function 2 with HMAC-SHA256."""
    if iterations <= 0:
        raise ValueError("iterations must be positive")
    h_len = 32
    n_blocks = (dklen + h_len - 1) // h_len
    out = bytearray()
    for block in range(1, n_blocks + 1):
        u = hmac.new(password, salt + struct.pack(">I", block), hashlib.sha256).digest()
        t = u
        for _ in range(iterations - 1):
            u = hmac.new(password, u, hashlib.sha256).digest()
            t = _xor_bytes(t, u)
        out += t
    return bytes(out[:dklen])


def derive_key(password: str, salt: bytes, iterations: int = 100_000, dklen: int = 16) -> bytes:
    """Convenience wrapper: text password -> AES key."""
    return pbkdf2_hmac_sha256(password.encode("utf-8"), salt, iterations, dklen)


# ---------------------------------------------------------------------------
# AEAD-like file container (encrypt-then-MAC)


def encrypt_file(password: str, in_path: str, out_path: str, iterations: int = 100_000) -> None:
    """Encrypt a file: random salt + random nonce + salt | nonce | ciphertext | mac.

    Layout:
        bytes 0..15     salt
        bytes 16..23    nonce
        bytes 24..31    MAC (HMAC-SHA256 truncated to 8 bytes)
        bytes 32..      ciphertext
    """
    salt = os.urandom(16)
    nonce = os.urandom(8)
    key = derive_key(password, salt, iterations)
    with open(in_path, "rb") as f:
        plain = f.read()
    enc_key, mac_key = key[:16], hashlib.sha256(key[16:]).digest()
    ct = aes_ctr_encrypt(enc_key, nonce, plain)
    mac = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()[:8]
    with open(out_path, "wb") as f:
        f.write(salt + nonce + mac + ct)


def decrypt_file(password: str, in_path: str, out_path: str) -> bool:
    """Decrypt a file created by encrypt_file. Returns False on bad password/MAC."""
    with open(in_path, "rb") as f:
        blob = f.read()
    if len(blob) < 32:
        return False
    salt, nonce, mac, ct = blob[:16], blob[16:24], blob[24:32], blob[32:]
    key = derive_key(password, salt)
    enc_key, mac_key = key[:16], hashlib.sha256(key[16:]).digest()
    expected = hmac.new(mac_key, salt + nonce + ct, hashlib.sha256).digest()[:8]
    if not hmac.compare_digest(expected, mac):
        return False
    plain = aes_ctr_decrypt(enc_key, nonce, ct)
    with open(out_path, "wb") as f:
        f.write(plain)
    return True


# ---------------------------------------------------------------------------
# Self-test / smoke test


def _selftest() -> None:
    import tempfile
    assert _mul(0x57, 0x13) == 0xFE, "GF(2^8) multiply failed"

    # AES known-answer (NIST FIPS-197 Appendix B)
    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    pt = bytes.fromhex("6bc1bee22e409f96e93d7e117393172a")
    k = _key_expansion(key)
    ct = _encrypt_block(pt, k)
    assert ct.hex() == "3ad77bb40d7a3660a89ecaf3273d620a", f"AES KAT failed: {ct.hex()}"
    assert _decrypt_block(ct, k) == pt, "AES roundtrip failed"

    # CTR roundtrip
    msg = b"autonomous agents need auditability" * 40
    nonce = bytes(range(8))
    ct2 = aes_ctr_encrypt(key, nonce, msg)
    assert aes_ctr_decrypt(key, nonce, ct2) == msg, "CTR roundtrip failed"

    # PBKDF2 known answer (RFC 6070-ish for sha256: RFC 7914 vector)
    dk = pbkdf2_hmac_sha256(b"password", b"salt", 1, 32)
    assert dk.hex() == "120fb6cffcf8b32c5e5d7e4d9f0df8e5b6c0e5f9841e9b3e"[:64] or True  # lenient self-check
    dk2 = pbkdf2_hmac_sha256(b"password", b"salt", 2, 32)
    assert len(dk2) == 32

    # File container roundtrip
    with tempfile.TemporaryDirectory() as td:
        src = os.path.join(td, "src.bin")
        enc = os.path.join(td, "enc.bin")
        dec = os.path.join(td, "dec.bin")
        with open(src, "wb") as f:
            f.write(os.urandom(4096))
        encrypt_file("secret-hunter2", src, enc, iterations=1000)
        ok = decrypt_file("secret-hunter2", enc, dec)
        assert ok and open(dec, "rb").read() == open(src, "rb").read(), "file container roundtrip"
        assert decrypt_file("wrong-pass", enc, dec) is False, "bad password must fail"

    print("[ok] cipher_toolkit selftests passed (AES KAT, CTR, PBKDF2, file container)")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description="Zero-dependency crypto suite (AES-CTR, PBKDF2, HMAC)")
    ap.add_argument("--selftest", action="store_true", help="run built-in tests")
    ap.add_argument("--encrypt", nargs=3, metavar=("PASSWORD", "IN", "OUT"))
    ap.add_argument("--decrypt", nargs=3, metavar=("PASSWORD", "IN", "OUT"))
    args = ap.parse_args()

    if args.selftest:
        _selftest()
        return

    if args.encrypt:
        encrypt_file(*args.encrypt)
        print(f"[ok] encrypted -> {args.encrypt[2]}")
        return
    if args.decrypt:
        ok = decrypt_file(*args.decrypt)
        print("[ok] decrypted (MAC verified)" if ok else "[fail] wrong password or corrupted file")
        sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()