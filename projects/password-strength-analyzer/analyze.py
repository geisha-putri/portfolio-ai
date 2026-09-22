"""
Password strength analyzer — entropy estimate + pattern penalties.
"""
import math
import re
import sys

COMMON_PASSWORDS = {
    "password", "123456", "12345678", "qwerty", "abc123", "password1",
    "iloveyou", "admin", "welcome", "monkey", "dragon", "letmein",
    "sunshine", "princess", "football", "shadow", "master", "1234567890",
    "p@ssw0rd", "admin123", "changeme", "default",
}

CHARSETS = [
    (r"[a-z]", 26), (r"[A-Z]", 26), (r"[0-9]", 10),
    (r"[^a-zA-Z0-9]", 33), (r"[\x80-\xff]", 1000),
]


def charset_pool(password: str) -> int:
    pool = 0
    for pattern, size in CHARSETS:
        if re.search(pattern, password):
            pool += size
    return pool


def entropy_bits(password: str) -> float:
    if not password:
        return 0.0
    pool = charset_pool(password)
    base = len(password) * math.log2(pool if pool else 1)
    penalty = 0.0
    if password.lower() in COMMON_PASSWORDS:
        penalty = base * 0.9
    if re.search(r"(.)\1{2,}", password):
        penalty += 12
    if re.search(r"(0123456789|abcdefghijkl|qwerty)", password.lower()):
        penalty += 10
    return max(0.0, base - penalty)


def grade(bits: float) -> str:
    if bits >= 60:
        return "STRONG"
    if bits >= 35:
        return "MEDIUM"
    return "WEAK"


def main():
    pw = sys.argv[1] if len(sys.argv) > 1 else "correct horse battery staple"
    bits = entropy_bits(pw)
    print(f"entropy: {bits:.1f} bits — {grade(bits)}")
    if bits < 35:
        print("suggest: 14+ chars, mixed case, digits, symbols, no dictionary words.")


if __name__ == "__main__":
    main()