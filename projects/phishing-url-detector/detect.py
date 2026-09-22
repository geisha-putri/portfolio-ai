"""
Phishing URL Detector — Random Forest classifier on lexical URL features.
Zero-cost: sklearn only, tiny dataset, no network calls.
"""
import re
import sys
from urllib.parse import urlparse

try:
    import numpy as np
    from sklearn.ensemble import RandomForestClassifier
except ImportError:
    print("This demo needs: pip install scikit-learn numpy")
    sys.exit(1)


SUSPICIOUS_WORDS = {"login", "verify", "secure", "update", "account",
                    "bank", "wallet", "confirm", "signin", "auth"}


def extract_features(url: str) -> list:
    url = url.lower().strip()
    p = urlparse(url if "://" in url else "http://" + url)
    host = p.hostname or ""
    feats = [
        len(url),                                          # total length
        url.count("."),
        url.count("/"),
        url.count("-"),
        1 if "@" in url else 0,
        1 if "javascript:" in url else 0,
        1 if re.search(r"%[0-9a-f]{2}", url) else 0,
        1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else 0,  # raw IP host
        1 if host.endswith((".tk", ".ml", ".ga", ".cf", ".gq")) else 0,
        len(host),
        sum(1 for w in SUSPICIOUS_WORDS if w in url),
        1 if p.scheme == "https" else 0,
    ]
    return feats


def train():
    # Tiny labelled toy set: (url, 1=phishing, 0=legit)
    rows = [
        ("http://secure-login-verify.bank-update.com/auth", 1),
        ("https://paypa1-secure-verify.web.ma/confirm", 1),
        ("http://192.168.1.250/update/account/login", 1),
        ("https://free-bitcoin-claim.gq/verify", 1),
        ("https://www.github.com/login", 0),
        ("https://www.google.com/search?q=python", 0),
        ("https://stackoverflow.com/questions/1", 0),
        ("https://mail.google.com/mail/u/0/", 0),
        ("https://www.wikipedia.org/", 0),
        ("https://news.ycombinator.com/", 0),
    ]
    X = np.array([extract_features(u) for u, _ in rows])
    y = np.array([l for _, l in rows])
    clf = RandomForestClassifier(n_estimators=50, random_state=7)
    clf.fit(X, y)
    return clf


def main():
    clf = train()
    targets = sys.argv[1:] or [
        "https://secure-login-verify.bank-update.com/auth",
        "https://www.github.com/login",
    ]
    for url in targets:
        prob = clf.predict_proba([extract_features(url)])[0]
        verdict = "PHISHING" if prob[1] >= 0.5 else "LEGIT"
        print(f"[{verdict}] conf={prob[1]:.2f} <- {url}")


if __name__ == "__main__":
    main()