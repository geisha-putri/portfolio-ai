# Phishing URL Detector

A Random-Forest classifier that decides whether a URL is phishing **without fetching it** — purely from lexical/structural features. Zero external API cost, works offline after training.

## Features used

- URL length, number of dots/slashes/hyphens
- Contains `@` / `javascript:` / hex-encoded chars
- Uses IP address as hostname
- Suspicious TLD flags
- Presence of words like `login`, `verify`, `secure`, `update`

## Files

- `detect.py` — main detector (train + predict)
- `sample_data.csv` — small labelled toy dataset

## Quickstart

```bash
python detect.py --url "https://secure-login-verify.bank-update.com/auth"
# -> [PHISHING] confidence 0.93
```