"""
AI News Digest Bot — RSS → ranked digest → Telegram.
Free-tier only: uses urllib + xml.etree (stdlib). No API keys except Telegram.
Usage: python digest.py [--dry-run] [--limit 5]
"""
import argparse
import os
import re
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timezone

FEEDS = [
    "https://hnrss.org/newest",
    "https://thehackernews.com/feed",
    "https://www.schneier.com/feed/atom",
    "https://venturebeat.com/category/ai/feed/",
]

KEYWORDS = re.compile(r"ai|llm|gpt|cyber|security|hack|privacy|model|neural|agent|exploit", re.I)


def fetch(url: str, timeout: int = 10) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "digest-bot/0.1"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read().decode("utf-8", errors="ignore")


def parse_items(xml: str, feed_title: str) -> list:
    items = []
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        return items
    for entry in root.iter():
        if entry.tag.rsplit("}", 1)[-1] in ("item", "entry"):
            title = (entry.findtext("title") or "").strip()
            link = (entry.findtext("link") or "").strip()
            if title and link:
                score = 3 if KEYWORDS.search(title) else 0
                items.append({"title": title, "link": link, "source": feed_title, "score": score})
                # only first N per feed to keep it light
                if len(items) >= 10:
                    break
    return items


def build_digest(limit: int = 5) -> str:
    all_items = []
    for feed in FEEDS:
        try:
            all_items += parse_items(fetch(feed), feed)
        except Exception:
            continue
    all_items.sort(key=lambda i: i["score"], reverse=True)
    top = all_items[:limit]
    lines = [f"AI × Security digest — {datetime.now(timezone.utc).strftime('%b %d, %H:%M UTC')}"]
    for i, item in enumerate(top, 1):
        star = "★" if item["score"] else " "
        lines.append(f"{i}. {star} {item['title']}\n   {item['link']} ({item['source']})")
    return "\n\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--limit", type=int, default=5)
    args = ap.parse_args()

    digest = build_digest(args.limit)
    print(digest)

    if args.dry_run:
        return
    token = os.getenv("TG_BOT_TOKEN")
    chat = os.getenv("TG_CHAT_ID")
    if not (token and chat):
        print("\n[skip] TG_BOT_TOKEN/TG_CHAT_ID not set — dry-run only", file=os.sys.stderr)
        return
    import urllib.parse
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    data = urllib.parse.urlencode({"chat_id": chat, "text": digest, "disable_web_page_preview": "true"}).encode()
    urllib.request.urlopen(url, data=data, timeout=15)  # noqa: S310 (sandbox-friendly)


if __name__ == "__main__":
    main()