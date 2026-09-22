# AI News Digest Bot (autonomous agent)

A scheduled agent that:
1. Pulls AI + cybersecurity headlines from free RSS feeds (Hacker News, RSSHub, etc.)
2. Deduplicates and ranks by freshness/relevance
3. Generates a structured digest (title, summary, tags)
4. Posts to a Telegram channel via bot API

This project is the **Content Creator** agent in my autonomous pipeline — it runs on a cron schedule and needs zero interaction.

## Files

- `digest.py` — RSS fetch + rank + Telegram post
- `feeds.txt` — list of RSS/Atom feeds

## Config (env vars)

- `TG_BOT_TOKEN` — Telegram bot token
- `TG_CHAT_ID` — chat/channel to post to

## Notes

- Uses only public RSS — no paid news APIs.
- Runs headless via cron: `0 18 * * * python digest.py --dry-run`.