"""Adapters from raw API responses to the report's ScanResult.

Wire these to whatever your scanner functions already return. The key rule:
leaked VALUES (passwords, hashes, phone numbers, addresses) never leave this
file — only the names of the data categories do.
"""
from __future__ import annotations

from datetime import date
from typing import Any, Iterable

from .models import Breach, PasteHit, UsernameHit

# Map platform names to categories. Extend this as your site list grows;
# anything missing is reported as "other".
PLATFORM_CATEGORIES = {
    # social
    "instagram": "social", "tiktok": "social", "twitter": "social", "x": "social",
    "facebook": "social", "reddit": "social", "snapchat": "social", "pinterest": "social",
    "threads": "social", "bluesky": "social", "mastodon": "social", "tumblr": "social",
    # professional
    "linkedin": "professional", "medium": "professional", "about.me": "professional",
    # developer
    "github": "developer", "gitlab": "developer", "stackoverflow": "developer",
    "dev.to": "developer", "hackerone": "developer", "npm": "developer", "pypi": "developer",
    # gaming
    "steam": "gaming", "twitch": "gaming", "xbox": "gaming", "roblox": "gaming",
    "chess.com": "gaming", "lichess": "gaming", "discord": "gaming",
    # creative
    "youtube": "creative", "soundcloud": "creative", "spotify": "creative",
    "behance": "creative", "dribbble": "creative", "deviantart": "creative",
    "bandcamp": "creative", "vimeo": "creative",
    # sensitive
    "tinder": "dating", "okcupid": "dating", "pof": "dating", "badoo": "dating",
    "onlyfans": "adult", "fansly": "adult", "pornhub": "adult", "chaturbate": "adult",
    "coinbase": "crypto", "binance": "crypto", "kraken": "crypto", "opensea": "crypto",
    "cash app": "finance", "venmo": "finance", "paypal": "finance", "patreon": "finance",
    "ebay": "marketplace", "etsy": "marketplace", "kijiji": "marketplace", "poshmark": "marketplace",
}


def categorize(platform: str) -> str:
    return PLATFORM_CATEGORIES.get(platform.strip().lower(), "other")


def _parse_date(v: Any) -> date | None:
    if not v:
        return None
    try:
        return date.fromisoformat(str(v)[:10])
    except ValueError:
        return None


def from_sherlock(hits: Iterable[dict]) -> list[UsernameHit]:
    """hits: [{"site"|"platform": str, "url": str}, ...] — only claimed/found ones."""
    out = []
    for h in hits:
        name = h.get("platform") or h.get("site") or "Unknown"
        out.append(UsernameHit(platform=name, url=h.get("url", ""),
                               category=h.get("category") or categorize(name)))
    return out


def from_hibp(breaches: Iterable[dict]) -> list[Breach]:
    """HIBP /breachedaccount/{account}?truncateResponse=false response."""
    return [Breach(name=b.get("Title") or b.get("Name", "Unknown"), source="HaveIBeenPwned",
                   breach_date=_parse_date(b.get("BreachDate")),
                   data_classes=list(b.get("DataClasses", [])),
                   is_verified=bool(b.get("IsVerified", True)))
            for b in breaches]


# Dehashed entry fields -> human-readable data class. Values are discarded.
_DEHASHED_FIELDS = {
    "email": "Email addresses", "username": "Usernames", "name": "Names",
    "password": "Passwords", "hashed_password": "Password hashes",
    "phone": "Phone numbers", "address": "Physical addresses",
    "ip_address": "IP addresses", "vin": "Vehicle identifiers", "dob": "Dates of birth",
}


def from_dehashed(entries: Iterable[dict]) -> list[Breach]:
    """Dehashed search entries, grouped by database_name. Only field NAMES survive."""
    grouped: dict[str, set[str]] = {}
    for e in entries:
        db = e.get("database_name") or "Unknown database"
        classes = grouped.setdefault(db, set())
        for field, label in _DEHASHED_FIELDS.items():
            v = e.get(field)
            if v and v != [""]:
                classes.add(label)
    return [Breach(name=db, source="Dehashed", data_classes=sorted(c)) for db, c in grouped.items()]


def from_intelx(records: Iterable[dict]) -> list[PasteHit]:
    """IntelX search result records."""
    return [PasteHit(source="IntelX", title=r.get("name") or "Untitled",
                     found_date=_parse_date(r.get("date") or r.get("added")),
                     bucket=r.get("bucketh") or r.get("bucket"))
            for r in records]


def merge_breaches(*lists: list[Breach]) -> list[Breach]:
    """Merge the same breach reported by several sources (match on name)."""
    merged: dict[str, Breach] = {}
    for lst in lists:
        for b in lst:
            key = b.name.strip().lower()
            if key in merged:
                m = merged[key]
                m.data_classes = sorted(set(m.data_classes) | set(b.data_classes))
                m.breach_date = m.breach_date or b.breach_date
                if b.source not in m.source:
                    m.source = f"{m.source}, {b.source}"
            else:
                merged[key] = b.model_copy()
    return list(merged.values())
