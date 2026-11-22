"""Breach lookups: Have I Been Pwned, Dehashed, Intelligence X.

Each provider is optional and turns on when its API key is set (see .env.example).
Results are summarised: tracefind reports *which* breaches and *which kinds* of data were
exposed, never the leaked passwords, hashes or other secret values themselves.
"""
from __future__ import annotations

import asyncio
import os
import re
from urllib.parse import quote

import httpx

UA = "tracefind/1.0 (Maypen Cybersecurity)"
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
SECRET_FIELDS = {"password", "hashed_password", "hash", "salt", "secret", "token"}


class ProviderError(Exception):
    pass


def configured() -> dict[str, bool]:
    return {"hibp": bool(os.getenv("HIBP_API_KEY")),
            "dehashed": bool(os.getenv("DEHASHED_API_KEY")),
            "intelx": bool(os.getenv("INTELX_API_KEY"))}


# ---------- Have I Been Pwned (v3) ----------

async def hibp(email: str, client: httpx.AsyncClient) -> dict:
    key = os.getenv("HIBP_API_KEY")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}?truncateResponse=false"
    r = await client.get(url, headers={"hibp-api-key": key, "user-agent": UA})
    if r.status_code == 404:
        return {"provider": "hibp", "count": 0, "breaches": []}
    if r.status_code == 401:
        raise ProviderError("HIBP rejected the API key")
    if r.status_code == 429:
        raise ProviderError("HIBP rate limit hit; wait a few seconds and retry")
    r.raise_for_status()
    breaches = [{"name": b.get("Title") or b.get("Name"), "domain": b.get("Domain"),
                 "date": b.get("BreachDate"), "accounts": b.get("PwnCount"),
                 "data_types": b.get("DataClasses", []), "verified": b.get("IsVerified")}
                for b in r.json()]
    breaches.sort(key=lambda b: b["date"] or "", reverse=True)
    return {"provider": "hibp", "count": len(breaches), "breaches": breaches}


# ---------- Dehashed (API v2) ----------

async def dehashed(query: str, client: httpx.AsyncClient) -> dict:
    key = os.getenv("DEHASHED_API_KEY")
    base = os.getenv("DEHASHED_BASE", "https://api.dehashed.com/v2")
    field = "email" if EMAIL_RE.match(query) else "username"
    r = await client.post(f"{base}/search", headers={"Dehashed-Api-Key": key, "User-Agent": UA},
                          json={"query": f'{field}:"{query}"', "page": 1, "size": 100, "de_dupe": True})
    if r.status_code in (401, 403):
        raise ProviderError("Dehashed rejected the API key or the account has no API credits")
    r.raise_for_status()
    data = r.json()
    by_db: dict[str, set] = {}
    for e in data.get("entries") or []:
        db = e.get("database_name") or "unknown source"
        exposed = {k for k, v in e.items() if v and k not in {"id", "database_name"}}
        by_db.setdefault(db, set()).update(exposed)
    sources = [{"name": db, "data_types": sorted(f.replace("_", " ") for f in fields),
                "secrets_exposed": bool(fields & SECRET_FIELDS)}
               for db, fields in sorted(by_db.items())]
    return {"provider": "dehashed", "count": len(sources), "total_records": data.get("total"),
            "breaches": sources}


# ---------- Intelligence X ----------

async def intelx(term: str, client: httpx.AsyncClient, max_results: int = 50) -> dict:
    key = os.getenv("INTELX_API_KEY")
    base = os.getenv("INTELX_BASE", "https://free.intelx.io")
    h = {"x-key": key, "User-Agent": UA}
    r = await client.post(f"{base}/intelligent/search", headers=h,
                          json={"term": term, "maxresults": max_results, "media": 0, "sort": 2, "terminate": []})
    if r.status_code in (401, 402):
        raise ProviderError("Intelligence X rejected the API key (free keys use free.intelx.io)")
    r.raise_for_status()
    sid = r.json().get("id")
    records = []
    for _ in range(10):  # poll until results are complete (status 1) or out of attempts
        rr = await client.get(f"{base}/intelligent/search/result", headers=h,
                              params={"id": sid, "limit": max_results})
        rr.raise_for_status()
        body = rr.json()
        records += body.get("records") or []
        if body.get("status") in (1, 2, 3) or len(records) >= max_results:
            break
        await asyncio.sleep(1.0)
    hits = [{"name": rec.get("name") or rec.get("systemid"), "date": (rec.get("date") or "")[:10],
             "bucket": rec.get("bucketh") or rec.get("bucket")} for rec in records[:max_results]]
    return {"provider": "intelx", "count": len(hits), "breaches": hits}


PROVIDERS = {"hibp": hibp, "dehashed": dehashed, "intelx": intelx}


async def lookup(term: str, providers: list[str] | None = None, transport=None) -> list[dict]:
    """Run every configured provider (or the ones asked for) and collect results/errors."""
    enabled = [p for p, ok in configured().items() if ok and (not providers or p in providers)]
    out = []
    async with httpx.AsyncClient(timeout=20, transport=transport) as client:
        for p in enabled:
            if p == "hibp" and not EMAIL_RE.match(term):
                out.append({"provider": p, "skipped": "HIBP searches email addresses only"})
                continue
            try:
                out.append(await PROVIDERS[p](term, client))
            except ProviderError as e:
                out.append({"provider": p, "error": str(e)})
            except httpx.HTTPError as e:
                out.append({"provider": p, "error": f"request failed ({type(e).__name__})"})
    return out
