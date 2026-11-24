"""Breach lookups: XposedOrNot (free), Have I Been Pwned, Dehashed, Intelligence X.

XposedOrNot needs no key and is on by default (set TRACEFIND_DISABLE_XON=1 to turn it off).
The other providers turn on when their API key is set (see .env.example).
Results are enriched with HIBP's free breach catalogue (exact dates, consistent names).
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
    return {"xposedornot": os.getenv("TRACEFIND_DISABLE_XON", "") not in ("1", "true", "yes"),
            "hibp": bool(os.getenv("HIBP_API_KEY")),
            "dehashed": bool(os.getenv("DEHASHED_API_KEY")),
            "intelx": bool(os.getenv("INTELX_API_KEY"))}


# ---------- XposedOrNot (free, no key) ----------
# Free tier is for personal / low-volume use: 2 req/s, 25/hour, 100/day per IP.

XON_BASE = "https://api.xposedornot.com/v1"
_PASSWORD_RISKS = {"plaintext", "easytocrack", "hardtocrack"}


async def xposedornot(email: str, client: httpx.AsyncClient) -> dict:
    base = os.getenv("XON_BASE", XON_BASE)
    r = await client.get(f"{base}/breach-analytics", params={"email": email}, headers={"User-Agent": UA})
    if r.status_code == 404:
        return {"provider": "xposedornot", "count": 0, "breaches": []}
    if r.status_code == 429:
        wait = r.headers.get("Retry-After")
        raise ProviderError("XposedOrNot free-tier limit reached (25 lookups/hour, 100/day)"
                            + (f"; try again in {wait}s" if wait else ""))
    r.raise_for_status()
    body = r.json() or {}
    exposed = body.get("ExposedBreaches") or {}
    details = exposed.get("breaches_details") if isinstance(exposed, dict) else None
    breaches = []
    for d in details or []:
        types = [t.strip() for t in str(d.get("xposed_data") or "").split(";") if t.strip()]
        risk = str(d.get("password_risk") or "").lower()
        year = str(d.get("xposed_date") or "")[:4]
        breaches.append({
            "name": d.get("breach") or "Unknown", "domain": d.get("domain") or None,
            "date": year or None, "accounts": d.get("xposed_records"),
            "data_types": types, "verified": str(d.get("verified", "")).lower() not in ("no", "false", "0"),
            "secrets_exposed": risk in _PASSWORD_RISKS or any("password" in t.lower() for t in types),
        })
    pastes = (body.get("PastesSummary") or {}).get("cnt") if isinstance(body.get("PastesSummary"), dict) else None
    out = {"provider": "xposedornot", "count": len(breaches), "breaches": breaches}
    if pastes:
        out["pastes"] = int(pastes)
    return out


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


PROVIDERS = {"xposedornot": xposedornot, "hibp": hibp, "dehashed": dehashed, "intelx": intelx}
EMAIL_ONLY = {"xposedornot": "XposedOrNot searches email addresses only",
              "hibp": "HIBP searches email addresses only"}


async def lookup(term: str, providers: list[str] | None = None, transport=None, catalog=None) -> list[dict]:
    """Run every configured provider (or the ones asked for) and collect results/errors.
    Breaches from XposedOrNot are enriched from HIBP's free catalogue when it's available."""
    enabled = [p for p, ok in configured().items() if ok and (not providers or p in providers)]
    out = []
    async with httpx.AsyncClient(timeout=20, transport=transport) as client:
        for p in enabled:
            if p in EMAIL_ONLY and not EMAIL_RE.match(term):
                out.append({"provider": p, "skipped": EMAIL_ONLY[p]})
                continue
            try:
                out.append(await PROVIDERS[p](term, client))
            except ProviderError as e:
                out.append({"provider": p, "error": str(e)})
            except httpx.HTTPError as e:
                out.append({"provider": p, "error": f"request failed ({type(e).__name__})"})

    xon = [r for r in out if r.get("provider") == "xposedornot" and r.get("breaches")]
    if xon:
        if catalog is None:
            from .hibp_catalog import load_catalog
            # transport is only set by tests (httpx.MockTransport works for sync clients too)
            catalog = await asyncio.to_thread(
                load_catalog, httpx.Client(timeout=20, transport=transport) if transport else None)
        if catalog:
            from .hibp_catalog import ATTRIBUTION, enrich
            for r in xon:
                r["breaches"] = [enrich(b, catalog, b.get("date")) for b in r["breaches"]]
                r["breaches"].sort(key=lambda b: str(b.get("date") or ""), reverse=True)
                r["attribution"] = ATTRIBUTION
    return out

