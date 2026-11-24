"""Domain ownership verification for active checks.

The owner proves control by publishing a token in DNS or on the website:
  DNS:  TXT record at _tracefind.<domain>   value: tracefind-verify=<token>
  File: https://<domain>/.well-known/tracefind-verify.txt   containing the token
The token is an HMAC of the domain with this install's secret, so it's stable for the
domain and can't be guessed by someone else.
"""
from __future__ import annotations

import hashlib
import hmac

import httpx

from .email_auth import Resolver


def token_for(domain: str, secret: bytes) -> str:
    return hmac.new(secret, f"domain-own:{domain}".encode(), hashlib.sha256).hexdigest()[:32]


def instructions(domain: str, secret: bytes) -> dict:
    tok = token_for(domain, secret)
    return {
        "domain": domain,
        "token": tok,
        "dns": {"type": "TXT", "name": f"_tracefind.{domain}", "value": f"tracefind-verify={tok}"},
        "file": {"url": f"https://{domain}/.well-known/tracefind-verify.txt", "content": tok},
    }


def check_ownership(domain: str, secret: bytes, resolver: Resolver, client: httpx.Client | None) -> str | None:
    """Returns 'dns' or 'file' when verified, else None. Checked live every time."""
    tok = token_for(domain, secret)
    from .email_auth import DnsUnavailable
    for name in (f"_tracefind.{domain}", domain):
        try:
            if any(t.strip() == f"tracefind-verify={tok}" for t in resolver.txt(name)):
                return "dns"
        except DnsUnavailable:
            continue
    if client is not None:
        try:
            r = client.get(f"https://{domain}/.well-known/tracefind-verify.txt", follow_redirects=False)
            if r.status_code == 200 and r.text[:200].strip() == tok:
                return "file"
        except httpx.HTTPError:
            pass
    return None
