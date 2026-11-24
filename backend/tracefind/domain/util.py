"""Domain input validation and SSRF guard."""
from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import urlsplit

_LABEL = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
BLOCKED_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".corp", ".test", ".invalid")


class DomainError(ValueError):
    pass


def normalize_domain(value: str) -> str:
    """Accepts 'example.ca', 'https://www.example.ca/path', 'EXAMPLE.CA.' -> 'example.ca' / 'www.example.ca'."""
    v = (value or "").strip().lower()
    if "://" in v:
        v = urlsplit(v).hostname or ""
    v = v.split("/")[0].split(":")[0].rstrip(".")
    try:
        v = v.encode("idna").decode("ascii")
    except UnicodeError:
        raise DomainError("That doesn't look like a valid domain.")
    try:
        ipaddress.ip_address(v)
        raise DomainError("Enter a domain name, not an IP address.")
    except ValueError:
        pass
    labels = v.split(".")
    if len(v) > 253 or len(labels) < 2 or not all(_LABEL.match(l) for l in labels) or labels[-1].isdigit():
        raise DomainError("That doesn't look like a valid domain.")
    if v == "localhost" or v.endswith(BLOCKED_SUFFIXES):
        raise DomainError("Internal or reserved domains can't be scanned.")
    return v


def is_public_ip(ip: str) -> bool:
    a = ipaddress.ip_address(ip)
    return a.is_global and not (a.is_private or a.is_loopback or a.is_link_local
                                or a.is_reserved or a.is_multicast)


def resolve_public(host: str) -> list[str]:
    """Resolve host and refuse if ANY address is non-public (prevents scanning your LAN)."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise DomainError(f"{host} does not resolve.") from e
    ips = sorted({i[4][0] for i in infos})
    bad = [ip for ip in ips if not is_public_ip(ip)]
    if bad:
        raise DomainError(f"{host} points to a private or reserved address ({bad[0]}); refusing to scan.")
    return ips
