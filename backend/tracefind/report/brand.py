"""Brand settings, set once through environment variables.

TRACEFIND_BRAND_DOMAIN   e.g. "yourbrand.ca": shown in report and email footers and the scanner's User-Agent.
                         Leave unset to show no domain anywhere.
TRACEFIND_BRAND_NAME     default "Maypen Cybersecurity"
"""
import os


def brand_name() -> str:
    return os.getenv("TRACEFIND_BRAND_NAME", "Maypen Cybersecurity")


def brand_domain() -> str:
    return os.getenv("TRACEFIND_BRAND_DOMAIN", "").strip().lower()


def brand_line() -> str:
    """'Maypen Cybersecurity · yourbrand.ca', or just the name when no domain is set."""
    d = brand_domain()
    return f"{brand_name()} · {d}" if d else brand_name()
