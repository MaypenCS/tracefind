"""Demo scan with fictional data — safe for screenshots and Facebook posts."""
from datetime import date, datetime, timezone

from .models import Breach, PasteHit, ScanResult, SourceStatus, UsernameHit


def demo_scan() -> ScanResult:
    u = "jordan.sample"
    hits = [
        ("Instagram", "social"), ("TikTok", "social"), ("Reddit", "social"),
        ("Pinterest", "social"), ("LinkedIn", "professional"), ("GitHub", "developer"),
        ("Steam", "gaming"), ("Twitch", "gaming"), ("Chess.com", "gaming"),
        ("SoundCloud", "creative"), ("YouTube", "creative"), ("Kijiji", "marketplace"),
        ("Badoo", "dating"), ("Coinbase", "crypto"), ("OldGamerForum", "forum"),
    ]
    return ScanResult(
        target="jordan.sample@example.com",
        target_type="email",
        scanned_at=datetime(2026, 11, 23, 15, 0, tzinfo=timezone.utc),
        sites_checked=460,
        is_demo=True,
        username_hits=[UsernameHit(platform=p, category=c,
                                   url=f"https://{p.lower().replace(' ', '')}.example/{u}")
                       for p, c in hits],
        breaches=[
            Breach(name="ExampleFitness", breach_date=date(2024, 3, 2),
                   data_classes=["Email addresses", "Passwords", "Usernames"]),
            Breach(name="SampleShop", source="Dehashed", breach_date=date(2022, 8, 14),
                   data_classes=["Email addresses", "Names", "Phone numbers", "Physical addresses"]),
            Breach(name="DemoNewsletter", breach_date=date(2019, 1, 20),
                   data_classes=["Email addresses", "Names"]),
        ],
        pastes=[PasteHit(title="combo_list_2025_part3.txt", found_date=date(2025, 6, 9), bucket="leaks")],
        sources=[
            SourceStatus(name="Username sweep", status="ok"),
            SourceStatus(name="HaveIBeenPwned", status="ok"),
            SourceStatus(name="Dehashed", status="ok"),
            SourceStatus(name="IntelX", status="rate_limited", detail="partial results only"),
        ],
    )


def demo_previous() -> ScanResult:
    """An earlier fictional scan, so the demo report shows 'Changes since'."""
    cur = demo_scan()
    keep = {"Instagram", "TikTok", "Reddit", "Pinterest", "LinkedIn", "GitHub", "Steam",
            "Twitch", "SoundCloud", "YouTube", "Kijiji", "Tumblr"}
    hits = [h for h in cur.username_hits if h.platform in keep]
    hits.append(UsernameHit(platform="Tumblr", category="social", url="https://tumblr.example/jordan.sample"))
    return cur.model_copy(update={
        "scanned_at": datetime(2026, 10, 23, 15, 0, tzinfo=timezone.utc),
        "username_hits": hits,
        "breaches": [b for b in cur.breaches if b.name != "ExampleFitness"],
        "pastes": [],
    })
