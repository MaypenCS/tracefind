"""tracefind command line.

  python -m tracefind serve [--port 8000]      start the web app (opens your browser)
  python -m tracefind search <username>        search from the terminal
  python -m tracefind breach <email|username>  breach lookup from the terminal
  python -m tracefind update-sites             download the latest site list
"""
import argparse
import asyncio
import json
import os
import sys
import threading
import webbrowser
from pathlib import Path


def load_env():
    """Minimal .env loader (KEY=value lines) so API keys can live in a file."""
    for p in (Path.cwd() / ".env", Path(__file__).resolve().parents[1] / ".env"):
        if p.exists():
            for line in p.read_text(encoding="utf-8").splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
            break


def main():
    load_env()
    ap = argparse.ArgumentParser(prog="tracefind", description="OSINT username + breach lookup by Maypen Cybersecurity")
    sub = ap.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("serve"); s.add_argument("--port", type=int, default=8000)
    s.add_argument("--host", default="127.0.0.1"); s.add_argument("--no-browser", action="store_true")
    q = sub.add_parser("search"); q.add_argument("username"); q.add_argument("--nsfw", action="store_true")
    q.add_argument("--json", action="store_true", help="print results as JSON")
    b = sub.add_parser("breach"); b.add_argument("term")
    sub.add_parser("update-sites")
    a = ap.parse_args()

    if a.cmd == "serve":
        import uvicorn
        url = f"http://{a.host}:{a.port}"
        print(f"tracefind running at {url}  (Ctrl+C to stop)")
        if not a.no_browser:
            threading.Timer(1.2, lambda: webbrowser.open(url)).start()
        uvicorn.run("tracefind.app:app", host=a.host, port=a.port, log_level="warning")

    elif a.cmd == "search":
        from .probe import search, valid_username
        from .sites import load_sites
        if not valid_username(a.username):
            sys.exit("Usernames may contain letters, numbers, dot, underscore and dash (max 64).")
        sites = load_sites(a.nsfw)

        async def run():
            found = []
            async for r in search(a.username, sites):
                if r.status == "found":
                    found.append(r)
                    if not a.json:
                        print(f"  [+] {r.site:<24} {r.url}")
            if a.json:
                print(json.dumps([r.to_dict() for r in found], indent=2))
            else:
                print(f"\n{len(found)} profiles found across {len(sites)} sites. Verify each one by hand.")
        asyncio.run(run())

    elif a.cmd == "breach":
        from .breach import lookup
        print(json.dumps(asyncio.run(lookup(a.term)), indent=2))

    elif a.cmd == "update-sites":
        from .sites import update_sites
        print(f"Updated: {update_sites()} sites")


if __name__ == "__main__":
    main()
