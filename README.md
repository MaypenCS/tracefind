# tracefind

**OSINT username + breach lookup by [Maypen Cybersecurity](https://maypen.ca) · @MaypenCS**

Type a username and tracefind checks 460+ sites at once, streaming each hit to the screen as it lands.
Type an email and it checks the breach databases you have keys for. It reports *which* breaches and
*which kinds* of data leaked, never the leaked passwords or hashes themselves.

> Built for authorized investigations and checking your own exposure. Respect each site's terms and your local law.

## Quick start

**Windows:** double-click `run.bat`
**Linux / macOS:** `./run.sh`

The first run sets up a Python virtual environment and installs dependencies (needs Python 3.10+).
Your browser then opens at http://127.0.0.1:8000.

## Breach lookups (optional)
Copy `.env.example` to `.env`, add the keys you have, then restart tracefind:

| Provider | Searches | Key |
|---|---|---|
| Have I Been Pwned | email | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| Dehashed | email or username | paid API add-on at dehashed.com |
| Intelligence X | email, username, domain | [intelx.io](https://intelx.io/account?tab=developer) (free keys: `INTELX_BASE=https://free.intelx.io`) |

## Command line
```bash
cd backend
python -m tracefind search maypen          # username sweep in the terminal
python -m tracefind search maypen --json   # machine-readable hits
python -m tracefind breach me@example.com  # breach lookup
python -m tracefind update-sites           # pull the latest site list (sites change; run monthly)
python -m tracefind serve --port 9000      # web app on another port
```

## How detection works
Each site has a rule: the HTTP status code, a "user not found" message in the page, or a redirect.
Sites change their pages, so expect a few false hits and misses. That's why every hit is a lead to
verify by hand, and why `update-sites` exists.

## Develop
```bash
cd backend && pip install -r requirements.txt pytest && python -m pytest     # 8 tests, no network needed
cd frontend && npm install && npm run dev       # UI with hot reload on :5173 (API proxied to :8000)
npm run build                                   # rebuild the UI into backend/tracefind/ui
```
Stack: Python · FastAPI · httpx (async) · React · Vite. Results stream over server-sent events.

## Credits
Site detection rules come from the [Sherlock Project](https://github.com/sherlock-project/sherlock)
(MIT License, see `backend/tracefind/data/SHERLOCK-LICENSE.txt`). tracefind's own code is MIT licensed (`LICENSE`).
