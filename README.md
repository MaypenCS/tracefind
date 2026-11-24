# tracefind

**OSINT username + breach lookup by [Maypen Cybersecurity](https://maypen.ca) · @MaypenCS**

Type a username and tracefind checks 460+ sites at once, streaming each hit to the screen as it lands.
Type an email and it checks breach databases: XposedOrNot works out of the box with no key, and
Have I Been Pwned, Dehashed and Intelligence X turn on when you add their keys. It reports *which* breaches and
*which kinds* of data leaked, never the leaked passwords or hashes themselves.

> Built for authorized investigations and checking your own exposure. Respect each site's terms and your local law.

## Quick start

**Windows:** double-click `run.bat`
**Linux / macOS:** `./run.sh`

The first run sets up a Python virtual environment and installs dependencies (needs Python 3.10+).
Your browser then opens at http://127.0.0.1:8000.

## Breach lookups
**Free, no setup:**
- **XposedOrNot** checks email addresses. Its free tier is for personal / low-volume use
  (25 lookups/hour, 100/day per IP); commercial use needs their paid xonAPI+ plan.
- **Have I Been Pwned breach catalogue** fills in exact breach dates and data types, and powers the
  Domain tab's "has this service been breached?" check. Credited as CC BY 4.0, as its terms require.
- **Pwned Passwords** powers *Check a password* on the Breach tab. The password is hashed in your
  browser and only the first 5 hash characters are sent (k-anonymity).

**Optional paid providers:** copy `.env.example` to `.env`, add the keys you have, then restart tracefind:

| Provider | Searches | Key |
|---|---|---|
| Have I Been Pwned | email | [haveibeenpwned.com/API/Key](https://haveibeenpwned.com/API/Key) |
| Dehashed | email or username | paid API add-on at dehashed.com |
| Intelligence X | email, username, domain | [intelx.io](https://intelx.io/account?tab=developer) (free keys: `INTELX_BASE=https://free.intelx.io`) |

## Exposure reports, history and domain checks

- **Exposure Report:** every finished username sweep or breach check produces a report with
  high/medium/low findings, plain-English fixes and a checklist. Download it as HTML or PDF.
- **Email verification:** breach results for an email are only shown after a 6-digit code sent to
  that inbox is entered. Codes print in the tracefind window until you set up SMTP in `.env`.
- **History:** username sweeps, email breach checks and domain scans are saved on this PC
  (`backend/tracefind_history.db`). Re-scanning shows what changed: new accounts, new breaches,
  fixed or new domain problems.
- **Domain tab:** SPF, DKIM, DMARC, MX, HTTPS certificate, security headers and public subdomains for
  any domain. Exposed-file and admin-page checks only run after you prove you own the domain
  (DNS TXT record or a file on the site).
- **Demo report:** History → *Demo report* shows a full report with fictional data, handy for screenshots.

PDF export uses WeasyPrint (`pip install weasyprint`). On Windows it also needs the
[GTK3 runtime](https://doc.courtbouillon.org/weasyprint/stable/first_steps.html#windows). Without it,
use *Download HTML* and print to PDF from the browser.

## Running it as a public website
See [`deploy/DEPLOY.md`](deploy/DEPLOY.md). Public mode turns off the username sweep, keeps history
private to proven owners, and rate-limits every visitor. The guide puts it behind Cloudflare Tunnel,
so no router ports are opened.

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
cd backend && pip install -r requirements.txt pytest && python -m pytest     # 100 tests, no network needed
cd frontend && npm install && npm run dev       # UI with hot reload on :5173 (API proxied to :8000)
npm run build                                   # rebuild the UI into backend/tracefind/ui
```
Stack: Python · FastAPI · httpx (async) · React · Vite. Results stream over server-sent events.

## Credits
Site detection rules come from the [Sherlock Project](https://github.com/sherlock-project/sherlock)
(MIT License, see `backend/tracefind/data/SHERLOCK-LICENSE.txt`). tracefind's own code is MIT licensed (`LICENSE`).
