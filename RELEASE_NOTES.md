# tracefind v1.3.0

## New
- **Public mode** (`TRACEFIND_PUBLIC=1`) for running TraceFind as a website: username sweep off,
  history only for proven owners, per-visitor rate limits, security headers, API docs hidden,
  optional automatic deletion of old scans (`TRACEFIND_HISTORY_DAYS`).
- **Deployment kit** in `deploy/`: hardened systemd service, public settings template, and a
  step-by-step guide for Cloudflare Tunnel (no open router ports).

# tracefind v1.2.0

## New
- **Free breach checks, no API key:** XposedOrNot is now built in and on by default.
- **HIBP breach catalogue (free):** exact dates and data types for every breach found, one name per
  breach across providers, and a new Domain-tab check for breaches of the domain's own service.
- **Check a password:** Pwned Passwords with k-anonymity. The password never leaves your browser.

# tracefind v1.1.0

## New
- **Exposure Report** after every username sweep and breach check: high/medium/low findings,
  why each one matters, what to do, a remediation checklist, and HTML/PDF download.
- **Email ownership verification:** a 6-digit code to the inbox before email breach results are shown.
- **Scan history** with "Changes since last scan": new accounts, new breaches, newly reported data.
- **Domain tab:** email-spoofing protection (SPF/DKIM/DMARC/MX), HTTPS and certificate, security headers,
  subdomains from certificate logs. Exposed-file and admin-page checks for verified owners only.
- **Demo report** with fictional data for screenshots.
- Branding through `.env` (`TRACEFIND_BRAND_NAME`, `TRACEFIND_BRAND_DOMAIN`).

# tracefind v1.0.0

First public release from Maypen Cybersecurity.

## What it does
- **Username sweep:** checks a username across 460+ sites at once and streams each hit live
  (19 adult sites are available behind an opt-in toggle).
- **Breach checks:** Have I Been Pwned, Dehashed and Intelligence X, each enabled by adding its API key to `.env`.
  tracefind shows which breaches and which kinds of data leaked. It never displays leaked passwords or hashes.
- **Exports:** found profiles as JSON or CSV.
- **CLI mode:** `python -m tracefind search <username>`, plus `breach` and `update-sites`.
- **One-click launchers:** `run.bat` (Windows) and `run.sh` (Linux/macOS) set everything up on first run.

## Notes
- Every hit is a lead, not proof. Verify profiles by hand.
- Sites change their pages; run `python -m tracefind update-sites` monthly for fresh detection rules.
- Site rules come from the Sherlock Project (MIT).

For authorized investigations and checking your own exposure only.
