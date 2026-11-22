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
