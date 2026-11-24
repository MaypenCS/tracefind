# Putting TraceFind online at tracefind.maypencs.net

This runs the **public version** of TraceFind on your spare Linux laptop:
- username sweep turned off
- history shown only to people who prove they own the email or domain
- rate limits on every search
- scans deleted after 90 days

The laptop never opens a port on your router. **Cloudflare Tunnel** makes an outgoing connection
to Cloudflare, and visitors reach TraceFind through Cloudflare, so your home IP address stays hidden.

```
visitor → Cloudflare (HTTPS) → tunnel → laptop 127.0.0.1:8000 → TraceFind
```

Commands assume Debian or Ubuntu (or Mint). Run them as your normal user with `sudo`.

---

## 0. Prepare the laptop

- **Network:** put the laptop on your router's **guest network**, or any network that can't reach the
  family media server. If TraceFind were ever compromised, it then can't touch anything else at home.
- **Updates on autopilot:**
  ```bash
  sudo apt update && sudo apt full-upgrade -y
  sudo apt install -y unattended-upgrades && sudo dpkg-reconfigure -plow unattended-upgrades
  ```
- **Firewall:** nothing needs to come in, because the tunnel connects outward.
  ```bash
  sudo apt install -y ufw && sudo ufw default deny incoming && sudo ufw default allow outgoing && sudo ufw enable
  ```
- **Keep it awake with the lid closed:** in `/etc/systemd/logind.conf` set `HandleLidSwitch=ignore` and
  `HandleLidSwitchExternalPower=ignore`, then `sudo systemctl restart systemd-logind`. Also turn off
  automatic sleep in the power settings, and keep it plugged in.

## 1. Install TraceFind

```bash
sudo apt install -y python3 python3-venv git
sudo useradd --system --home /opt/tracefind --shell /usr/sbin/nologin tracefind
sudo git clone https://github.com/MaypenCS/tracefind.git /opt/tracefind
cd /opt/tracefind/backend
sudo python3 -m venv .venv
sudo .venv/bin/pip install -r requirements.txt
sudo chown -R root:root /opt/tracefind        # code is read-only to the service
```
(If you haven't pushed v1.2 to GitHub yet, push from your PC first, or copy the project folder over.)

Run the tests once: `sudo .venv/bin/pip install pytest && sudo .venv/bin/python -m pytest -q`
(the 100 tests need no network).

## 2. Settings

```bash
sudo mkdir -p /etc/tracefind
sudo cp /opt/tracefind/deploy/tracefind.env.example /etc/tracefind/tracefind.env
sudo chmod 600 /etc/tracefind/tracefind.env
python3 -c "import secrets; print(secrets.token_hex(32))"   # copy this
sudo nano /etc/tracefind/tracefind.env
```
Fill in `TRACEFIND_SECRET` (the value you just printed) and `SMTP_PASSWORD`. Everything else is
already set for maypencs.net.

## 3. Start the service

```bash
sudo cp /opt/tracefind/deploy/tracefind.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tracefind
systemctl status tracefind                      # should say "active (running)"
curl -s http://127.0.0.1:8000/api/config        # should include "public": true
journalctl -u tracefind -f                      # live logs (Ctrl+C to exit)
```

## 4. Move maypencs.net's DNS to Cloudflare (free plan)

Tunnels with your own hostname need the domain's DNS at Cloudflare. **Email and the landing page
keep working**, as long as every record is copied over first.

1. Create a free account at cloudflare.com and **Add a domain**: `maypencs.net`.
2. Cloudflare scans your current IONOS records. **Before continuing, open IONOS → Domains →
   maypencs.net → DNS side by side, and check that every record is in Cloudflare:**
   - the website records (`@` and `www` A/AAAA pointing at IONOS webspace)
   - **MX** records (IONOS mail servers)
   - the **SPF** TXT record (`v=spf1 include:_spf-us.ionos.com ~all`)
   - **DKIM** records (`s1-ionos._domainkey`, `s2-ionos._domainkey`)
   - `_dmarc` TXT, plus any `_tracefind` TXT ownership record
   - **Mail records must be "DNS only" (grey cloud)**, never proxied.
3. Remove the old IONOS forwarding on `tracefind.maypencs.net`; the tunnel replaces it.
4. In IONOS, change maypencs.net's **name servers** to the two Cloudflare gives you.
   It can take a few hours. Cloudflare emails you when the domain is active.
5. Afterwards: send yourself an email, check maypencs.net loads, and run TraceFind's Domain tab
   on maypencs.net. SPF, DKIM and MX should still be green.

## 5. Create the tunnel

In Cloudflare: **Zero Trust → Networks → Tunnels → Create a tunnel** (type *Cloudflared*), name it
`tracefind`. Choose Debian/Ubuntu, and Cloudflare shows install commands with your token. Run them
on the laptop. They install `cloudflared` as a service that starts on boot.

Then add a **Public hostname**:

| Field | Value |
|---|---|
| Subdomain | `tracefind` |
| Domain | `maypencs.net` |
| Service type | `HTTP` |
| URL | `127.0.0.1:8000` |

Save, then open **https://tracefind.maypencs.net** 🎉

## 6. Check it's locked down

- There's **no Username tab**, and History asks for *your* email or domain.
- `https://tracefind.maypencs.net/docs` gives "Not found".
- Do 11 breach checks in a row: the 11th says "Too many requests".
- Send yourself a verification code. It should arrive from admin@maypencs.net.
- Scan `tracefind.maypencs.net` in the Domain tab. HTTPS and security headers should pass.

## Updating later

```bash
cd /opt/tracefind && sudo git pull
sudo backend/.venv/bin/pip install -r backend/requirements.txt
sudo systemctl restart tracefind
```

## Good to know

- **Free breach source limits:** XposedOrNot's free tier allows about 100 lookups a day from one IP,
  and every visitor shares the laptop's IP. When that runs out, visitors see a "try again later"
  message. XposedOrNot's free API is meant for personal, low-volume use, so for real traffic, add an
  `HIBP_API_KEY` or move to XposedOrNot's paid plan.
- **Privacy:** visitors' emails and results are stored for 90 days. Add a short privacy notice
  (what's stored, for how long, and how to ask for deletion) before you promote the site.
- **If the laptop is off, the site is down.** Cloudflare shows an error page. When traffic grows,
  the same setup moves to a small cloud server: just install `cloudflared` there.
