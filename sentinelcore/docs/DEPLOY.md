# SentinelCore — Full Deployment Guide

Step-by-step to take the stack from zero to HTTPS-live on DigitalOcean.

---

## Prerequisites

- DigitalOcean account with billing enabled
- A domain name (e.g. `rampartcore.com`) pointed to your droplet's IP
- GitHub repo with the `claude/malware-detection-app-bRsUv` branch
- A Mac or Linux machine with `ssh` and `git` installed

---

## 1 — Provision the App Droplet

1. Create a **$12/mo droplet** on DigitalOcean:
   - Image: Ubuntu 22.04 LTS x64
   - Size: 2 vCPU / 2 GB RAM (Basic plan)
   - Region: New York or whichever is closest to you
   - Enable SSH key auth (add your public key)

2. Note the droplet's public IP — call it `APP_IP`.

3. Point your domain A record to `APP_IP`:
   ```
   A    @          APP_IP      TTL 300
   A    www        APP_IP      TTL 300
   ```
   Wait for DNS to propagate (~5 min for DigitalOcean managed DNS).

---

## 2 — Bootstrap the Server

SSH in and run the setup script:

```bash
ssh root@APP_IP

# Clone the repo
git clone https://github.com/bilybobthorton/bilybobthorton.git /opt/sentinelcore
cd /opt/sentinelcore/sentinelcore

# Run one-shot server setup (Docker, UFW, fail2ban, auto-generated secrets)
bash scripts/server-setup.sh
```

The script will:
- Install Docker + Docker Compose v2
- Configure UFW (ports 22/80/443 open)
- Install fail2ban
- Generate random `POSTGRES_PASSWORD`, `REDIS_PASSWORD`, `SECRET_KEY`, `JWT_SECRET_KEY`
- Write `/opt/sentinelcore/.env` with those values
- Print the generated secrets — **copy them somewhere safe**

---

## 3 — Configure `.env`

Edit `/opt/sentinelcore/sentinelcore/.env` and fill in the missing values:

```bash
nano /opt/sentinelcore/sentinelcore/.env
```

Required fields to fill in:

```env
DOMAIN=redgaurd.com
APP_BASE_URL=https://redgaurd.com

# Threat intel (free keys — get them now if you haven't)
VIRUSTOTAL_API_KEY=   # https://virustotal.com → API key in profile
OTX_API_KEY=          # https://otx.alienvault.com → API key in profile

# Email (free tier = 3k emails/mo)
RESEND_API_KEY=re_... # https://resend.com/api-keys
EMAIL_FROM=SentinelCore <alerts@redgaurd.com>

# Stripe (use test keys for now, swap to live when ready to charge)
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...  # set up in step 5
STRIPE_PRICE_PRO=price_...       # create in Stripe dashboard
STRIPE_PRICE_ENTERPRISE=price_...
```

Leave `VPN_SERVER_PUBLIC_KEY` blank until step 6.

---

## 4 — Issue TLS Certificate

```bash
cd /opt/sentinelcore/sentinelcore
bash scripts/init-letsencrypt.sh redgaurd.com your@email.com
```

This uses webroot challenge — nginx must be reachable on port 80.
If it fails, verify DNS propagation: `dig +short redgaurd.com`.

---

## 5 — Start the Stack

```bash
cd /opt/sentinelcore/sentinelcore
make prod-build    # build images (first time ~5 min)
make prod-up       # start all services
make prod-migrate  # run Alembic migrations
```

Verify everything is up:
```bash
make prod-logs         # watch logs
curl https://redgaurd.com/health  # should return {"status":"ok"}
```

---

## 6 — Configure Stripe Webhook

1. Go to **dashboard.stripe.com → Developers → Webhooks**
2. Add endpoint: `https://redgaurd.com/api/v1/billing/webhook`
3. Select events: `checkout.session.completed`, `customer.subscription.updated`, `customer.subscription.deleted`
4. Copy the webhook signing secret (`whsec_...`)
5. Update `.env`: `STRIPE_WEBHOOK_SECRET=whsec_...`
6. Restart: `make prod-down && make prod-up`

---

## 7 — Train the ML Model (Optional but Recommended)

The synthetic model works but is fake. For real detection:

```bash
# On the server (or your Mac, then scp the .pkl file)
cd /opt/sentinelcore/sentinelcore
PYTHONPATH=. python3 -m engine.ml.trainer --synthetic   # quick fake model for now
```

For a real model, download MalwareBazaar samples and clean PE files, then:
```bash
PYTHONPATH=. python3 -m engine.ml.trainer \
  --malware-dir /data/malware \
  --clean-dir   /data/clean
```

---

## 8 — Provision VPN Droplet(s)

Buy 1–2 separate DigitalOcean droplets for WireGuard (keep VPN traffic off the main app server):

```bash
# On each VPN droplet (Ubuntu 22.04)
ssh root@VPN_IP
bash <(curl -fsSL https://raw.githubusercontent.com/bilybobthorton/bilybobthorton/claude/malware-detection-app-bRsUv/sentinelcore/scripts/setup-wireguard.sh)
```

It will print a `SERVER_PUBLIC_KEY`. Copy it back to the main server's `.env`:

```env
VPN_SERVER_PUBLIC_KEY=<paste here>
VPN_SERVER_ENDPOINT=VPN_IP:51820
VPN_DNS=1.1.1.1, 1.0.0.1
```

Then restart the API: `docker compose -f infra/docker-compose.prod.yml restart api`

---

## 9 — Deploy Updates

Every time you push a new tag, GitHub Actions runs CI then SSH-deploys automatically:

```bash
git tag v0.1.0
git push origin v0.1.0
```

Or deploy manually:
```bash
ssh root@APP_IP
cd /opt/sentinelcore/sentinelcore && bash scripts/deploy.sh
```

---

## Quick Reference

| Task | Command |
|------|---------|
| View logs | `make prod-logs` |
| Restart stack | `make prod-down && make prod-up` |
| Run migrations | `make prod-migrate` |
| Check API health | `curl https://redgaurd.com/health` |
| Add VPN peer manually | `wg-add-peer <pubkey> <psk> <ip>` (on VPN droplet) |
| View WireGuard peers | `wg show` (on VPN droplet) |

---

## Cost Estimate (monthly)

| Resource | Cost |
|----------|------|
| App droplet (2 vCPU / 2 GB) | ~$12/mo |
| VPN droplet × 1 (1 vCPU / 1 GB) | ~$6/mo |
| Domain (.com) | ~$1/mo |
| Resend email | Free (3k/mo) |
| VirusTotal / OTX | Free tiers |
| Stripe | 2.9% + 30¢ per transaction |
| **Total fixed** | **~$19/mo** |

---

## Checklist

- [ ] App droplet provisioned
- [ ] DNS A record pointing to droplet IP
- [ ] `server-setup.sh` completed
- [ ] `.env` filled in (VT key, OTX key, Resend key, Stripe keys, domain)
- [ ] TLS cert issued via `init-letsencrypt.sh`
- [ ] `make prod-build && make prod-up && make prod-migrate`
- [ ] `curl https://redgaurd.com/health` returns `{"status":"ok"}`
- [ ] Stripe webhook endpoint configured
- [ ] ML model trained (at minimum synthetic)
- [ ] VPN droplet provisioned + `setup-wireguard.sh` run
- [ ] `VPN_SERVER_PUBLIC_KEY` set in `.env`, API restarted
- [ ] First user registered and scanned a file end-to-end
