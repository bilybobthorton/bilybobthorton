# CLAUDE.md — Project Memory Palace

Loaded automatically at the start of every Claude Code session.
Update after every major session.

---

## Who We Are

**Founder:** @bilybobthorton (Trevor King)
- USMC Cybersecurity (separating ~April 2027)
- Bachelor's degree in relevant field
- 5 years hands-on cybersecurity experience
- Goal: Build a globally recognized endpoint security company

**Product:** SentinelCore
- Malware detection + analysis platform
- Target: Consumers, SMBs, Enterprise
- Competitor benchmark: Malwarebytes, CrowdStrike Falcon, Carbon Black

---

## Business Model

### SentinelCore (Antivirus / Malware Detection)
| Tier       | Price     | Features |
|------------|-----------|----------|
| Free       | $0        | 5 scans/day, static analysis, hash lookup |
| Pro        | $9.99/mo  | Unlimited scans, ML scoring, custom YARA, endpoint agent, PDF reports |
| Enterprise | $99+/mo   | API access, MISP integration, network IOC enrichment, SLA |

### SentinelVPN
| Tier           | Price      | Features |
|----------------|------------|----------|
| VPN Free       | $0         | 1 location (US East), 10 GB/mo, 1 device |
| VPN Pro        | $4.99/mo   | All locations, unlimited bandwidth, 5 devices, kill switch |
| Security Bundle | $12.99/mo | VPN Pro + SentinelCore Pro — full-stack defense, 30% off vs separate |
| Enterprise     | Custom     | Dedicated nodes, SIEM/MISP, policy management, 99.9% SLA |

**Strategy:** Use SentinelCore (antivirus) as the acquisition channel, upsell to the Security Bundle. Same playbook as NordSecurity (Nord Threat Protection), Bitdefender Total Security, Norton 360. VPN market is 10× larger than standalone AV.

---

## Domain Name

**Status:** No domain purchased yet. Using 159.65.237.42.nip.io for now.
**Budget constraint:** Standard registration price only (~$10-15/yr). No aftermarket/broker purchases.
**Brand preference:** Trevor likes "bastioncore" style — strong, technical, security-focused compounds.

**Candidates to check on Namecheap (likely unregistered):**
- `rampartcore.com` — rampart (defensive wall) + core
- `wardcore.com` — ward (to guard/protect) + core
- `vigilcore.com` — vigil + core
- `bastionhq.com` — bastion + hq (bastioncore.com is taken)
- `cipherwall.com` — cipher + wall
- `hexshield.io` — hex + shield (.io is ~$35/yr, slightly pricier)
- `ironbulwark.com` — iron + bulwark (a fortification)
- `vaultcore.io` — vault + core

**How to check:** Go to namecheap.com, search each name. Standard .com reg is ~$10-12/yr first year.

---

## Repo & Branch

**Repo:** bilybobthorton/bilybobthorton (move to dedicated repo eventually)
**Dev branch:** claude/malware-detection-app-bRsUv
**Push token:** refresh from user each session (PAT with repo write scope)

---

## Stack

| Layer | Tech |
|---|---|
| Backend API | Python 3.11 + FastAPI + Uvicorn |
| Analysis engine | pefile, yara-python, ssdeep, capstone, lief |
| ML | scikit-learn RandomForest (train offline, load pkl) |
| Task queue | Celery + Redis |
| Database | PostgreSQL 16 (asyncpg async + psycopg2 sync for Celery) |
| Auth | JWT Bearer + X-API-Key header |
| Billing | Stripe (Checkout Sessions, webhooks, Customer Portal) |
| Email | Resend (REST via httpx, no extra package) |
| PDF generation | WeasyPrint 62.3 |
| Endpoint agent | Rust (tokio, notify, sysinfo, reqwest) |
| Dashboard | Next.js 14 + Tailwind CSS (App Router) |
| Container | Docker Compose (dev) + docker-compose.prod.yml (prod) |
| CI/CD | GitHub Actions (CI + SSH deploy on git tag) |
| VPS | DigitalOcean — IP 159.65.237.42 (Ubuntu 22.04) |

---

## What Is Built (as of Session 7)

### Python Engine (`sentinelcore/engine/`)
- `static/hasher.py` — streaming MD5/SHA1/SHA256/ssdeep
- `static/pe_analyzer.py` — full PE: sections, entropy, imports, exports, overlay, signing, .NET
- `static/strings_extractor.py` — URLs, IPs, registry keys, suspicious APIs
- `static/yara_scanner.py` — loads .yar/.yara from signatures/yara/
- `static/analyzer.py` — orchestrator: type detect → hash → PE → YARA → strings → heuristics → score
- `static/heuristics.py` — heuristic engine: 15+ API combination rules (injection, ransomware, keylogger, LSASS dump, DPAPI, persistence, anti-debug), structural PE rules (EP anomaly, high-entropy exec section, large overlay, tiny PE, anomalous section names), string rules (VM evasion, sandbox detection, credential harvesting, exfil endpoints, base64 blobs, hardcoded IPs); each hit tagged with MITRE ATT&CK technique + tactic
- `static/models.py` — ThreatLevel, FileType, PEInfo, SectionInfo, YaraMatch, StaticAnalysisResult, HeuristicHit, HeuristicResult
- `intel/virustotal.py` — VirusTotalClient: lookup_hash, lookup_url
- `intel/otx.py` — OTXClient: lookup_hash, lookup_ip, lookup_domain + top-level helper fns
- `intel/hash_db.py` — in-memory SHA256 blocklist from signatures/malware_hashes.txt
- `ml/features.py` — 31-feature vector extraction from StaticAnalysisResult
- `ml/model.py` — MalwareClassifier wrapper (RandomForest pkl, singleton loader)
- `ml/trainer.py` — offline trainer CLI; --synthetic flag for dev model
- `signatures/yara/suspicious_strings.yar` — 4 starter rules
- `signatures/malware_hashes.txt` — seed SHA256 blocklist (WannaCry, NotPetya, Emotet, etc.)

### FastAPI Backend (`sentinelcore/api/`)
- `config.py` — Pydantic Settings (DB, Redis, JWT, VT, OTX, Stripe, Resend, MISP, ML)
- `database.py` — async SQLAlchemy engine + session factory
- `main.py` — FastAPI app, CORS, all routers registered
- `models/scan.py` — User (with Stripe + tier fields), ScanJob
- `models/alert.py` — AgentAlert (from Rust agent)
- `models/yara_rule.py` — YaraRule (custom + built-in)
- `auth/jwt.py` — hash_password, verify_password, create_access_token, generate_api_key
- `auth/dependencies.py` — get_current_user (JWT Bearer → X-API-Key fallback)
- `routes/auth.py` — POST /api/v1/auth/register, /login; 14-day Pro trial set on register; returns tier + trial_ends_at
- `routes/scan.py` — POST /api/v1/scan/file, GET /api/v1/scan/{id} (now includes heuristics), GET /api/v1/scan/history (paginated), POST /api/v1/scan/hash, GET /scan/quota/me
- `routes/agent.py` — POST/GET /api/v1/agent/alert(s), GET /api/v1/agent/stats
- `routes/admin.py` — GET /api/v1/admin/stats (Enterprise only)
- `routes/billing.py` — POST checkout/portal/webhook, GET subscription
- `routes/yara_rules.py` — CRUD /api/v1/yara/rules + POST /validate
- `routes/ml.py` — GET /api/v1/ml/status, POST /reload, POST /train/synthetic
- `routes/report.py` — GET /api/v1/report/{id} (HTML), GET /api/v1/report/{id}/pdf (WeasyPrint PDF download), GET /api/v1/report/{id}/json
- `routes/enterprise.py` — GET/POST /api/v1/enterprise/misp/export|push/{id} (Enterprise)
- `routes/health.py` — GET /health
- `services/email.py` — Resend email client; send_scan_alert() with dark-themed HTML template
- `services/misp.py` — build_misp_event(), push_to_misp(); full IOC mapping to MISP attributes
- `middleware/rate_limit.py` — Redis INCR counters, per-tier daily limits, HTTP 429
- `tasks/celery_app.py` — Celery instance
- `tasks/scan_tasks.py` — 5-layer pipeline: hash DB → ML → VT hash → OTX hash → OTX IP → URL/domain reputation → email alert

### Detection Pipeline (scan_tasks.py) — 5 layers

1. **Local hash DB** — instant SHA256 blocklist lookup; match = MALICIOUS, confidence 1.0
2. **ML scoring** — 31-feature RandomForest; escalates CLEAN→SUSPICIOUS if model flags it
3. **VirusTotal hash** — ≥3 engines = MALICIOUS; auto-adds confirmed hashes to local DB
4. **OTX hash + IP enrichment** — pulse count on file hash; checks up to 5 extracted public IPs
5. **URL/domain reputation** — OTX domain lookup + VT URL scan on strings extracted from file

Email alert fires after scan if MALICIOUS or SUSPICIOUS and user has RESEND_API_KEY set.

### Alembic Migrations
- 0001: users + scan_jobs tables
- 0002: agent_alerts table
- 0003: yara_rules table + Stripe fields on users

### Rust Endpoint Agent (`sentinelcore/agent/`)
- `src/main.rs` — CLI (run/quarantine/status), tokio task spawner, fan-out alert channel
- `src/alert.rs` — Alert struct, Severity, AlertKind enums (incl. C2ConnectionDetected, SuspiciousNetworkActivity)
- `src/config.rs` — AgentConfig with platform defaults
- `src/scanner/hash.rs` — streaming SHA256 + MD5 (64KB chunks)
- `src/monitor/filesystem.rs` — notify watcher: high-risk extensions, suspicious filenames, temp drops
- `src/monitor/process.rs` — sysinfo: LOLBAS detection, suspicious parent-child chains
- `src/monitor/fim.rs` — baseline critical system files, alert on hash drift every 30s
- `src/monitor/network.rs` — polls TCP connections every 30s; known-bad IPs, C2 ports (4444/1337/31337/50050), exfiltration detection (50+ connections/process); Linux: parses /proc/net/tcp natively; macOS/Windows: ss/netstat fallback
- `src/monitor/lolbas.rs` — ~35 LOLBin entries with MITRE ATT&CK mappings
- `src/quarantine.rs` — XOR-obfuscated vault, JSON metadata, restore support
- `src/reporter.rs` — HTTP POST to API with 4-attempt exponential backoff
- `install/windows/sentinel.nsi` — NSIS installer (GUI, service registration, Start Menu)
- `install/windows/install-service.ps1` — PowerShell service installer for CI/enterprise
- `install/windows/build-windows.sh` — cross-compile helper (cross/Docker or mingw-w64)

### Next.js Dashboard (`sentinelcore/dashboard/`)
- `/` — marketing landing page: hero, stats bar, 4-layer detection cards, features grid, how-it-works, pricing (Free/Pro/Enterprise), VPN teaser banner, final CTA
- `/scan` — drag-drop file upload, live polling, scan result with threat badge, ML/VT/OTX/Heuristics pills, heuristic hit cards with MITRE tags, "View report" + "↓ PDF" buttons
- `/history` — paginated scan history table: filename, SHA256 snippet, threat badge, status pill, date; links to report
- `/alerts` — real-time agent alerts (5s refresh), severity cards, detail drawer
- `/yara` — YARA rule editor with live syntax validation
- `/billing` — plan comparison + Stripe checkout + portal
- `/vpn` — SentinelVPN landing page: hero, AV vs VPN coverage table, 6 feature cards, pricing (VPN Free/Pro/Bundle/Enterprise), CTA
- `/settings` — email, plan, trial banner (days left + upgrade CTA), API key copy, scan history link, sign out
- Nav: sticky with backdrop-blur, History + VPN links, AuthNav (avatar dropdown or Log in / Get started CTA), footer

### Infrastructure
- `infra/docker-compose.yml` — dev stack (api, worker, db, redis, nginx, flower, migrate)
- `infra/docker-compose.prod.yml` — production stack: no exposed db/redis ports, certbot renewal sidecar, Redis password auth
- `infra/Dockerfile.api` — python:3.11-slim + libmagic + libfuzzy + WeasyPrint system deps
- `infra/nginx/nginx.conf` — dev nginx with rate limiting
- `infra/nginx/nginx.prod.conf` — HTTPS, TLS 1.2/1.3, HSTS, ACME challenge, Stripe CSP
- `scripts/server-setup.sh` — one-shot Ubuntu 22.04 bootstrap (Docker, UFW, fail2ban, auto-generated secrets, systemd)
- `scripts/init-letsencrypt.sh` — first-time cert issuance via webroot
- `scripts/deploy.sh` — rolling deploy: pull → build → migrate → restart → health check loop
- `.github/workflows/ci.yml` — Python lint/migrate/test, Rust build/clippy, Next.js build
- `.github/workflows/deploy.yml` — CD on `git tag v*`: lint gate → SSH deploy

---

## Live VPS

- **IP:** 159.65.237.42 (DigitalOcean, NYC, Ubuntu 22.04)
- **Domain:** nip.io for now (`159.65.237.42.nip.io`) — buy real domain and swap
- **Status:** server-setup.sh ran successfully; init-letsencrypt.sh not yet run (user was away from Mac)
- **App dir:** `/opt/sentinelcore/sentinelcore/`
- **To finish deploy:** SSH in, `bash scripts/init-letsencrypt.sh 159.65.237.42.nip.io kingtrevor981@gmail.com`
- **To add email:** set `RESEND_API_KEY` + `APP_BASE_URL` in `.env`, restart worker

---

## Env Vars (`.env.example` — key ones)

```
DATABASE_URL=postgresql+asyncpg://sentinel:POSTGRES_PASSWORD@db:5432/sentinelcore
POSTGRES_PASSWORD=...
REDIS_URL=redis://:REDIS_PASSWORD@redis:6379/0
REDIS_PASSWORD=...
SECRET_KEY=...          # python3 -c "import secrets; print(secrets.token_hex(32))"
JWT_SECRET_KEY=...
DOMAIN=yourdomain.com
VIRUSTOTAL_API_KEY=     # virustotal.com free tier
OTX_API_KEY=            # otx.alienvault.com free tier
RESEND_API_KEY=re_...   # resend.com free tier (3k emails/mo)
EMAIL_FROM=SentinelCore <alerts@yourdomain.com>
APP_BASE_URL=https://yourdomain.com
STRIPE_SECRET_KEY=sk_live_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_ENTERPRISE=price_...
MISP_URL=https://your-misp.example.com   # Enterprise only
MISP_KEY=...
MISP_VERIFY_SSL=true
# VPN server (set after provisioning WireGuard on droplet)
VPN_SERVER_PUBLIC_KEY=...   # wg pubkey < /etc/wireguard/server_private.key
VPN_SERVER_ENDPOINT=vpn1.yourdomain.com:51820
VPN_DNS=1.1.1.1, 1.0.0.1
```

---

## Running the Dev Model (No Real Dataset)

```bash
cd sentinelcore
PYTHONPATH=. python3 -m engine.ml.trainer --synthetic
# → writes engine/ml/sentinel_rf.pkl
```

User confirmed this works on their Mac (Python 3.9 compat fixed with `from __future__ import annotations`).

---

## TODO / Next Up

### Near-term (pre-public launch)
- [ ] **Finish VPS deploy** — SSH in, run init-letsencrypt.sh, verify stack is live
- [ ] **Buy domain** — check Namecheap for cheap unregistered .com (see domain section below)
- [ ] **Train real ML model** — MalwareBazaar + clean Windows binaries, run `make train-real`
- [ ] **Dedicated repo** — move sentinelcore/ out of bilybobthorton/bilybobthorton
- [x] **Auth UI** — /login, /register, /settings pages; JWT stored in localStorage; AuthNav component with avatar dropdown and logout
- [x] **Email verification** — token on register, verify-email page, resend endpoint, settings status badge
- [x] **Webhooks** — CRUD + HMAC-signed delivery + test endpoint (Pro+), fires on scan completion
- [x] **VPN key API** — WireGuard keypair generation, device limits by tier, config download
- [x] **VPN device management UI** — /vpn/keys: add/revoke devices, download .conf, setup guide
- [x] **WireGuard server setup script** — scripts/setup-wireguard.sh: one-command droplet provisioning
- [x] **Linux agent installer** — agent/install/linux/install.sh: curl-pipe install, systemd service, auto-arch detection
- [x] **Usage dashboard** — /dashboard: scan counts, threat breakdown, 14-day spark chart, quota bar
- [x] **API docs page** — /api-docs: full endpoint reference, rate limits table, auth examples
- [x] **Scan history UI** — /history: paginated table with threat badges
- [x] **Webhook notifications** — CRUD + HMAC-signed delivery

### Detection capability roadmap
- [ ] **Memory analysis** — analyze process memory dumps for malware indicators:
  - Parse minidump / raw memory files (Volatility3 or custom)
  - Extract injected shellcode, unpacked PE images, suspicious strings from memory
  - Detect process hollowing, reflective DLL injection, heap spray patterns
  - Gate: Pro+ (file upload of .dmp) or Enterprise (live agent memory capture)

- [ ] **Behavioral analysis (sandbox)** — dynamic analysis by actually running the file:
  - Spin up isolated VM/container (QEMU/KVM or gVisor) per scan
  - Instrument with syscall tracing (strace on Linux, ETW/API Monitor on Windows)
  - Capture: file system changes, registry writes, network connections (pcap), spawned processes
  - Detonation report: timeline of events, IOC extraction from live traffic, DNS queries
  - Gate: Enterprise only (resource-heavy — needs dedicated sandbox infrastructure)
  - Implementation path: integrate with Cuckoo Sandbox or build custom detonation worker

- [ ] **macOS agent** — extend Rust agent for macOS (FSEvents, Endpoint Security Framework)
- [ ] **Windows agent signing** — code-sign the binary for SmartScreen/AV compatibility

### SentinelVPN (infrastructure)
- [x] **WireGuard server setup** — scripts/setup-wireguard.sh provisions a droplet in one command
- [x] **VPN key API** — generate WireGuard keypairs, store in DB, serve .conf download, device limits by tier
- [x] **VPN device management UI** — /vpn/keys frontend with CRUD, config preview, download, setup guide
- [ ] **Provision 2 VPN droplets** — buy DO droplets, run setup-wireguard.sh, set VPN_SERVER_* in .env
- [ ] **Threat-aware DNS resolver** — block known C2 domains at the DNS layer using SentinelCore's IOC feed
- [ ] **Bandwidth metering** — track per-user usage against tier limits (free = 10 GB/mo)
- [ ] **VPN kill switch** — iptables/nftables rule generation for Linux; per-platform instructions for Windows/macOS

### Growth / business
- [ ] **MISP integration UI** — Enterprise dashboard page to configure + test MISP push
- [ ] **Windows agent MSI** — WiX-based MSI alongside NSIS for enterprise MDM deployment
- [ ] **macOS agent** — extend Rust agent for macOS

---

## Session Log

### Session 1 — 2026-04-29
- Created CLAUDE.md, designed architecture, scaffolded structure
- Built static analysis engine (PE, YARA, strings, entropy)
- Built FastAPI backend (auth, scan, Docker Compose, Alembic)
- Built Next.js dashboard (upload, scan result, threat badge)
- Added VirusTotal integration

### Session 2 — 2026-04-29
- Built full Rust endpoint agent (filesystem/process/FIM monitors, LOLBAS DB, quarantine, reporter, CLI)
- Added agent alert ingestion API + alerts dashboard page
- Added local hash reputation DB + wired VT into scan pipeline
- Added GitHub Actions CI (Python + Rust + Next.js)
- Added Stripe billing (checkout, webhooks, portal, plan UI)
- Added YARA rule management (CRUD API + live editor UI)
- Built ML layer: feature extractor (31 features), RandomForest wrapper, offline trainer
- Added OTX threat intel integration
- Wired ML + OTX into scan pipeline (4-layer detection)
- Updated ScanResult UI to show ML score + VT + OTX intel pills

### Session 3 — 2026-05-01
- Fixed Python 3.9 compatibility (`from __future__ import annotations` across all files)
- Built full VPS deploy infrastructure: docker-compose.prod.yml, nginx.prod.conf (HTTPS/HSTS), server-setup.sh, init-letsencrypt.sh, deploy.sh
- Added GitHub Actions CD pipeline (SSH deploy on git tag)
- Provisioned DigitalOcean droplet (159.65.237.42); server-setup.sh completed; TLS cert pending
- Built marketing landing page at `/`; moved scan tool to `/scan`; sticky nav with auth CTAs
- Added email notifications via Resend (dark HTML template; fires on MALICIOUS/SUSPICIOUS)
- Extended scan pipeline: OTX IP enrichment + OTX domain + VT URL reputation (Layer 4b/4c)
- Built Rust agent network monitor (network.rs): C2 IP/port detection, exfiltration detection, /proc/net/tcp parser
- Built Windows agent installer: NSIS GUI installer + PowerShell service script + cross-compile helper
- Added PDF report download (WeasyPrint, white/print-optimised A4 layout; Pro+)
- Built MISP integration: build_misp_event(), push_to_misp(), enterprise routes with full IOC mapping
- Updated CLAUDE.md with memory analysis + behavioral analysis on roadmap

### Session 4 — 2026-05-01
- Built auth UI: /login, /register, /settings pages (Next.js App Router, client-side)
- Created lib/auth.ts: token storage in localStorage (sc_token/sc_email/sc_apikey), apiLogin/apiRegister helpers
- Created AuthNav component: avatar initial + dropdown (Dashboard/Billing/Settings/Sign out); unauthenticated state shows Log in + Get started CTA
- Settings page: shows email, API key with copy button, sign out
- Wired auth headers into all api.ts fetch calls (submitScan, pollScan, lookupHash, fetchAlerts, fetchAgentStats)

### Session 5 — 2026-05-01
- Built heuristic analysis engine (`engine/static/heuristics.py`): 15+ API combination rules (process injection T1055, process hollowing T1055.012, DLL injection T1055.001, keylogger T1056.001, ransomware T1486, downloader T1105, LSASS dump T1003.001, DPAPI T1555, anti-debug T1622, registry persistence T1547.001, token escalation T1134, memory alloc+exec T1620); structural PE rules (EP outside .text, high-entropy exec sections, large overlay, tiny PE, anomalous section names); string rules (VM/sandbox evasion T1497.001, credential harvesting T1555, exfil endpoints T1567, base64 blobs T1027, hardcoded IPs T1071)
- Added HeuristicHit + HeuristicResult dataclasses to models.py; StaticAnalysisResult now carries `heuristics` field
- Wired heuristics into analyzer.py (runs after base scoring, escalates threat level)
- Surfaced heuristics in scan_tasks.py result_dict as top-level key with full hit details
- Updated ScanResult.tsx: heuristic pill in intel row + expandable hit cards with MITRE technique badges, severity-colored borders, evidence snippets
- Built SentinelVPN product (`/vpn` page): hero, AV-vs-VPN coverage comparison table, 6 feature cards (WireGuard, zero-log, threat-aware routing, kill switch, DNS leak protection, global servers), 4-tier pricing (Free/Pro/Bundle/Enterprise), CTA
- Added VPN teaser banner to main landing page (indigo accent, bundle pitch, links to /vpn)
- Added VPN nav link (indigo color, distinct from main nav items)

### Session 8 — 2026-05-02
- VPN device management UI: /vpn/keys page with add/revoke/download, setup guide, device limit bar
- WireGuard server provisioning script: scripts/setup-wireguard.sh (one-command droplet setup, keypair gen, NAT, UFW, systemd)
- Linux agent installer: agent/install/linux/install.sh (curl-pipe install, auto-arch detection, systemd service, hardened unit file, uninstall flag)
- .env.example: added VPN_SERVER_PUBLIC_KEY, VPN_SERVER_ENDPOINT, VPN_DNS vars
- VPN page (/vpn): "Manage my devices" CTA when authenticated vs "Start free" for guests; added Wifi icon
- Nav: added "Devices" link next to "VPN" for quick access to /vpn/keys
- CLAUDE.md: cleaned up stale TODOs, updated session log

### Session 7 — 2026-05-02
- Fixed Rust clippy -D warnings (sysinfo 0.30.x API, unreachable cfg patterns, dead_code, while-let style, format string)
- Email verification: `is_verified` + `verification_token` on User (migration 0005), verify-email route, resend endpoint, Resend email template, /verify-email frontend page, Settings badge + resend button
- Webhooks: migration 0006, `webhook_endpoints` table, CRUD API + HMAC-signed delivery + test endpoint (Pro+ only), fires from scan_tasks.py on completion, /webhooks frontend page with secret copy + test button
- VPN key API: migration 0007, `vpn_keys` table, X25519 keypair generation, preshared key, device limits by tier (Free 1 / Pro 5 / Enterprise 25), WireGuard .conf download, /api/v1/vpn/* routes
- Usage dashboard: /dashboard page with scan counts (today/week/month), daily quota bar, threat breakdown bars, 14-day SVG spark chart, quick links
- API docs: /api-docs static page with full endpoint reference, method color chips, rate limits table, auth examples, webhook payload schema
- New /api/v1/stats/me endpoint with 14-day daily counts grouped by day (PostgreSQL date_trunc)
- Config: VPN_SERVER_PUBLIC_KEY, VPN_SERVER_ENDPOINT, VPN_DNS env vars; CORS allows app_base_url
- Dashboard nav: added Dashboard link; Settings page: email status badge, links to dashboard/webhooks

### Session 6 — 2026-05-01
- Fixed all CI failures: E402 docstring ordering in 3 Python files, moved asynccontextmanager import in database.py, auto-fixed 14 F401 unused imports, fixed 3 E712 SQLAlchemy `== True` → `.is_(True)`; ran `cargo fmt` across all Rust source files
- Added dashboard .gitignore + committed package-lock.json for reproducible npm ci in CI
- Added 14-day Pro trial: `trial_ends_at` column on User (migration 0004), set on register, rate limiter treats active-trial users as Pro tier
- auth.py now returns `tier` + `trial_ends_at` in TokenResponse; stored in localStorage (sc_tier, sc_trial_ends)
- Added `GET /api/v1/scan/history` endpoint (paginated, auth-required)
- ScanResult API response now includes `heuristics` key (was in result_json, not surfaced)
- Built `/history` page: scan table with threat badges, status pills, date, SHA256 snippet, links to reports
- Settings page: trial banner with days-remaining + upgrade CTA, plan display, history link
- Added History to nav
