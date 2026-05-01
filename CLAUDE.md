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

| Tier       | Price     | Features |
|------------|-----------|----------|
| Free       | $0        | 5 scans/day, static analysis, hash lookup |
| Pro        | $9.99/mo  | Unlimited scans, ML scoring, custom YARA, endpoint agent, PDF reports |
| Enterprise | $99+/mo   | API access, MISP integration, network IOC enrichment, SLA |

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

## What Is Built (as of Session 3)

### Python Engine (`sentinelcore/engine/`)
- `static/hasher.py` — streaming MD5/SHA1/SHA256/ssdeep
- `static/pe_analyzer.py` — full PE: sections, entropy, imports, exports, overlay, signing, .NET
- `static/strings_extractor.py` — URLs, IPs, registry keys, suspicious APIs
- `static/yara_scanner.py` — loads .yar/.yara from signatures/yara/
- `static/analyzer.py` — orchestrator: type detect → hash → PE → YARA → strings → score
- `static/models.py` — ThreatLevel, FileType, PEInfo, SectionInfo, YaraMatch, StaticAnalysisResult
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
- `routes/auth.py` — POST /api/v1/auth/register, /login
- `routes/scan.py` — POST /api/v1/scan/file, GET /api/v1/scan/{id}, POST /api/v1/scan/hash, GET /scan/quota/me
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
- `/` — marketing landing page: hero, stats bar, 4-layer detection cards, features grid, how-it-works, pricing (Free/Pro/Enterprise), final CTA
- `/scan` — drag-drop file upload, live polling, scan result with threat badge, ML/VT/OTX pills, "View report" + "↓ PDF" buttons
- `/alerts` — real-time agent alerts (5s refresh), severity cards, detail drawer
- `/yara` — YARA rule editor with live syntax validation
- `/billing` — plan comparison + Stripe checkout + portal
- Nav: sticky with backdrop-blur, Login + "Get started free" CTA, footer

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
- [ ] **Buy domain** — sentinelcore.io or similar; swap nip.io config
- [ ] **Train real ML model** — MalwareBazaar + clean Windows binaries, run `make train-real`
- [ ] **Dedicated repo** — move sentinelcore/ out of bilybobthorton/bilybobthorton
- [x] **Auth UI** — /login, /register, /settings pages; JWT stored in localStorage; AuthNav component with avatar dropdown and logout

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

### Growth / business
- [ ] **Email verification** — verify email on register (Resend already wired in)
- [ ] **Scan history UI** — /history page showing past scans per user
- [ ] **Usage dashboard** — show quota used, scans over time, threat breakdown
- [ ] **MISP integration UI** — Enterprise dashboard page to configure + test MISP push
- [ ] **Webhook notifications** — POST scan results to user-configured URLs (Slack, Teams, SIEM)
- [ ] **API docs page** — public-facing API reference for Enterprise customers
- [ ] **Windows agent MSI** — WiX-based MSI alongside NSIS for enterprise MDM deployment

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
