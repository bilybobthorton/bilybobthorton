# CLAUDE.md — Project Memory Palace

Loaded automatically at the start of every Claude Code session.
Update after every major session.

---

## Who We Are

**Founder:** @bilybobthorton
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
| Pro        | $9.99/mo  | Unlimited scans, ML scoring, custom YARA, endpoint agent |
| Enterprise | $99+/mo   | API access, sandbox, threat intel, MISP, SLA |

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
| Endpoint agent | Rust (tokio, notify, sysinfo, reqwest) |
| Dashboard | Next.js 14 + Tailwind CSS (App Router) |
| Container | Docker Compose |
| CI/CD | GitHub Actions |

---

## What Is Built (as of Session 2)

### Python Engine (`sentinelcore/engine/`)
- `static/hasher.py` — streaming MD5/SHA1/SHA256/ssdeep
- `static/pe_analyzer.py` — full PE: sections, entropy, imports, exports, overlay, signing, .NET
- `static/strings_extractor.py` — URLs, IPs, registry keys, suspicious APIs
- `static/yara_scanner.py` — loads .yar/.yara from signatures/yara/
- `static/analyzer.py` — orchestrator: type detect → hash → PE → YARA → strings → score
- `static/models.py` — ThreatLevel, FileType, PEInfo, SectionInfo, YaraMatch, StaticAnalysisResult
- `intel/virustotal.py` — VirusTotalClient: lookup_hash, lookup_url
- `intel/otx.py` — OTXClient: lookup_hash, lookup_ip, lookup_domain (AlienVault OTX)
- `intel/hash_db.py` — in-memory SHA256 blocklist from signatures/malware_hashes.txt
- `ml/features.py` — 31-feature vector extraction from StaticAnalysisResult
- `ml/model.py` — MalwareClassifier wrapper (RandomForest pkl, singleton loader)
- `ml/trainer.py` — offline trainer CLI; --synthetic flag for dev model without real dataset
- `signatures/yara/suspicious_strings.yar` — 4 starter rules
- `signatures/malware_hashes.txt` — seed SHA256 blocklist (WannaCry, NotPetya, Emotet, etc.)

### FastAPI Backend (`sentinelcore/api/`)
- `config.py` — Pydantic Settings (DB, Redis, JWT, VT, OTX, Stripe, ML)
- `database.py` — async SQLAlchemy engine + session factory
- `main.py` — FastAPI app, CORS, all routers registered
- `models/scan.py` — User (with Stripe fields), ScanJob
- `models/alert.py` — AgentAlert (from Rust agent)
- `models/yara_rule.py` — YaraRule (custom + built-in)
- `auth/jwt.py` — hash_password, verify_password, create_access_token, generate_api_key
- `auth/dependencies.py` — get_current_user (JWT Bearer → X-API-Key fallback)
- `routes/auth.py` — POST /api/v1/auth/register, /login
- `routes/scan.py` — POST /api/v1/scan/file, GET /api/v1/scan/{id}, POST /api/v1/scan/hash
- `routes/agent.py` — POST/GET /api/v1/agent/alert(s), GET /api/v1/agent/stats
- `routes/admin.py` — GET /api/v1/admin/stats (Enterprise only)
- `routes/billing.py` — POST checkout/portal/webhook, GET subscription
- `routes/yara_rules.py` — CRUD /api/v1/yara/rules + POST /validate
- `routes/ml.py` — GET /api/v1/ml/status, POST /reload, POST /train/synthetic
- `routes/health.py` — GET /health
- `tasks/celery_app.py` — Celery instance
- `tasks/scan_tasks.py` — run_scan task: static → ML → VirusTotal → OTX → write DB

### Alembic Migrations
- 0001: users + scan_jobs tables
- 0002: agent_alerts table
- 0003: yara_rules table + Stripe fields on users

### Rust Endpoint Agent (`sentinelcore/agent/`)
- `src/main.rs` — CLI (run/quarantine/status), tokio task spawner, fan-out alert channel
- `src/alert.rs` — Alert struct, Severity, AlertKind enums, builder pattern
- `src/config.rs` — AgentConfig with platform defaults (watch_dirs, exclude_dirs, quarantine_dir)
- `src/scanner/hash.rs` — streaming SHA256 + MD5 (64KB chunks)
- `src/monitor/filesystem.rs` — notify watcher: high-risk extensions, suspicious filenames, temp drops
- `src/monitor/process.rs` — sysinfo: LOLBAS detection, suspicious parent-child chains
- `src/monitor/fim.rs` — baseline critical system files, alert on hash drift every 30s
- `src/monitor/lolbas.rs` — ~35 LOLBin entries with MITRE ATT&CK mappings
- `src/quarantine.rs` — XOR-obfuscated vault, JSON metadata, restore support
- `src/reporter.rs` — HTTP POST to API with 4-attempt exponential backoff

### Next.js Dashboard (`sentinelcore/dashboard/`)
- `/` — hero + drag-drop scan upload + live polling + results
- `/alerts` — real-time agent alerts (5s refresh), severity cards, detail drawer
- `/yara` — YARA rule editor with live syntax validation
- `/billing` — plan comparison + Stripe checkout + portal
- Nav: Scan | Alerts | YARA | Billing

### Infrastructure
- `infra/docker-compose.yml` — api, worker, db (postgres:16), redis:7, flower
- `infra/Dockerfile.api` — python:3.11-slim + libmagic + libfuzzy
- `.github/workflows/ci.yml` — Python lint/migrate/test, Rust build/clippy, Next.js build

---

## Env Vars (`.env.example`)

```
DATABASE_URL=postgresql+asyncpg://sentinel:sentinel@db:5432/sentinelcore
REDIS_URL=redis://redis:6379/0
SECRET_KEY=...
JWT_SECRET_KEY=...
VIRUSTOTAL_API_KEY=     # virustotal.com free tier
OTX_API_KEY=            # otx.alienvault.com free tier
STRIPE_SECRET_KEY=sk_test_...
STRIPE_WEBHOOK_SECRET=whsec_...
STRIPE_PRICE_PRO=price_...
STRIPE_PRICE_ENTERPRISE=price_...
```

---

## Detection Pipeline (scan_tasks.py)

1. **Static analysis** — PE/YARA/strings/entropy → score 0.0–1.0
2. **ML model** — 31-feature RandomForest → malice probability; boosts confidence if agrees with static
3. **VirusTotal** — hash lookup; ≥3 engines = MALICIOUS; auto-caches confirmed hashes
4. **OTX** — pulse count; ≥3 pulses + clean static = SUSPICIOUS

---

## Running the Dev Model (No Real Dataset)

```bash
cd sentinelcore
python -m engine.ml.trainer --synthetic
# → writes engine/ml/sentinel_rf.pkl
```

Then call `POST /api/v1/ml/train/synthetic` from the dashboard or curl for online generation.

---

## TODO / Next Up

- [ ] **Tests** — pytest suite for engine + API routes (high priority before public launch)
- [ ] **Landing page** — marketing site (Next.js or separate static site)
- [ ] **Deploy MVP** — Docker Compose on DigitalOcean/Hetzner VPS + nginx reverse proxy
- [ ] **Train real ML model** — grab MalwareBazaar + clean Windows binaries, run trainer.py
- [ ] **AlienVault OTX IP enrichment** — wire extracted IPs from scan through OTX
- [ ] **Windows agent packaging** — sign binary, NSIS/WiX installer, register as Windows service
- [ ] **Scan report PDF** — downloadable full analysis report (Pro+ feature)
- [ ] **Rate limiting** — enforce free tier 5 scans/day in API middleware
- [ ] **Email notifications** — alert user when scan finds malware (SendGrid/Resend)
- [ ] **MISP integration** — enterprise tier threat sharing
- [ ] **Dedicated repo** — move sentinelcore/ out of bilybobthorton/bilybobthorton

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
