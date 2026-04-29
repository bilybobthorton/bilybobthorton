# CLAUDE.md — Project Memory Palace

This file is loaded automatically at the start of every Claude Code session.
It contains everything needed to continue building without re-explaining context.
Update it after every major session.

---

## Who We Are

**Founder:** @bilybobthorton
- USMC Cybersecurity (separating ~April 2027)
- Bachelor's degree in relevant field
- 5 years hands-on cybersecurity experience
- Certs: (update this list as you earn/list them)
- Goal: Build a globally recognized endpoint security company

**Product:** SentinelCore (working name — can change)
- Malware detection + analysis platform
- Target: Consumers, SMBs, and eventually Enterprise
- Competitor benchmark: Malwarebytes, CrowdStrike Falcon, Carbon Black

---

## Business Context

- We are building this as a real, revenue-generating business
- Stack must be production-quality from day one — no toy code
- Development timeline: ~12 months while still in USMC, then full-time
- MVP goal: Working static analysis engine + web dashboard + free/pro tier SaaS
- Long-term: Real-time agent, behavioral sandbox, threat intel feeds, ML detection

---

## Project: SentinelCore

**Repo:** bilybobthorton/bilybobthorton (this will move to a dedicated repo — track that)
**Dev branch:** claude/malware-detection-app-bRsUv
**Language stack:**
- Backend: Python 3.11+ with FastAPI
- Analysis engine: Python (pefile, yara-python, ssdeep, capstone)
- ML layer: scikit-learn + PyTorch (future)
- Frontend: React + Next.js + Tailwind CSS
- Database: PostgreSQL (primary), Redis (cache + job queue)
- Task queue: Celery + Redis
- Container: Docker + Docker Compose
- CI/CD: GitHub Actions
- Hosting target: Cloudflare Workers (edge API) + VPS for heavy analysis

---

## Architecture Overview

```
sentinelcore/
├── engine/              # Core detection engine (Python)
│   ├── static/          # Static analysis (PE, ELF, strings, entropy, YARA)
│   ├── dynamic/         # Behavioral analysis (sandbox hooks, process monitoring)
│   ├── ml/              # ML detection models + inference
│   ├── intel/           # Threat intelligence (VT API, OTX, MISP, hash DBs)
│   └── signatures/      # YARA rules, hash lists, IOC feeds
├── api/                 # FastAPI REST backend
│   ├── routes/          # Endpoints: scan, report, auth, admin
│   ├── models/          # SQLAlchemy ORM models
│   ├── tasks/           # Celery async tasks
│   └── auth/            # JWT + API key auth
├── agent/               # Lightweight endpoint agent (future)
│   ├── windows/         # Windows-specific hooks (minifilter driver — future)
│   └── linux/           # Linux inotify + fanotify hooks
├── dashboard/           # Next.js frontend
│   ├── app/             # App router pages
│   ├── components/      # UI components
│   └── lib/             # API client, utils
├── infra/               # Docker, nginx, deployment configs
│   ├── docker-compose.yml
│   └── nginx/
└── tests/               # Test suite
    ├── unit/
    └── integration/
```

---

## Detection Methodology

### Layer 1 — Static Analysis (Fast, no execution)
1. **Hash matching** — MD5/SHA1/SHA256 vs known-bad databases
2. **YARA rules** — Pattern matching against file bytes and strings
3. **PE analysis** — Import tables, section entropy, overlay data, resource anomalies
4. **String extraction** — URLs, IPs, registry keys, suspicious API calls
5. **Entropy analysis** — Packed/encrypted sections flagged for further analysis
6. **Fuzzy hashing** — ssdeep/tlsh for variant detection

### Layer 2 — ML Detection (Medium speed)
1. Feature extraction from static analysis output
2. Random forest classifier (baseline)
3. Deep learning on PE byte sequences (future — MalConv architecture)
4. Confidence scoring: 0.0–1.0

### Layer 3 — Dynamic/Behavioral (Slow, sandboxed)
1. Detonation in isolated VM/container
2. API call sequence monitoring
3. Network C2 detection
4. File system + registry change tracking
5. Memory injection detection

### Layer 4 — Threat Intelligence
1. VirusTotal API enrichment
2. AlienVault OTX pulse data
3. Internal hash reputation DB
4. MISP threat sharing (enterprise tier)

---

## API Design (v1)

```
POST /api/v1/scan/file          # Upload + scan a file
GET  /api/v1/scan/{scan_id}     # Get scan results
POST /api/v1/scan/hash          # Lookup hash reputation
GET  /api/v1/report/{scan_id}   # Full analysis report
POST /api/v1/auth/register      # User registration
POST /api/v1/auth/login         # JWT login
GET  /api/v1/admin/stats        # Platform stats (admin only)
```

---

## Business Model

| Tier       | Price       | Features |
|------------|-------------|----------|
| Free       | $0          | 5 scans/day, basic static analysis, hash lookup |
| Pro        | $9.99/mo    | Unlimited scans, ML scoring, YARA custom rules, reports |
| Enterprise | $99+/mo     | API access, behavioral sandbox, threat intel feeds, MISP, SLA |

---

## Session Log

### Session 1 — 2026-04-29
- Created CLAUDE.md (this file)
- Designed full system architecture
- Scaffolded project directory structure
- Created static analysis engine skeleton
- Created FastAPI backend skeleton
- Set up Docker Compose environment
- Next: Fill in static analysis engine logic (pefile parsing, YARA, entropy)

---

## Key Decisions Made

1. **Python for engine** — Largest security tooling ecosystem (pefile, yara-python, volatility, etc.)
2. **FastAPI over Flask/Django** — Async-first, auto OpenAPI docs, Pydantic validation
3. **Celery + Redis for async** — Heavy scanning jobs run in background workers
4. **Free tier as lead gen** — Build reputation, drive Pro conversions
5. **Static analysis first** — Ship fast, add ML + dynamic later
6. **Docker from day one** — Reproducible dev/prod environments

---

## How to Continue a Session

Start each session by saying:
> "Read CLAUDE.md and continue building SentinelCore. Here's what I want to do today: [your goal]"

Claude will load this file, understand full context, and pick up exactly where we left off.

---

## TODO / Roadmap

- [ ] Static analysis engine — pefile parsing (complete basic structure)
- [ ] YARA rule integration
- [ ] FastAPI endpoints — /scan/file working end-to-end
- [ ] PostgreSQL models + Alembic migrations
- [ ] Celery task queue for async scanning
- [ ] Basic React dashboard — upload file, show results
- [ ] Docker Compose full stack working locally
- [ ] VirusTotal API integration (free tier)
- [ ] User auth (JWT)
- [ ] Stripe integration for Pro tier billing
- [ ] GitHub Actions CI/CD pipeline
- [ ] Deploy MVP to VPS (DigitalOcean/Hetzner)
- [ ] ML baseline model (random forest on PE features)
- [ ] Windows endpoint agent (real-time file scanning)
- [ ] Landing page + marketing site
