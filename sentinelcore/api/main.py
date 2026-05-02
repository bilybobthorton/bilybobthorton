from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api.config import get_settings
from api.routes import health, scan
from api.routes import auth, agent, admin, billing, yara_rules, ml, report, enterprise
from api.routes import webhooks, vpn, stats

settings = get_settings()

app = FastAPI(
    title="SentinelCore API",
    description="Malware detection and analysis platform",
    version="0.1.0",
    docs_url="/docs" if settings.app_env != "production" else None,
    redoc_url="/redoc" if settings.app_env != "production" else None,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        settings.app_base_url,
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(health.router)
app.include_router(auth.router, prefix="/api/v1")
app.include_router(scan.router, prefix="/api/v1")
app.include_router(agent.router)
app.include_router(admin.router)
app.include_router(billing.router)
app.include_router(yara_rules.router)
app.include_router(ml.router)
app.include_router(report.router)
app.include_router(enterprise.router)
app.include_router(webhooks.router)
app.include_router(vpn.router)
app.include_router(stats.router)
