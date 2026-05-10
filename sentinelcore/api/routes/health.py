from fastapi import APIRouter

router = APIRouter(tags=["health"])

# Bump this when a new desktop app build is released
APP_VERSION = "0.1.7"
DOWNLOAD_URL = "https://dashboard.redgaurd.com/files/RedGuard_Setup.exe"


@router.get("/health")
async def health():
    return {"status": "ok", "service": "sentinelcore-api"}


@router.get("/api/v1/version")
async def app_version():
    return {
        "version": APP_VERSION,
        "release_notes": "VPN now sets itself up automatically on first connect — no manual WireGuard install needed.",
        "download_url": DOWNLOAD_URL,
    }
