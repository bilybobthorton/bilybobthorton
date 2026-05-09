from fastapi import APIRouter

router = APIRouter(tags=["health"])

# Bump this when a new desktop app build is released
APP_VERSION = "0.1.6"
DOWNLOAD_URL = "https://dashboard.redgaurd.com/files/RedGuard_Setup.exe"


@router.get("/health")
async def health():
    return {"status": "ok", "service": "sentinelcore-api"}


@router.get("/api/v1/version")
async def app_version():
    return {
        "version": APP_VERSION,
        "release_notes": "VPN connect fix, real-time scan progress, scanner improvements.",
        "download_url": DOWNLOAD_URL,
    }
