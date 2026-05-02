from __future__ import annotations

import base64
import secrets
import uuid

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat
from fastapi import APIRouter, Depends, HTTPException, Response, status
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.config import get_settings
from api.database import get_db
from api.models.scan import User
from api.models.vpn import VpnKey

router = APIRouter(prefix="/api/v1/vpn", tags=["vpn"])
settings = get_settings()

DEVICE_LIMITS = {"free": 1, "pro": 5, "enterprise": 25}


def _gen_keypair() -> tuple[str, str]:
    priv = X25519PrivateKey.generate()
    priv_b64 = base64.b64encode(
        priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    ).decode()
    pub_b64 = base64.b64encode(
        priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)
    ).decode()
    return priv_b64, pub_b64


def _gen_psk() -> str:
    return base64.b64encode(secrets.token_bytes(32)).decode()


class VpnKeyCreate(BaseModel):
    name: str = "My Device"


class VpnKeyOut(BaseModel):
    id: str
    name: str
    public_key: str
    client_ip: str
    created_at: str


class VpnKeyCreated(VpnKeyOut):
    private_key: str
    preshared_key: str
    config: str


@router.get("/keys", response_model=list[VpnKeyOut])
async def list_keys(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(VpnKey).where(VpnKey.user_id == current_user.id).order_by(VpnKey.created_at)
    )
    return [_out(k) for k in result.scalars().all()]


@router.post("/keys", response_model=VpnKeyCreated, status_code=status.HTTP_201_CREATED)
async def create_key(
    body: VpnKeyCreate,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    tier = current_user.tier or "free"
    limit = DEVICE_LIMITS.get(tier, 1)

    result = await db.execute(
        select(func.count()).where(VpnKey.user_id == current_user.id)
    )
    count = result.scalar_one() or 0
    if count >= limit:
        raise HTTPException(
            status_code=403,
            detail=f"Device limit reached ({limit} for {tier} tier). Upgrade to add more.",
        )

    # Assign client IP from the 10.8.0.0/24 pool starting at .2 (.1 is server)
    res = await db.execute(select(func.count()).select_from(VpnKey))
    total = (res.scalar_one() or 0) + 2  # offset: .2, .3, ...
    client_ip = f"10.8.0.{total}/32"

    priv_b64, pub_b64 = _gen_keypair()
    psk = _gen_psk()

    key = VpnKey(
        id=uuid.uuid4(),
        user_id=current_user.id,
        name=body.name,
        public_key=pub_b64,
        private_key=priv_b64,
        preshared_key=psk,
        client_ip=client_ip,
    )
    db.add(key)
    await db.commit()
    await db.refresh(key)

    config = _build_config(key)
    return VpnKeyCreated(
        id=str(key.id),
        name=key.name,
        public_key=key.public_key,
        private_key=key.private_key,
        preshared_key=key.preshared_key,
        client_ip=key.client_ip,
        created_at=key.created_at.isoformat() if key.created_at else "",
        config=config,
    )


@router.get("/keys/{key_id}/config")
async def download_config(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(VpnKey).where(
            VpnKey.id == uuid.UUID(key_id),
            VpnKey.user_id == current_user.id,
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="VPN key not found")
    config = _build_config(key)
    return Response(
        content=config,
        media_type="text/plain",
        headers={"Content-Disposition": f'attachment; filename="{key.name.replace(" ", "_")}.conf"'},
    )


@router.delete("/keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
async def revoke_key(
    key_id: str,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(VpnKey).where(
            VpnKey.id == uuid.UUID(key_id),
            VpnKey.user_id == current_user.id,
        )
    )
    key = result.scalar_one_or_none()
    if not key:
        raise HTTPException(status_code=404, detail="VPN key not found")
    await db.delete(key)
    await db.commit()


def _out(k: VpnKey) -> VpnKeyOut:
    return VpnKeyOut(
        id=str(k.id),
        name=k.name,
        public_key=k.public_key,
        client_ip=k.client_ip,
        created_at=k.created_at.isoformat() if k.created_at else "",
    )


def _build_config(key: VpnKey) -> str:
    server_pub = settings.vpn_server_public_key or "<SERVER_PUBLIC_KEY>"
    endpoint = settings.vpn_server_endpoint or "<vpn.yourservice.com:51820>"
    dns = settings.vpn_dns or "1.1.1.1, 1.0.0.1"

    return f"""[Interface]
# Device: {key.name}
PrivateKey = {key.private_key}
Address = {key.client_ip}
DNS = {dns}

[Peer]
PublicKey = {server_pub}
PresharedKey = {key.preshared_key}
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = {endpoint}
PersistentKeepalive = 25
"""
