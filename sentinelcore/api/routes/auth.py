import secrets
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, status
from pydantic import BaseModel, EmailStr
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth.dependencies import get_current_user
from api.auth.jwt import create_access_token, generate_api_key, hash_password, verify_password
from api.config import get_settings
from api.database import get_db
from api.models.scan import User
from api.services.email import send_verification_email

TRIAL_DAYS = 7  # Free users get 7 days of VPN access to drive Pro conversion

router = APIRouter(prefix="/auth", tags=["auth"])
settings = get_settings()


class RegisterRequest(BaseModel):
    email: EmailStr
    password: str


class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    api_key: str
    tier: str = "free"
    trial_ends_at: str | None = None
    is_verified: bool = False


@router.post("/register", response_model=TokenResponse, status_code=status.HTTP_201_CREATED)
async def register(
    body: RegisterRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(User).where(User.email == body.email))
    if result.scalar_one_or_none():
        raise HTTPException(status_code=400, detail="Email already registered")

    trial_ends = datetime.now(timezone.utc) + timedelta(days=TRIAL_DAYS)
    verification_token = secrets.token_urlsafe(32)

    user = User(
        id=uuid.uuid4(),
        email=body.email,
        hashed_password=hash_password(body.password),
        api_key=generate_api_key(),
        trial_ends_at=trial_ends,
        verification_token=verification_token,
        is_verified=False,
    )
    db.add(user)
    await db.commit()
    await db.refresh(user)

    if settings.resend_api_key:
        background_tasks.add_task(
            send_verification_email,
            to_email=user.email,
            token=verification_token,
            base_url=settings.app_base_url,
            api_key=settings.resend_api_key,
            from_email=settings.email_from,
        )

    token = create_access_token(str(user.id))
    return TokenResponse(
        access_token=token,
        api_key=user.api_key,
        tier=user.tier or "free",
        trial_ends_at=user.trial_ends_at.isoformat() if user.trial_ends_at else None,
        is_verified=False,
    )


@router.post("/login", response_model=TokenResponse)
async def login(body: LoginRequest, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.email == body.email))
    user = result.scalar_one_or_none()

    if not user or not verify_password(body.password, user.hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    token = create_access_token(str(user.id))
    return TokenResponse(
        access_token=token,
        api_key=user.api_key,
        tier=user.tier or "free",
        trial_ends_at=user.trial_ends_at.isoformat() if user.trial_ends_at else None,
        is_verified=bool(user.is_verified),
    )


@router.get("/verify-email")
async def verify_email(token: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(User).where(User.verification_token == token))
    user = result.scalar_one_or_none()
    if not user:
        raise HTTPException(status_code=400, detail="Invalid or expired verification token")
    user.is_verified = True
    user.verification_token = None
    await db.commit()
    return {"message": "Email verified successfully"}


@router.post("/resend-verification", status_code=status.HTTP_200_OK)
async def resend_verification(
    background_tasks: BackgroundTasks,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if current_user.is_verified:
        return {"message": "Email already verified"}

    token = secrets.token_urlsafe(32)
    current_user.verification_token = token
    await db.commit()

    if settings.resend_api_key:
        background_tasks.add_task(
            send_verification_email,
            to_email=current_user.email,
            token=token,
            base_url=settings.app_base_url,
            api_key=settings.resend_api_key,
            from_email=settings.email_from,
        )
    return {"message": "Verification email sent"}


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/change-password", status_code=status.HTTP_200_OK)
async def change_password(
    body: ChangePasswordRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    if not verify_password(body.current_password, current_user.hashed_password):
        raise HTTPException(status_code=400, detail="Current password is incorrect")
    if len(body.new_password) < 8:
        raise HTTPException(status_code=400, detail="New password must be at least 8 characters")
    current_user.hashed_password = hash_password(body.new_password)
    await db.commit()
    return {"message": "Password updated successfully"}