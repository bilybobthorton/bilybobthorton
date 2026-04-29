from fastapi import Depends, HTTPException, Security, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer, APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from api.auth.jwt import decode_token
from api.database import get_db
from api.models.scan import User

bearer_scheme = HTTPBearer(auto_error=False)
api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User:
    # Try JWT bearer first
    if credentials:
        user_id = decode_token(credentials.credentials)
        if user_id:
            result = await db.execute(select(User).where(User.id == user_id))
            user = result.scalar_one_or_none()
            if user:
                return user

    # Fall back to API key
    if api_key:
        result = await db.execute(select(User).where(User.api_key == api_key))
        user = result.scalar_one_or_none()
        if user:
            return user

    raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Not authenticated")


async def get_current_user_optional(
    credentials: HTTPAuthorizationCredentials = Security(bearer_scheme),
    api_key: str = Security(api_key_header),
    db: AsyncSession = Depends(get_db),
) -> User | None:
    try:
        return await get_current_user(credentials, api_key, db)
    except HTTPException:
        return None
