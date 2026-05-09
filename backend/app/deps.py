import uuid
from datetime import datetime, timezone

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.core.security import decode_access_token
from app.db import get_session
from app.models import User, UserRole

bearer = HTTPBearer(auto_error=False)


async def current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    session: AsyncSession = Depends(get_session),
) -> User:
    if not credentials:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing bearer token")
    try:
        payload = decode_access_token(credentials.credentials)
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError, jwt.PyJWTError) as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token") from exc

    user = await session.get(User, user_id)
    if not user or not user.is_email_verified:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Inactive user")
    if user.locked_until and user.locked_until > datetime.now(timezone.utc):
        raise HTTPException(status_code=status.HTTP_423_LOCKED, detail="Account temporarily locked")
    return user


async def admin_user(user: User = Depends(current_user)) -> User:
    if user.role != UserRole.admin:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Admin only")
    return user


def verify_ingest_token(x_ingest_token: str | None = Header(default=None)) -> None:
    if x_ingest_token != get_settings().ingest_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid ingest token")


def verify_internal_token(x_internal_token: str | None = Header(default=None)) -> None:
    if x_internal_token != get_settings().internal_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid internal token")
