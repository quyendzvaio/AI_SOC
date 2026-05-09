import asyncio
import uuid

import jwt
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.security import decode_access_token
from app.db import get_session
from app.models import User
from app.services.realtime import broker, sse

router = APIRouter(prefix="/stream", tags=["stream"])


async def stream_user(token: str = Query(...), session: AsyncSession = Depends(get_session)) -> User:
    try:
        payload = decode_access_token(token)
        user_id = uuid.UUID(payload["sub"])
    except (KeyError, ValueError, jwt.PyJWTError) as exc:
        raise HTTPException(status_code=401, detail="Invalid stream token") from exc
    user = await session.get(User, user_id)
    if not user or not user.is_email_verified:
        raise HTTPException(status_code=401, detail="Inactive user")
    return user


@router.get("/events")
async def stream_events(_user: User = Depends(stream_user)) -> StreamingResponse:
    async def iterator():
        yield sse("ready", {"status": "connected"})
        async for event in broker.subscribe():
            yield sse(event["type"], event)
            await asyncio.sleep(0)

    return StreamingResponse(iterator(), media_type="text/event-stream")
