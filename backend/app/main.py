from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import ORJSONResponse

from app.core.config import get_settings
from app.db import create_all
from app.routers import auth, emails, ingest, internal, logs, resources, stream
from app.services.kafka import start_kafka, stop_kafka


@asynccontextmanager
async def lifespan(app: FastAPI):
    await create_all()
    await start_kafka()
    yield
    await stop_kafka()


settings = get_settings()
app = FastAPI(title=settings.app_name, default_response_class=ORJSONResponse, lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router)
app.include_router(ingest.router)
app.include_router(internal.router)
app.include_router(logs.router)
app.include_router(emails.router)
app.include_router(resources.router)
app.include_router(stream.router)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}
