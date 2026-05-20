import asyncio
import email
import imaplib
import os
import ssl
from contextlib import asynccontextmanager
from email.utils import getaddresses
from email.message import Message
from typing import Any

import httpx
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import PlainTextResponse


API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000").rstrip("/")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "local-ingest-token")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "local-internal-token")
IMAP_HOST = os.getenv("IMAP_HOST", "")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD", "")
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "INBOX")
IMAP_POLL_SECONDS = float(os.getenv("IMAP_POLL_SECONDS", "10"))
IMAP_BACKFILL_LIMIT = int(os.getenv("IMAP_BACKFILL_LIMIT", "50"))
RUNTIME_CONFIG_RETRIES = int(os.getenv("RUNTIME_CONFIG_RETRIES", "8"))
RUNTIME_CONFIG_RETRY_SECONDS = float(os.getenv("RUNTIME_CONFIG_RETRY_SECONDS", "2"))
MAILBOX_LABEL = os.getenv("MAILBOX_LABEL", IMAP_USER or "mailbox")
GRAPH_CLIENT_STATE = os.getenv("GRAPH_CLIENT_STATE", "")


def normalize_secret(value: str | None) -> str:
    return (value or "").strip()


def normalize_imap_password(host: str, password: str | None) -> str:
    normalized = normalize_secret(password)
    if host.endswith("gmail.com"):
        return normalized.replace(" ", "")
    return normalized


def env_imap_config() -> dict[str, str]:
    return {
        "imap_host": IMAP_HOST.strip(),
        "imap_port": str(IMAP_PORT),
        "imap_user": IMAP_USER.strip(),
        "imap_password": normalize_imap_password(IMAP_HOST.strip(), IMAP_PASSWORD),
        "imap_folder": IMAP_FOLDER.strip() or "INBOX",
        "imap_backfill_limit": str(IMAP_BACKFILL_LIMIT),
    }


async def fetch_runtime_config(client: httpx.AsyncClient) -> dict[str, str]:
    try:
        response = await client.get("/internal/runtime-config", headers={"x-internal-token": INTERNAL_TOKEN})
        response.raise_for_status()
        data = response.json()
        return {key: str(value).strip() for key, value in data.items() if value is not None}
    except Exception as exc:
        print(f"runtime IMAP config fetch failed, using env: {exc}", flush=True)
        return {}


async def fetch_runtime_config_with_retry(client: httpx.AsyncClient, stop_event: asyncio.Event) -> dict[str, str]:
    runtime: dict[str, str] = {}
    for attempt in range(1, RUNTIME_CONFIG_RETRIES + 1):
        runtime = await fetch_runtime_config(client)
        if runtime or attempt == RUNTIME_CONFIG_RETRIES or stop_event.is_set():
            return runtime
        await asyncio.sleep(RUNTIME_CONFIG_RETRY_SECONDS)
    return runtime


def merged_imap_config(runtime: dict[str, str]) -> dict[str, str]:
    config = env_imap_config()
    for key in config:
        if runtime.get(key):
            config[key] = runtime[key]
    if runtime.get("imap_user_verified"):
        config["imap_user_verified"] = runtime["imap_user_verified"]
    config["imap_password"] = normalize_imap_password(config.get("imap_host", ""), config.get("imap_password"))
    return config


def imap_user_is_verified(config: dict[str, str], runtime: dict[str, str]) -> bool:
    # Env-only fallback remains useful for local/dev. Runtime-configured IMAP must be OTP verified.
    if not runtime.get("imap_user"):
        return True
    return (runtime.get("imap_user_verified") or "").lower() == (config.get("imap_user") or "").lower()


def log_imap_config_source(config: dict[str, str], runtime: dict[str, str]) -> None:
    source = "runtime backend" if any(runtime.get(key) for key in env_imap_config()) else "env fallback"
    print(
        "IMAP config loaded from "
        f"{source}: host={config.get('imap_host') or '<empty>'}, "
        f"user={config.get('imap_user') or '<empty>'}, "
        f"folder={config.get('imap_folder') or 'INBOX'}, "
        f"backfill={config.get('imap_backfill_limit') or '50'}",
        flush=True,
    )


def summarize_message(msg: Message) -> tuple[str, list[dict[str, Any]]]:
    body_parts: list[str] = []
    attachments: list[dict[str, Any]] = []
    if msg.is_multipart():
        for part in msg.walk():
            disposition = part.get_content_disposition()
            content_type = part.get_content_type()
            filename = part.get_filename()
            if disposition == "attachment" or filename:
                attachments.append(
                    {
                        "filename": filename,
                        "content_type": content_type,
                        "size": len(part.get_payload(decode=True) or b""),
                    }
                )
                continue
            if content_type in {"text/plain", "text/html"}:
                payload = part.get_payload(decode=True)
                if payload:
                    body_parts.append(payload.decode(part.get_content_charset() or "utf-8", errors="replace"))
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            body_parts.append(payload.decode(msg.get_content_charset() or "utf-8", errors="replace"))
    body = " ".join(" ".join(part.split()) for part in body_parts)
    return body[:4000], attachments


async def send_email_event(client: httpx.AsyncClient, payload: dict[str, Any]) -> None:
    response = await client.post("/ingest/webhook", json=payload)
    response.raise_for_status()


async def poll_imap(stop_event: asyncio.Event) -> None:
    headers = {"x-ingest-token": INGEST_TOKEN}
    async with httpx.AsyncClient(base_url=API_BASE_URL, headers=headers, timeout=20) as client:
        runtime = await fetch_runtime_config_with_retry(client, stop_event)
        config = merged_imap_config(runtime)
        log_imap_config_source(config, runtime)
        if not imap_user_is_verified(config, runtime):
            print("IMAP polling disabled: verify IMAP User OTP in Settings before reading mailbox", flush=True)
            return
        if not (config["imap_host"] and config["imap_user"] and config["imap_password"]):
            print("IMAP polling disabled: configure IMAP in Settings or IMAP_HOST/IMAP_USER/IMAP_PASSWORD env", flush=True)
            return

        backfill_limit = int(config.get("imap_backfill_limit") or "50")
        if backfill_limit > 0:
            try:
                for payload in await asyncio.to_thread(fetch_once, config, "ALL", backfill_limit, False):
                    await send_email_event(client, payload)
                print(f"imap backfill completed: last {backfill_limit} messages", flush=True)
            except Exception as exc:
                print(f"imap backfill failed: {exc}", flush=True)
        while not stop_event.is_set():
            try:
                runtime = await fetch_runtime_config(client)
                config = merged_imap_config(runtime)
                if not imap_user_is_verified(config, runtime):
                    print("IMAP polling paused: IMAP User is not OTP verified", flush=True)
                elif not (config["imap_host"] and config["imap_user"] and config["imap_password"]):
                    print("IMAP polling paused: missing runtime IMAP config", flush=True)
                else:
                    for payload in await asyncio.to_thread(fetch_once, config, "UNSEEN", 0, True):
                        await send_email_event(client, payload)
            except Exception as exc:
                print(f"imap poll failed: {exc}", flush=True)
            await asyncio.sleep(IMAP_POLL_SECONDS)


def parsed_addresses(*headers: str | None) -> list[str]:
    values = [value for value in headers if value]
    return sorted({addr.lower() for _name, addr in getaddresses(values) if addr})


def fetch_once(config: dict[str, str], search_criterion: str = "UNSEEN", newest_limit: int = 0, mark_seen: bool = True) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    context = ssl.create_default_context()
    imap_host = config["imap_host"]
    imap_port = int(config.get("imap_port") or "993")
    imap_user = config["imap_user"]
    imap_password = config["imap_password"]
    imap_folder = config.get("imap_folder") or "INBOX"
    mailbox_label = os.getenv("MAILBOX_LABEL") or imap_user
    with imaplib.IMAP4_SSL(imap_host, imap_port, ssl_context=context) as mailbox:
        mailbox.login(imap_user, imap_password)
        mailbox.select(imap_folder)
        status, ids_data = mailbox.search(None, search_criterion)
        if status != "OK":
            return events
        message_ids = ids_data[0].split()
        if newest_limit > 0:
            message_ids = message_ids[-newest_limit:]
        for message_id in message_ids:
            status, msg_data = mailbox.fetch(message_id, "(RFC822)")
            if status != "OK" or not msg_data:
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            body, attachments = summarize_message(msg)
            recipients = parsed_addresses(
                msg.get("To"),
                msg.get("Cc"),
                msg.get("Bcc"),
                msg.get("Delivered-To"),
                msg.get("X-Original-To"),
            )
            content = (
                f"Subject: {msg.get('Subject', '')}\n"
                f"From: {msg.get('From', '')}\n"
                f"To: {msg.get('To', '')}\n"
                f"Cc: {msg.get('Cc', '')}\n"
                f"Attachments: {attachments}\n"
                f"Body: {body}"
            )
            events.append(
                {
                    "source_type": "email",
                    "source": mailbox_label,
                    "content": content,
                    "correlation_id": msg.get("Message-ID") or message_id.decode(),
                    "metadata": {
                        "mailbox": mailbox_label,
                        "message_id": msg.get("Message-ID"),
                        "sender": msg.get("From"),
                        "recipients": recipients,
                        "subject": msg.get("Subject"),
                        "attachments": attachments,
                    },
                }
            )
            if mark_seen:
                mailbox.store(message_id, "+FLAGS", "\\Seen")
    return events


stop = asyncio.Event()


@asynccontextmanager
async def lifespan(app: FastAPI):
    task = asyncio.create_task(poll_imap(stop))
    yield
    stop.set()
    await task


app = FastAPI(title="AI-SOC Email Ingest", lifespan=lifespan)


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/graph/webhook")
async def graph_webhook(
    request: Request,
    validationToken: str | None = Query(default=None),  # Microsoft Graph validation uses this exact name.
) -> Response:
    if validationToken:
        return PlainTextResponse(validationToken)
    payload = await request.json()
    headers = {"x-ingest-token": INGEST_TOKEN}
    async with httpx.AsyncClient(base_url=API_BASE_URL, headers=headers, timeout=20) as client:
        for item in payload.get("value", []):
            if GRAPH_CLIENT_STATE and item.get("clientState") != GRAPH_CLIENT_STATE:
                continue
            resource = item.get("resource", "graph-message")
            await send_email_event(
                client,
                {
                    "source_type": "email",
                    "source": "microsoft-graph",
                    "content": f"Microsoft Graph mail notification received for {resource}",
                    "correlation_id": item.get("subscriptionId"),
                    "metadata": item,
                },
            )
    return Response(status_code=202)
