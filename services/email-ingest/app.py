import asyncio
import email
import imaplib
import os
import ssl
from contextlib import asynccontextmanager
from email.message import Message
from typing import Any

import httpx
from fastapi import FastAPI, Query, Request, Response
from fastapi.responses import PlainTextResponse


API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000").rstrip("/")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "local-ingest-token")
IMAP_HOST = os.getenv("IMAP_HOST", "")
IMAP_PORT = int(os.getenv("IMAP_PORT", "993"))
IMAP_USER = os.getenv("IMAP_USER", "")
IMAP_PASSWORD = os.getenv("IMAP_PASSWORD", "")
IMAP_FOLDER = os.getenv("IMAP_FOLDER", "INBOX")
IMAP_POLL_SECONDS = float(os.getenv("IMAP_POLL_SECONDS", "10"))
MAILBOX_LABEL = os.getenv("MAILBOX_LABEL", IMAP_USER or "mailbox")
GRAPH_CLIENT_STATE = os.getenv("GRAPH_CLIENT_STATE", "")


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
    if not (IMAP_HOST and IMAP_USER and IMAP_PASSWORD):
        print("IMAP polling disabled: IMAP_HOST/IMAP_USER/IMAP_PASSWORD not set", flush=True)
        return
    headers = {"x-ingest-token": INGEST_TOKEN}
    async with httpx.AsyncClient(base_url=API_BASE_URL, headers=headers, timeout=20) as client:
        while not stop_event.is_set():
            try:
                for payload in await asyncio.to_thread(fetch_once):
                    await send_email_event(client, payload)
            except Exception as exc:
                print(f"imap poll failed: {exc}", flush=True)
            await asyncio.sleep(IMAP_POLL_SECONDS)


def fetch_once() -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    context = ssl.create_default_context()
    with imaplib.IMAP4_SSL(IMAP_HOST, IMAP_PORT, ssl_context=context) as mailbox:
        mailbox.login(IMAP_USER, IMAP_PASSWORD)
        mailbox.select(IMAP_FOLDER)
        status, ids_data = mailbox.search(None, "UNSEEN")
        if status != "OK":
            return events
        for message_id in ids_data[0].split():
            status, msg_data = mailbox.fetch(message_id, "(RFC822)")
            if status != "OK" or not msg_data:
                continue
            raw = msg_data[0][1]
            msg = email.message_from_bytes(raw)
            body, attachments = summarize_message(msg)
            content = (
                f"Subject: {msg.get('Subject', '')}\n"
                f"From: {msg.get('From', '')}\n"
                f"To: {msg.get('To', '')}\n"
                f"Attachments: {attachments}\n"
                f"Body: {body}"
            )
            events.append(
                {
                    "source_type": "email",
                    "source": MAILBOX_LABEL,
                    "content": content,
                    "correlation_id": msg.get("Message-ID") or message_id.decode(),
                    "metadata": {
                        "mailbox": MAILBOX_LABEL,
                        "message_id": msg.get("Message-ID"),
                        "sender": msg.get("From"),
                        "subject": msg.get("Subject"),
                        "attachments": attachments,
                    },
                }
            )
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
