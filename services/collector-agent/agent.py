import asyncio
import hashlib
import json
import os
import platform
import shutil
import socket
import subprocess
import time
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import httpx
import orjson


API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000").rstrip("/")
INGEST_TOKEN = os.getenv("INGEST_TOKEN", "local-ingest-token")
AGENT_VERSION = os.getenv("AGENT_VERSION", "0.1.0")
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "50"))
FLUSH_SECONDS = float(os.getenv("FLUSH_SECONDS", "2"))
LOG_PATHS = [Path(p) for p in os.getenv("LOG_PATHS", "").split(",") if p.strip()]
ENABLE_JOURNALCTL = os.getenv("ENABLE_JOURNALCTL", "true").lower() == "true"
WINDOWS_CHANNELS = [c.strip() for c in os.getenv("WINDOWS_CHANNELS", "Security,System,Application").split(",") if c.strip()]
WINDOWS_POLL_SECONDS = float(os.getenv("WINDOWS_POLL_SECONDS", "5"))


def os_type() -> str:
    system = platform.system().lower()
    if system == "windows":
        return "windows"
    return "ubuntu"


async def api_post(client: httpx.AsyncClient, path: str, payload: dict[str, Any]) -> dict[str, Any]:
    response = await client.post(path, json=payload)
    response.raise_for_status()
    return response.json()


async def register(client: httpx.AsyncClient) -> str:
    payload = {
        "host_name": socket.gethostname(),
        "os_type": os_type(),
        "agent_version": AGENT_VERSION,
    }
    data = await api_post(client, "/collectors/register", payload)
    return data["id"]


async def heartbeat(client: httpx.AsyncClient, collector_id: str) -> None:
    while True:
        try:
            await api_post(client, "/collectors/heartbeat", {"collector_id": collector_id, "status": "online"})
        except Exception as exc:
            print(f"heartbeat failed: {exc}", flush=True)
        await asyncio.sleep(20)


async def tail_file(path: Path) -> AsyncIterator[dict[str, Any]]:
    while not path.exists():
        print(f"waiting for log file {path}", flush=True)
        await asyncio.sleep(5)
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        handle.seek(0, os.SEEK_END)
        while True:
            line = handle.readline()
            if not line:
                await asyncio.sleep(0.2)
                continue
            yield {
                "source_type": f"{os_type()}_agent",
                "source": str(path),
                "content": line.strip(),
                "metadata": {"collector": "file_tail", "path": str(path)},
            }


async def journalctl_events() -> AsyncIterator[dict[str, Any]]:
    if platform.system().lower() == "windows" or not ENABLE_JOURNALCTL:
        return
    if shutil.which("journalctl") is None:
        print("journalctl not found; skip journal stream and continue with file tails", flush=True)
        return
    process = await asyncio.create_subprocess_exec(
        "journalctl",
        "-f",
        "-o",
        "json",
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    assert process.stdout
    async for raw in process.stdout:
        try:
            item = orjson.loads(raw)
            message = item.get("MESSAGE") or raw.decode("utf-8", errors="replace")
        except Exception:
            item = {}
            message = raw.decode("utf-8", errors="replace")
        yield {
            "source_type": "ubuntu_agent",
            "source": "journalctl",
            "content": str(message),
            "correlation_id": item.get("_BOOT_ID"),
            "metadata": {
                "collector": "journalctl",
                "unit": item.get("_SYSTEMD_UNIT"),
                "priority": item.get("PRIORITY"),
                "pid": item.get("_PID"),
            },
        }


async def windows_events() -> AsyncIterator[dict[str, Any]]:
    if platform.system().lower() != "windows":
        return
    seen: set[str] = set()
    while True:
        for channel in WINDOWS_CHANNELS:
            try:
                output = subprocess.check_output(
                    ["wevtutil", "qe", channel, "/c:20", "/rd:true", "/f:text"],
                    text=True,
                    errors="replace",
                    timeout=10,
                )
            except Exception as exc:
                print(f"wevtutil failed for {channel}: {exc}", flush=True)
                continue
            for block in output.split("\n\n"):
                content = block.strip()
                if not content:
                    continue
                key = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()
                if key in seen:
                    continue
                seen.add(key)
                yield {
                    "source_type": "windows_agent",
                    "source": f"windows:{channel}",
                    "content": content,
                    "correlation_id": key,
                    "metadata": {"collector": "wevtutil", "channel": channel},
                }
        await asyncio.sleep(WINDOWS_POLL_SECONDS)


async def fan_in(queue: asyncio.Queue[dict[str, Any]], iterator: AsyncIterator[dict[str, Any]]) -> None:
    async for event in iterator:
        await queue.put(event)


async def shipper(client: httpx.AsyncClient, collector_id: str, queue: asyncio.Queue[dict[str, Any]]) -> None:
    batch: list[dict[str, Any]] = []
    last_flush = time.monotonic()
    while True:
        timeout = max(0.1, FLUSH_SECONDS - (time.monotonic() - last_flush))
        try:
            event = await asyncio.wait_for(queue.get(), timeout=timeout)
            batch.append(event)
        except asyncio.TimeoutError:
            pass
        if not batch:
            continue
        if len(batch) >= BATCH_SIZE or time.monotonic() - last_flush >= FLUSH_SECONDS:
            payload = {"collector_id": collector_id, "events": batch[:BATCH_SIZE]}
            try:
                await api_post(client, "/collectors/events", payload)
                del batch[:BATCH_SIZE]
                last_flush = time.monotonic()
            except Exception as exc:
                print(f"ship batch failed: {exc}", flush=True)
                await asyncio.sleep(2)


async def main() -> None:
    headers = {"x-ingest-token": INGEST_TOKEN}
    async with httpx.AsyncClient(base_url=API_BASE_URL, headers=headers, timeout=15) as client:
        collector_id = await register(client)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=5000)
        tasks = [asyncio.create_task(heartbeat(client, collector_id)), asyncio.create_task(shipper(client, collector_id, queue))]
        if platform.system().lower() == "windows":
            tasks.append(asyncio.create_task(fan_in(queue, windows_events())))
        else:
            if ENABLE_JOURNALCTL:
                tasks.append(asyncio.create_task(fan_in(queue, journalctl_events())))
            for path in LOG_PATHS:
                tasks.append(asyncio.create_task(fan_in(queue, tail_file(path))))
        await asyncio.gather(*tasks)


if __name__ == "__main__":
    asyncio.run(main())
