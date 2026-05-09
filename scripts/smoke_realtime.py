import json
import re
import time
import urllib.request


BASE = "http://127.0.0.1:8000"


def post(path: str, payload: dict, headers: dict | None = None) -> dict:
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", **(headers or {})},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.loads(response.read())


def main() -> None:
    email = f"realtime{int(time.time())}@example.com"
    reg = post("/auth/register", {"email": email, "password": "StrongPass123!"})
    otp = re.search(r"DEV_OTP:(\d{6})", reg["token"]).group(1)
    verified = post("/auth/verify-otp", {"email": email, "otp": otp, "purpose": "register"})
    token = verified["token"]

    stream = urllib.request.urlopen(f"{BASE}/stream/events?token={token}", timeout=20)
    first = stream.readline().decode()
    assert first.startswith("event: ready"), first

    post(
        "/ingest/webhook",
        {
            "source_type": "email",
            "source": "smoke-realtime-mailbox",
            "content": "phishing email with suspicious domain evil.example and failed password from 9.9.9.9",
            "metadata": {"smoke": True},
        },
        {"x-ingest-token": "local-ingest-token"},
    )

    deadline = time.time() + 10
    event_name = ""
    data = ""
    while time.time() < deadline:
        line = stream.readline().decode().strip()
        if line.startswith("event: "):
            event_name = line.removeprefix("event: ")
        elif line.startswith("data: "):
            data = line.removeprefix("data: ")
        elif line == "" and event_name == "log" and data:
            payload = json.loads(data)
            assert payload["log"]["source_type"] == "email", payload
            assert payload["alert"]["severity"] in {"Medium", "High", "Critical"}, payload
            print(json.dumps({"event": event_name, "source": payload["log"]["source"], "severity": payload["alert"]["severity"]}))
            return
    raise SystemExit("Timed out waiting for realtime log event")


if __name__ == "__main__":
    main()
