# AI-SOC MVP

Backend MVP for realtime Windows/Ubuntu collector ingest, email/webhook ingest, summarized logs, alerts, OTP auth, and queued email notifications.

## Run locally

```bash
docker compose up --build api postgres redis
```

API health:

```bash
curl http://localhost:8000/healthz
```

Register returns a `DEV_OTP` token in local mode so the OTP flow can be tested before wiring a mail provider.

## Realtime dashboard

```bash
docker compose up --build frontend api postgres
```

Open `http://localhost:3000`. The dashboard subscribes to `GET /stream/events` and shows log/email events as they arrive.

Send a test event:

```bash
curl -X POST http://localhost:8000/ingest/webhook \
  -H 'Content-Type: application/json' \
  -H 'x-ingest-token: local-ingest-token' \
  -d '{"source_type":"email","source":"demo-mailbox","content":"phishing email from attacker@example.com with suspicious domain evil.example and failed login from 8.8.8.8"}'
```

## Collector agent

Ubuntu collector container:

```bash
docker compose --profile agent up --build collector-agent
```

On Windows, run `services/collector-agent/agent.py` directly with Python; it uses `wevtutil` to poll Windows Event Logs.

## Email ingest

IMAP polling and Microsoft Graph webhook receiver:

```bash
docker compose --profile integrations up --build email-ingest
```

Graph webhook endpoint: `POST http://localhost:8010/graph/webhook`.

## Full async enrichment stack

Kafka, Qdrant, and the enrichment worker are split into `docker-compose.full.yml` so the default boot stays light:

```bash
docker compose -f docker-compose.yml -f docker-compose.full.yml up --build
```

The API image is intentionally slim: `python:3.12-slim`, no dev dependencies, precompiled bytecode, no reload server, and no LLM/Threat Intel calls in the hot ingest path. Kafka publishing is optional and only starts when `KAFKA_BOOTSTRAP_SERVERS` is set.
