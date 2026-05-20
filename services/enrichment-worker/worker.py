import asyncio
import os
from typing import Any

import httpx
import orjson
from aiokafka import AIOKafkaConsumer


API_BASE_URL = os.getenv("API_BASE_URL", "http://api:8000").rstrip("/")
INTERNAL_TOKEN = os.getenv("INTERNAL_TOKEN", "local-internal-token")
KAFKA_BOOTSTRAP_SERVERS = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "kafka:9092")
KAFKA_TOPIC = os.getenv("KAFKA_SECURITY_EVENTS_TOPIC", "security_events")
KAFKA_GROUP_ID = os.getenv("KAFKA_GROUP_ID", "ai-soc-enrichment-worker")

ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY", "")
VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")
NVD_API_KEY = os.getenv("NVD_API_KEY", "")

LLM_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("OPENAI_API_KEY") or os.getenv("DEEPSEEK_API_KEY", "")
LLM_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.openai.com/v1").rstrip("/")
LLM_MODEL = os.getenv("LLM_MODEL", "gpt-4o-mini")
LLM_TIMEOUT_SECONDS = float(os.getenv("LLM_TIMEOUT_SECONDS", "8"))


async def fetch_runtime_config(client: httpx.AsyncClient) -> dict[str, str]:
    try:
        response = await client.get("/internal/runtime-config")
        response.raise_for_status()
        return {key: value for key, value in response.json().items() if value}
    except Exception as exc:
        print(f"runtime config fetch failed, using env: {exc}", flush=True)
        return {}


def loads(raw: bytes) -> dict[str, Any]:
    return orjson.loads(raw)


async def abuseipdb(client: httpx.AsyncClient, ip: str, api_key: str) -> dict[str, Any] | None:
    if not api_key:
        return None
    response = await client.get(
        "https://api.abuseipdb.com/api/v2/check",
        params={"ipAddress": ip, "maxAgeInDays": 90},
        headers={"Key": api_key, "Accept": "application/json"},
    )
    if response.status_code >= 400:
        return {"ip": ip, "error": response.text[:200]}
    data = response.json().get("data", {})
    return {
        "ip": ip,
        "abuse_confidence_score": data.get("abuseConfidenceScore"),
        "country_code": data.get("countryCode"),
        "usage_type": data.get("usageType"),
        "domain": data.get("domain"),
    }


async def virustotal_domain(client: httpx.AsyncClient, domain: str, api_key: str) -> dict[str, Any] | None:
    if not api_key:
        return None
    response = await client.get(
        f"https://www.virustotal.com/api/v3/domains/{domain}",
        headers={"x-apikey": api_key},
    )
    if response.status_code >= 400:
        return {"domain": domain, "error": response.text[:200]}
    stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {"domain": domain, "last_analysis_stats": stats}


async def nvd_search(client: httpx.AsyncClient, keyword: str, api_key: str) -> dict[str, Any] | None:
    if not (api_key and keyword):
        return None
    headers = {"apiKey": api_key}
    response = await client.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params={"keywordSearch": keyword[:120], "resultsPerPage": 3},
        headers=headers,
    )
    if response.status_code >= 400:
        return {"keyword": keyword, "error": response.text[:200]}
    items = response.json().get("vulnerabilities", [])
    return {
        "keyword": keyword,
        "cves": [
            {
                "id": item.get("cve", {}).get("id"),
                "published": item.get("cve", {}).get("published"),
            }
            for item in items
        ],
    }


async def llm_summary(client: httpx.AsyncClient, event: dict[str, Any], enrichment: dict[str, Any], config: dict[str, str]) -> str | None:
    api_key = config.get("llm_api_key") or LLM_API_KEY
    base_url = (config.get("llm_base_url") or LLM_BASE_URL).rstrip("/")
    model = config.get("llm_model") or LLM_MODEL
    if not api_key:
        return None
    prompt = (
        "You are a SOC analyst. Summarize this event in 3 concise sentences, "
        "include likely risk and next action. Do not reveal raw secrets.\n\n"
        f"Event summary: {event.get('log_summary')}\n"
        f"Entities: {event.get('extracted_entities')}\n"
        f"Threat intel: {enrichment}"
    )
    response = await client.post(
        f"{base_url}/chat/completions",
        headers={"Authorization": f"Bearer {api_key}"},
        json={
            "model": model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.1,
            "max_tokens": 220,
        },
        timeout=LLM_TIMEOUT_SECONDS,
    )
    if response.status_code >= 400:
        return None
    return response.json()["choices"][0]["message"]["content"]


def choose_severity(event: dict[str, Any], enrichment: dict[str, Any]) -> str | None:
    for ip_info in enrichment.get("abuseipdb", []):
        score = ip_info.get("abuse_confidence_score")
        if isinstance(score, int) and score >= 85:
            return "Critical"
        if isinstance(score, int) and score >= 50:
            return "High"
    for domain_info in enrichment.get("virustotal_domains", []):
        stats = domain_info.get("last_analysis_stats") or {}
        if stats.get("malicious", 0) >= 3:
            return "High"
    if event.get("initial_alert_id"):
        return None
    return "Medium"


async def enrich_event(client: httpx.AsyncClient, event: dict[str, Any]) -> dict[str, Any]:
    config = await fetch_runtime_config(client)
    entities = event.get("extracted_entities") or {}
    ips = entities.get("ips") or []
    domains = entities.get("domains") or []
    enrichment: dict[str, Any] = {"abuseipdb": [], "virustotal_domains": [], "nvd": None}

    tasks = []
    for ip in ips[:5]:
        tasks.append(abuseipdb(client, ip, config.get("abuseipdb_api_key") or ABUSEIPDB_API_KEY))
    for domain in domains[:5]:
        tasks.append(virustotal_domain(client, domain, config.get("virustotal_api_key") or VIRUSTOTAL_API_KEY))
    if event.get("source"):
        tasks.append(nvd_search(client, event["source"], config.get("nvd_api_key") or NVD_API_KEY))

    results = [item for item in await asyncio.gather(*tasks, return_exceptions=False) if item]
    for item in results:
        if "ip" in item:
            enrichment["abuseipdb"].append(item)
        elif "domain" in item:
            enrichment["virustotal_domains"].append(item)
        elif "cves" in item:
            enrichment["nvd"] = item

    ai_summary = await llm_summary(client, event, enrichment, config)
    return {"enrichment": enrichment, "ai_summary": ai_summary}


async def apply_enrichment(client: httpx.AsyncClient, event: dict[str, Any], result: dict[str, Any]) -> None:
    severity = choose_severity(event, result["enrichment"])
    payload = {
        "log_id": event["log_id"],
        "severity": severity,
        "message": "Async enrichment completed",
        "ai_summary": result["ai_summary"] or event.get("log_summary"),
        "rule_name": "async_threat_intel_llm",
        "enrichment": result["enrichment"],
    }
    response = await client.post("/internal/enrichments", json=payload)
    response.raise_for_status()


async def main() -> None:
    headers = {"x-internal-token": INTERNAL_TOKEN}
    while True:
        consumer = AIOKafkaConsumer(
            KAFKA_TOPIC,
            bootstrap_servers=KAFKA_BOOTSTRAP_SERVERS,
            group_id=KAFKA_GROUP_ID,
            value_deserializer=loads,
            enable_auto_commit=False,
        )
        try:
            await consumer.start()
            async with httpx.AsyncClient(base_url=API_BASE_URL, headers=headers, timeout=20) as client:
                async for message in consumer:
                    event = message.value
                    try:
                        result = await enrich_event(client, event)
                        await apply_enrichment(client, event, result)
                        await consumer.commit()
                    except Exception as exc:
                        print(f"failed to enrich event {event.get('log_id')}: {exc}", flush=True)
                        await asyncio.sleep(2)
        except Exception as exc:
            print(f"worker startup/consume failed: {exc}; retrying", flush=True)
            await asyncio.sleep(5)
        finally:
            await consumer.stop()


if __name__ == "__main__":
    asyncio.run(main())
