import asyncio
import json
import os
import re
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Iterable
from typing import Any

from sqlalchemy import desc, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models import Alert, EmailMessage, LogEvent, RuntimeSetting
from app.services.crypto import decrypt_value
from app.services.knowledge_base import all_knowledge_docs, retrieve_knowledge

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
WORD_RE = re.compile(r"[a-zA-Z0-9_]{2,}")


def _env_or_config(config: dict[str, str | None], key: str, env_key: str) -> str:
    return (config.get(key) or os.getenv(env_key) or "").strip()


def _tokenize(text: str) -> set[str]:
    return {w.lower() for w in WORD_RE.findall(text)}


def _extract_indicators(text: str) -> dict[str, list[str]]:
    return {
        "ips": sorted(set(IP_RE.findall(text)))[:5],
        "domains": sorted(set(DOMAIN_RE.findall(text)))[:5],
        "hashes": sorted(set(HASH_RE.findall(text)))[:5],
    }


def _http_json(url: str, headers: dict[str, str] | None = None, payload: dict[str, Any] | None = None, timeout: float = 8.0) -> dict[str, Any]:
    data = None if payload is None else json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(url, data=data, method="POST" if payload is not None else "GET")
    for key, value in (headers or {}).items():
        req.add_header(key, value)
    if payload is not None:
        req.add_header("Content-Type", "application/json")
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


async def _load_runtime_config(session: AsyncSession) -> dict[str, str | None]:
    result = await session.execute(select(RuntimeSetting))
    output: dict[str, str | None] = {}
    for setting in result.scalars():
        output[setting.key] = decrypt_value(setting.value_encrypted) if setting.is_secret else setting.value_public
    return output


def _score_doc(question_terms: set[str], question_iocs: dict[str, list[str]], text: str) -> int:
    terms = _tokenize(text)
    overlap = len(question_terms & terms)
    iocs = _extract_indicators(text)
    ioc_hit = sum(1 for ip in question_iocs["ips"] if ip in iocs["ips"])
    ioc_hit += sum(1 for d in question_iocs["domains"] if d in iocs["domains"])
    ioc_hit += sum(1 for h in question_iocs["hashes"] if h in iocs["hashes"])
    return overlap + ioc_hit * 5


def _rerank(question: str, docs: Iterable[dict[str, str]], top_k: int = 8) -> list[dict[str, str]]:
    q_terms = _tokenize(question)
    q_iocs = _extract_indicators(question)
    ranked = sorted(
        docs,
        key=lambda d: _score_doc(q_terms, q_iocs, f"{d.get('title', '')} {d.get('text', '')}"),
        reverse=True,
    )
    return [d for d in ranked if _score_doc(q_terms, q_iocs, f"{d.get('title', '')} {d.get('text', '')}") > 0][:top_k]


async def _threat_intel_bundle(config: dict[str, str | None], indicators: dict[str, list[str]], hint: str) -> dict[str, Any]:
    abuse_key = _env_or_config(config, "abuseipdb_api_key", "ABUSEIPDB_API_KEY")
    vt_key = _env_or_config(config, "virustotal_api_key", "VIRUSTOTAL_API_KEY")
    nvd_key = _env_or_config(config, "nvd_api_key", "NVD_API_KEY")
    bundle: dict[str, Any] = {"abuseipdb": [], "virustotal": [], "nvd": None}

    async def abuse_lookup(ip: str) -> dict[str, Any]:
        if not abuse_key:
            return {"ip": ip, "skipped": "missing_key"}
        url = "https://api.abuseipdb.com/api/v2/check?" + urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
        try:
            data = await asyncio.to_thread(
                _http_json,
                url,
                {"Key": abuse_key, "Accept": "application/json"},
                None,
                6.0,
            )
            info = data.get("data", {})
            return {"ip": ip, "score": info.get("abuseConfidenceScore"), "country": info.get("countryCode")}
        except Exception as exc:
            return {"ip": ip, "error": str(exc)}

    async def vt_lookup(domain: str) -> dict[str, Any]:
        if not vt_key:
            return {"domain": domain, "skipped": "missing_key"}
        url = f"https://www.virustotal.com/api/v3/domains/{domain}"
        try:
            data = await asyncio.to_thread(_http_json, url, {"x-apikey": vt_key}, None, 6.0)
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"domain": domain, "stats": stats}
        except Exception as exc:
            return {"domain": domain, "error": str(exc)}

    async def nvd_lookup() -> dict[str, Any]:
        if not (nvd_key and hint.strip()):
            return {"skipped": "missing_key_or_hint"}
        query = urllib.parse.urlencode({"keywordSearch": hint[:120], "resultsPerPage": 3})
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?{query}"
        try:
            data = await asyncio.to_thread(_http_json, url, {"apiKey": nvd_key}, None, 7.0)
            vulns = data.get("vulnerabilities", [])
            return {"cves": [v.get("cve", {}).get("id") for v in vulns[:3]]}
        except Exception as exc:
            return {"error": str(exc)}

    abuse_tasks = [abuse_lookup(ip) for ip in indicators["ips"][:3]]
    vt_tasks = [vt_lookup(d) for d in indicators["domains"][:3]]
    bundle["abuseipdb"] = await asyncio.gather(*abuse_tasks) if abuse_tasks else []
    bundle["virustotal"] = await asyncio.gather(*vt_tasks) if vt_tasks else []
    bundle["nvd"] = await nvd_lookup()
    return bundle


async def _fetch_rag_docs(session: AsyncSession) -> list[dict[str, str]]:
    docs: list[dict[str, str]] = [
        {"title": doc["title"], "text": f"source={doc['source']} {doc['text']}"}
        for doc in all_knowledge_docs()
    ]
    log_rows = await session.execute(select(LogEvent).order_by(desc(LogEvent.received_at)).limit(120))
    for row in log_rows.scalars():
        docs.append(
            {
                "title": f"log:{row.source}",
                "text": f"{row.log_summary} entities={row.extracted_entities}",
            }
        )
    alert_rows = await session.execute(select(Alert).order_by(desc(Alert.detected_at)).limit(80))
    for row in alert_rows.scalars():
        docs.append(
            {
                "title": f"alert:{row.severity.value}",
                "text": f"{row.message} | {row.ai_summary}",
            }
        )
    mail_rows = await session.execute(select(EmailMessage).order_by(desc(EmailMessage.received_at)).limit(80))
    for row in mail_rows.scalars():
        docs.append(
            {
                "title": f"mail:{row.mailbox}",
                "text": f"{row.subject} from={row.sender} to={row.recipients} summary={row.body_summary}",
            }
        )
    return docs


async def answer_question(session: AsyncSession, question: str) -> str:
    config = await _load_runtime_config(session)
    llm_key = _env_or_config(config, "llm_api_key", "LLM_API_KEY")
    llm_base = (_env_or_config(config, "llm_base_url", "LLM_BASE_URL") or "https://api.openai.com/v1").rstrip("/")
    llm_model = _env_or_config(config, "llm_model", "LLM_MODEL") or "gpt-4o-mini"
    if not llm_key:
        raise RuntimeError("Thiếu LLM API key trong runtime settings hoặc biến môi trường LLM_API_KEY")

    docs = await _fetch_rag_docs(session)
    knowledge_hits = retrieve_knowledge(question, top_k=6)
    ranked = _rerank(question, docs, top_k=10)
    if not ranked:
        ranked = docs[:5]

    indicators = _extract_indicators(question + " " + " ".join(d["text"] for d in ranked[:3]))
    intel = await _threat_intel_bundle(config, indicators, question)

    context_lines = []
    for idx, doc in enumerate(knowledge_hits, start=1):
        context_lines.append(f"[KB{idx}] {doc['title']} ({doc['source']}, score={doc['score']}): {doc['text'][:650]}")
    for idx, doc in enumerate(ranked, start=1):
        context_lines.append(f"[{idx}] {doc['title']}: {doc['text'][:500]}")
    prompt = (
        "You are an AI SOC assistant. Use the provided RAG context and threat intel to answer.\n"
        "Return concise actionable analysis: risk level, evidence, and next actions.\n\n"
        f"Question: {question}\n\n"
        "Hybrid RAG Context (knowledge base + local telemetry):\n"
        + "\n".join(context_lines[:12])
        + "\n\nThreat Intel:\n"
        + json.dumps(intel, ensure_ascii=False)
    )

    payload = {
        "model": llm_model,
        "messages": [
            {"role": "system", "content": "You are a senior SOC analyst assistant."},
            {"role": "user", "content": prompt},
        ],
        "temperature": 0.1,
        "max_tokens": 500,
    }
    try:
        data = await asyncio.to_thread(
            _http_json,
            f"{llm_base}/chat/completions",
            {"Authorization": f"Bearer {llm_key}"},
            payload,
            20.0,
        )
        return data["choices"][0]["message"]["content"].strip()
    except urllib.error.HTTPError as exc:
        body = exc.read().decode("utf-8", errors="ignore")
        raise RuntimeError(f"LLM request failed: HTTP {exc.code} {body[:300]}") from exc
    except Exception as exc:
        raise RuntimeError(f"LLM request failed: {str(exc)}") from exc
