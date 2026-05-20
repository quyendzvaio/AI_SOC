import re
from collections.abc import Iterable

WORD_RE = re.compile(r"[a-zA-Z0-9_.-]{2,}")

KNOWLEDGE_DOCS: list[dict[str, str]] = [
    {
        "title": "MITRE T1110 Brute Force",
        "source": "mitre_attack",
        "text": "T1110 Brute Force: adversaries try many passwords or keys to gain valid credentials. SOC actions: enable MFA, rate-limit authentication, block suspicious IPs, review successful logins after failures.",
    },
    {
        "title": "MITRE T1078 Valid Accounts",
        "source": "mitre_attack",
        "text": "T1078 Valid Accounts: adversaries use legitimate credentials to access systems. Signals include impossible travel, off-hours admin login, unusual geography, and login after repeated failures.",
    },
    {
        "title": "MITRE T1566.001 Spearphishing Attachment",
        "source": "mitre_attack",
        "text": "T1566.001 Spearphishing Attachment: malicious email attachments such as invoice.exe can establish initial access. Quarantine message, detonate attachment, and hunt for execution.",
    },
    {
        "title": "MITRE T1566.002 Spearphishing Link",
        "source": "mitre_attack",
        "text": "T1566.002 Spearphishing Link: phishing emails lure users to credential theft or malware URLs. Block URL, search similar messages, and reset exposed credentials.",
    },
    {
        "title": "MITRE T1204.002 User Execution Malicious File",
        "source": "mitre_attack",
        "text": "T1204.002 User Execution: adversaries rely on users opening malicious files. Look for .exe, .scr, .js, .vbs, powershell, suspicious download, and follow-up process execution.",
    },
    {
        "title": "MITRE T1190 Exploit Public-Facing Application",
        "source": "mitre_attack",
        "text": "T1190 Exploit Public-Facing Application includes SQL injection and other web exploitation. Review WAF logs, parameterize SQL queries, patch vulnerable apps, and inspect data access.",
    },
    {
        "title": "MITRE T1003 Credential Dumping",
        "source": "mitre_attack",
        "text": "T1003 Credential Dumping includes tools like Mimikatz. Treat as critical, isolate host, collect memory, rotate credentials, and hunt lateral movement.",
    },
    {
        "title": "MITRE T1486 Data Encrypted for Impact",
        "source": "mitre_attack",
        "text": "T1486 ransomware encryption impacts availability. Isolate affected hosts, preserve evidence, disable compromised accounts, and validate backups before recovery.",
    },
    {
        "title": "SOC Playbook Brute Force",
        "source": "playbook",
        "text": "Playbook: confirm event volume and time window, enrich source IP, check successful login after failures, enforce MFA, block source IP if malicious, close as false positive only with owner validation.",
    },
    {
        "title": "SOC Playbook Phishing",
        "source": "playbook",
        "text": "Playbook: inspect sender, SPF/DKIM/DMARC, URLs, attachment hash, and mailbox spread. Quarantine related mail, block indicators, reset credentials, educate user.",
    },
    {
        "title": "SOC Playbook SQL Injection",
        "source": "playbook",
        "text": "Playbook: confirm payload, identify target endpoint, check DB errors and data access, block at WAF, patch input validation, add regression tests.",
    },
    {
        "title": "CVE/NVD Web Exposure Guidance",
        "source": "cve_playbook",
        "text": "For public-facing web alerts, search NVD for framework and endpoint technology, prioritize exploited vulnerabilities, patch exposed services, and monitor exploit attempts.",
    },
]


def tokenize(text: str) -> set[str]:
    return {item.lower() for item in WORD_RE.findall(text)}


def score_doc(query_terms: set[str], doc: dict[str, str]) -> float:
    text = f"{doc['title']} {doc['source']} {doc['text']}"
    terms = tokenize(text)
    overlap = len(query_terms & terms)
    boost = 0
    for term in ("t1110", "t1078", "t1566.001", "t1566.002", "t1204.002", "t1190", "phishing", "brute", "sql"):
        if term in query_terms and term in terms:
            boost += 3
    return float(overlap + boost)


def retrieve_knowledge(query: str, top_k: int = 6, extra_docs: Iterable[dict[str, str]] | None = None) -> list[dict[str, str | float]]:
    query_terms = tokenize(query)
    docs = list(KNOWLEDGE_DOCS)
    if extra_docs:
        docs.extend(extra_docs)
    ranked = sorted(
        ((doc, score_doc(query_terms, doc)) for doc in docs),
        key=lambda item: item[1],
        reverse=True,
    )
    return [
        {"title": doc["title"], "source": doc["source"], "text": doc["text"], "score": score}
        for doc, score in ranked
        if score > 0
    ][:top_k]


def all_knowledge_docs() -> list[dict[str, str]]:
    return list(KNOWLEDGE_DOCS)
