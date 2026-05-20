import ipaddress
import re
from dataclasses import dataclass

from app.models import Severity, SourceType
from app.schemas import EventIn

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b")
HASH_RE = re.compile(r"\b[a-fA-F0-9]{32,64}\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)

CRITICAL_TERMS = ("ransomware", "mimikatz", "credential dumping", "reverse shell", "c2", "exfiltration")
HIGH_TERMS = ("malware", "powershell encodedcommand", "privilege escalation")
MEDIUM_TERMS = ("denied", "blocked", "suspicious", "unauthorized", "invalid user")
SUSPICIOUS_TLDS = (".ru", ".cn", ".top", ".xyz", ".tk")
EXECUTABLE_EXTENSIONS = (".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jar", ".dll")


@dataclass(frozen=True)
class Analysis:
    severity: Severity | None
    message: str
    summary: str
    entities: dict
    rule_name: str | None


@dataclass(frozen=True)
class DetectionRule:
    rule_name: str
    severity: Severity
    message: str
    labels: tuple[str, ...]
    mitre: tuple[str, ...]
    recommendations: tuple[str, ...]
    confidence: float


def summarize(content: str, limit: int = 500) -> str:
    compact = " ".join(content.replace("\x00", " ").split())
    masked = EMAIL_RE.sub("[email]", compact)
    return masked[:limit] + ("..." if len(masked) > limit else "")


def _is_private_ip(value: str) -> bool:
    try:
        return ipaddress.ip_address(value).is_private
    except ValueError:
        return False


def extract_entities(content: str) -> dict:
    ips = sorted(set(IP_RE.findall(content)))[:25]
    return {
        "ips": ips,
        "public_ips": [ip for ip in ips if not _is_private_ip(ip)],
        "private_ips": [ip for ip in ips if _is_private_ip(ip)],
        "domains": sorted(set(DOMAIN_RE.findall(content)))[:25],
        "urls": sorted(set(URL_RE.findall(content)))[:25],
        "hashes": sorted(set(HASH_RE.findall(content)))[:25],
        "emails": sorted(set(EMAIL_RE.findall(content)))[:25],
    }


def _metadata_text(event: EventIn) -> str:
    metadata = event.metadata or {}
    parts: list[str] = []
    for key in ("subject", "sender", "mailbox"):
        if metadata.get(key):
            parts.append(str(metadata[key]))
    for attachment in metadata.get("attachments") or []:
        if isinstance(attachment, dict):
            parts.extend(str(v) for v in attachment.values() if v)
        else:
            parts.append(str(attachment))
    return " ".join(parts)


def _rule(rule: DetectionRule, summary: str, entities: dict) -> Analysis:
    enriched = entities | {
        "threat_labels": list(rule.labels),
        "mitre_techniques": list(rule.mitre),
        "recommendations": list(rule.recommendations),
        "confidence": rule.confidence,
    }
    return Analysis(rule.severity, rule.message, summary, enriched, rule.rule_name)


def _detect_security_rule(event: EventIn, content_lower: str, entities: dict) -> DetectionRule | None:
    metadata_lower = _metadata_text(event).lower()
    combined = f"{content_lower} {metadata_lower}"

    if "ransomware" in combined or "mimikatz" in combined or "credential dumping" in combined:
        return DetectionRule(
            "critical_credential_or_ransomware",
            Severity.Critical,
            "Critical credential theft or ransomware activity detected",
            ("credential_theft", "malware"),
            ("T1003", "T1486"),
            ("isolate affected host", "collect memory and endpoint telemetry", "rotate exposed credentials"),
            0.96,
        )

    failed_login_count = re.search(r"\b([1-9]\d{1,5})\s+(?:failed\s+)?(?:ssh\s+)?login attempts?\b", combined)
    if "brute force" in combined or "failed password" in combined or failed_login_count:
        count = int(failed_login_count.group(1)) if failed_login_count else 1
        severity = Severity.High if count >= 10 or "brute force" in combined else Severity.Medium
        return DetectionRule(
            "auth_brute_force_t1110",
            severity,
            "Brute force authentication activity detected",
            ("brute_force", "authentication_attack"),
            ("T1110",),
            ("enable MFA", "rate-limit login attempts", "block or challenge the source IP", "review successful logins after the attempts"),
            0.92 if severity == Severity.High else 0.78,
        )

    if ("login from russia" in combined or "country" in combined or "geo" in combined) and "admin" in combined:
        return DetectionRule(
            "suspicious_admin_geo_login_t1078",
            Severity.High,
            "Suspicious privileged login from unusual geography detected",
            ("suspicious_login", "valid_account_abuse"),
            ("T1078",),
            ("verify user identity", "enforce conditional access", "reset credentials if activity is unauthorized"),
            0.86,
        )

    if re.search(r"(\bor\b\s+1\s*=\s*1|union\s+select|--|/\*|\bsleep\s*\(|benchmark\s*\()", combined) and (
        "get " in combined or "post " in combined or ".php" in combined or "http" in combined
    ):
        return DetectionRule(
            "web_sql_injection_t1190",
            Severity.High,
            "SQL injection web attack detected",
            ("sql_injection", "web_attack"),
            ("T1190",),
            ("block source IP at WAF", "inspect web logs for data access", "parameterize SQL queries", "add regression tests for the endpoint"),
            0.9,
        )

    if any(ext in combined for ext in EXECUTABLE_EXTENSIONS) and ("download" in combined or "attachment" in combined or event.source_type == SourceType.email):
        label = "malicious_attachment" if "attachment" in combined or event.source_type == SourceType.email else "malware_activity"
        mitre = ("T1566.001", "T1204.002") if event.source_type == SourceType.email else ("T1105", "T1204.002")
        return DetectionRule(
            "malware_executable_delivery",
            Severity.High,
            "Suspicious executable delivery or malware download detected",
            (label, "suspicious_executable"),
            mitre,
            ("quarantine attachment or file", "detonate sample in sandbox", "block related domain or URL", "hunt for execution events"),
            0.89,
        )

    if event.source_type == SourceType.email and (
        "verify your account" in combined
        or "reset your bank" in combined
        or "password immediately" in combined
        or any(url.lower().endswith(SUSPICIOUS_TLDS) for url in entities["urls"])
        or any(domain.lower().endswith(SUSPICIOUS_TLDS) for domain in entities["domains"])
    ):
        return DetectionRule(
            "email_phishing_link_t1566_002",
            Severity.High,
            "Phishing email with suspicious link detected",
            ("phishing", "suspicious_url"),
            ("T1566.002",),
            ("do not click the link", "block URL and sender", "reset exposed credentials", "search mailbox for similar messages"),
            0.88,
        )

    if event.source_type == SourceType.email and (
        "congratulations" in combined or "you won" in combined or "free iphone" in combined or "prize" in combined
    ):
        return DetectionRule(
            "email_spam_scam",
            Severity.Medium,
            "Spam or scam email detected",
            ("spam", "scam"),
            ("T1566",),
            ("move message to spam quarantine", "block sender if repeated", "educate user about prize scam lures"),
            0.75,
        )

    if any(term in combined for term in HIGH_TERMS):
        return DetectionRule(
            "high_risk_keyword",
            Severity.High,
            "High-risk security event detected",
            ("high_risk_keyword",),
            ("T1204",),
            ("triage host and related indicators",),
            0.7,
        )

    if any(term in combined for term in MEDIUM_TERMS) or entities["hashes"]:
        return DetectionRule(
            "indicator_or_medium_keyword",
            Severity.Medium,
            "Suspicious security event detected",
            ("suspicious_activity",),
            (),
            ("review event context",),
            0.6,
        )

    if entities["public_ips"] and any(term in combined for term in ("failed", "denied", "blocked", "unauthorized")):
        return DetectionRule(
            "public_ip_security_indicator",
            Severity.Medium,
            "Security event contains public network indicator",
            ("network_indicator",),
            (),
            ("check IP reputation",),
            0.55,
        )

    return None


def analyze_event(event: EventIn) -> Analysis:
    content_lower = event.content.lower()
    entities = extract_entities(event.content + " " + _metadata_text(event))
    summary = summarize(event.content)

    if any(term in content_lower for term in CRITICAL_TERMS):
        rule = DetectionRule(
            "critical_keyword",
            Severity.Critical,
            "Critical suspicious activity detected",
            ("critical_keyword",),
            (),
            ("start incident response immediately",),
            0.85,
        )
        return _rule(rule, summary, entities)

    security_rule = _detect_security_rule(event, content_lower, entities)
    if security_rule:
        return _rule(security_rule, summary, entities)

    if event.source_type == SourceType.email and (entities["domains"] or "attachment" in content_lower):
        rule = DetectionRule(
            "email_indicator",
            Severity.Low,
            "Email event contains inspectable indicators",
            ("email_indicator",),
            (),
            ("review sender reputation and URL indicators",),
            0.4,
        )
        return _rule(rule, summary, entities)

    return Analysis(
        None,
        "No alert threshold reached",
        summary,
        entities | {"threat_labels": [], "mitre_techniques": [], "recommendations": [], "confidence": 0.0},
        None,
    )
