from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any

import pandas as pd


SEVERITY_ORDER = {
    "Critical": 5,
    "High": 4,
    "Medium": 3,
    "Low": 2,
    "Informational": 1,
    "Unknown": 1,
}


THREAT_PROFILES: dict[str, dict[str, Any]] = {
    "SQL Injection": {
        "default_severity": "High",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [
            {
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            },
            {
                "technique_id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
        ],
        "immediate_fix": "Block the malicious request pattern, parameterize the affected query, and review access logs for successful data access.",
        "long_term_fix": "Adopt prepared statements or a safe ORM everywhere, add SQL injection regression tests, and validate input at service boundaries.",
        "business_impact": "A successful SQL injection can expose, modify, or delete business data and may lead to account takeover or regulatory exposure.",
        "false_positive_note": "SQL keywords in documentation, search pages, or analytics URLs can look suspicious; verify whether the input reached a database query.",
    },
    "XSS": {
        "default_severity": "Medium",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [
            {
                "technique_id": "T1189",
                "technique": "Drive-by Compromise",
                "tactic": "Initial Access",
            },
            {
                "technique_id": "T1059.007",
                "technique": "JavaScript",
                "tactic": "Execution",
            },
        ],
        "immediate_fix": "Escape reflected output, strip dangerous HTML attributes, and add a Content Security Policy for the affected page.",
        "long_term_fix": "Use framework-native auto-escaping, centralize sanitization for rich text, and add browser tests for dangerous payloads.",
        "business_impact": "A successful XSS can steal sessions, alter pages, redirect users, or perform actions as a victim.",
        "false_positive_note": "Security tests, escaped examples, and stored documentation may contain script-like text without being executable.",
    },
    "Path Traversal": {
        "default_severity": "High",
        "owasp": "A01:2021 - Broken Access Control",
        "mitre_attack": [
            {
                "technique_id": "T1083",
                "technique": "File and Directory Discovery",
                "tactic": "Discovery",
            },
            {
                "technique_id": "T1005",
                "technique": "Data from Local System",
                "tactic": "Collection",
            },
        ],
        "immediate_fix": "Reject traversal sequences, normalize paths before access, and constrain reads to an allowlisted base directory.",
        "long_term_fix": "Move file access behind a storage service that uses opaque IDs, authorization checks, and canonical path validation.",
        "business_impact": "Attackers may read source code, configuration, credentials, or sensitive customer files from the server.",
        "false_positive_note": "Some clients encode relative paths during normal navigation; confirm whether the requested path maps to a filesystem read.",
    },
    "Brute Force": {
        "default_severity": "Medium",
        "owasp": "A07:2021 - Identification and Authentication Failures",
        "mitre_attack": [
            {
                "technique_id": "T1110",
                "technique": "Brute Force",
                "tactic": "Credential Access",
            },
            {
                "technique_id": "T1078",
                "technique": "Valid Accounts",
                "tactic": "Defense Evasion",
            },
        ],
        "immediate_fix": "Rate-limit the source, lock or challenge repeated failures, and check whether any login succeeded after the failures.",
        "long_term_fix": "Add MFA, credential stuffing protection, breached-password checks, and alerting for anomalous authentication spikes.",
        "business_impact": "Repeated authentication attacks can lead to account compromise, fraud, downtime, and customer trust loss.",
        "false_positive_note": "A broken integration, password reset flow, or shared office IP can generate repeated failures without malicious intent.",
    },
    "Command Injection": {
        "default_severity": "Critical",
        "owasp": "A03:2021 - Injection",
        "mitre_attack": [
            {
                "technique_id": "T1059",
                "technique": "Command and Scripting Interpreter",
                "tactic": "Execution",
            },
            {
                "technique_id": "T1105",
                "technique": "Ingress Tool Transfer",
                "tactic": "Command and Control",
            },
        ],
        "immediate_fix": "Remove shell execution for user-controlled input, deny dangerous metacharacters, and rotate secrets if execution may have succeeded.",
        "long_term_fix": "Replace shell calls with safe library APIs, isolate workers with least privilege, and add command-injection tests to CI.",
        "business_impact": "A successful command injection can give attackers server execution, data theft, malware staging, or full environment takeover.",
        "false_positive_note": "Build scripts and admin tooling may legitimately include shell commands; risk depends on whether user input reaches the command.",
    },
    "Suspicious User-Agent": {
        "default_severity": "Low",
        "owasp": "A05:2021 - Security Misconfiguration",
        "mitre_attack": [
            {
                "technique_id": "T1595",
                "technique": "Active Scanning",
                "tactic": "Reconnaissance",
            },
            {
                "technique_id": "T1592",
                "technique": "Gather Victim Host Information",
                "tactic": "Reconnaissance",
            },
        ],
        "immediate_fix": "Review the source IP and requested paths, block noisy scanners, and verify that sensitive endpoints are not exposed.",
        "long_term_fix": "Tune WAF/bot controls, add scanner allowlists for approved tools, and alert on reconnaissance patterns.",
        "business_impact": "Scanner activity often precedes exploitation and can reveal exposed admin paths, outdated software, or misconfigurations.",
        "false_positive_note": "Internal scanners, uptime monitors, and approved vulnerability assessments may use automated user agents.",
    },
    "Exposed Config Files": {
        "default_severity": "High",
        "owasp": "A05:2021 - Security Misconfiguration",
        "mitre_attack": [
            {
                "technique_id": "T1552.001",
                "technique": "Credentials In Files",
                "tactic": "Credential Access",
            },
            {
                "technique_id": "T1083",
                "technique": "File and Directory Discovery",
                "tactic": "Discovery",
            },
        ],
        "immediate_fix": "Remove the exposed file, block access at the web server, and rotate any credentials that may have been disclosed.",
        "long_term_fix": "Keep secrets outside the web root, enforce deployment deny rules for config files, and add secret scanning to CI.",
        "business_impact": "Exposed configuration can leak credentials, internal topology, API keys, and database connection details.",
        "false_positive_note": "Requests for non-existent files may be generic internet noise; verify server response status and whether content was returned.",
    },
    "Sensitive File Access": {
        "default_severity": "Medium",
        "owasp": "A05:2021 - Security Misconfiguration",
        "mitre_attack": [
            {
                "technique_id": "T1005",
                "technique": "Data from Local System",
                "tactic": "Collection",
            },
            {
                "technique_id": "T1083",
                "technique": "File and Directory Discovery",
                "tactic": "Discovery",
            },
        ],
        "immediate_fix": "Confirm whether the file exists, block direct access, and review responses for successful downloads.",
        "long_term_fix": "Harden web server file exposure rules and add deployment checks for backups, dumps, and hidden directories.",
        "business_impact": "Sensitive files can disclose source code, backups, database dumps, or operational secrets.",
        "false_positive_note": "Mass scanners often probe common paths that do not exist; treat 404-only traffic as lower confidence.",
    },
    "Hardcoded Credentials": {
        "default_severity": "High",
        "owasp": "A02:2021 - Cryptographic Failures",
        "mitre_attack": [
            {
                "technique_id": "T1552.001",
                "technique": "Credentials In Files",
                "tactic": "Credential Access",
            },
            {
                "technique_id": "T1555",
                "technique": "Credentials from Password Stores",
                "tactic": "Credential Access",
            },
        ],
        "immediate_fix": "Remove the secret from code, rotate the exposed value, and invalidate any tokens already deployed.",
        "long_term_fix": "Move secrets to a managed vault or environment-specific secret store and enforce automated secret scanning.",
        "business_impact": "Hardcoded secrets can let attackers access databases, cloud resources, APIs, or administrative functions.",
        "false_positive_note": "Test fixtures and placeholders can match secret patterns; confirm whether the value is live, long-lived, or production scoped.",
    },
    "Weak Cryptography": {
        "default_severity": "Medium",
        "owasp": "A02:2021 - Cryptographic Failures",
        "mitre_attack": [
            {
                "technique_id": "T1552",
                "technique": "Unsecured Credentials",
                "tactic": "Credential Access",
            },
            {
                "technique_id": "T1600",
                "technique": "Weaken Encryption",
                "tactic": "Defense Evasion",
            },
        ],
        "immediate_fix": "Stop using broken algorithms for security decisions and replace weak hashes or ciphers in the affected code path.",
        "long_term_fix": "Standardize on vetted crypto libraries, modern TLS settings, password hashing with Argon2/bcrypt/scrypt, and crypto reviews.",
        "business_impact": "Weak cryptography can expose passwords, tokens, or sensitive data to offline cracking or downgrade attacks.",
        "false_positive_note": "MD5 or SHA1 may be acceptable for non-security checksums; verify whether the algorithm protects secrets or integrity.",
    },
    "Other": {
        "default_severity": "Informational",
        "owasp": "A04:2021 - Insecure Design",
        "mitre_attack": [
            {
                "technique_id": "T1190",
                "technique": "Exploit Public-Facing Application",
                "tactic": "Initial Access",
            }
        ],
        "immediate_fix": "Review the evidence and apply a targeted mitigation for the affected component.",
        "long_term_fix": "Add the scenario to secure design reviews, tests, monitoring, and incident response playbooks.",
        "business_impact": "Unclassified security issues can still affect availability, confidentiality, or integrity if left unreviewed.",
        "false_positive_note": "Manual validation is required because this finding does not map cleanly to a known detector.",
    },
}


ALIASES = {
    "scanner activity": "Suspicious User-Agent",
    "suspicious scanner tools": "Suspicious User-Agent",
    "sensitive file": "Sensitive File Access",
    "sensitive file access": "Sensitive File Access",
    "exposed config": "Exposed Config Files",
    "exposed config file": "Exposed Config Files",
    "exposed configuration": "Exposed Config Files",
    "broken auth": "Brute Force",
    "credential stuffing": "Brute Force",
    "sql injection": "SQL Injection",
    "sqli": "SQL Injection",
    "cross-site scripting": "XSS",
    "cross site scripting": "XSS",
    "xss": "XSS",
}


def normalize_threat_type(threat_type: str | None) -> str:
    if not threat_type:
        return "Other"
    cleaned = str(threat_type).strip()
    lowered = cleaned.lower()
    if lowered in ALIASES:
        return ALIASES[lowered]
    for known in THREAT_PROFILES:
        if known.lower() == lowered:
            return known
    return cleaned if cleaned in THREAT_PROFILES else "Other"


def get_threat_profile(threat_type: str | None) -> dict[str, Any]:
    normalized = normalize_threat_type(threat_type)
    return THREAT_PROFILES.get(normalized, THREAT_PROFILES["Other"])


def format_mitre_attack(mitre_attack: Any) -> str:
    mappings = _coerce_mitre_list(mitre_attack)
    if not mappings:
        return "N/A"
    parts = []
    for item in mappings:
        technique_id = item.get("technique_id", "")
        technique = item.get("technique", "")
        tactic = item.get("tactic", "")
        label = " ".join(part for part in [technique_id, technique] if part)
        parts.append(f"{label} ({tactic})" if tactic else label)
    return "; ".join(parts)


def enrich_finding(finding: dict[str, Any], rule_context: dict[str, Any] | None = None) -> dict[str, Any]:
    enriched = dict(finding)
    threat_type = normalize_threat_type(enriched.get("threat_type"))
    profile = get_threat_profile(threat_type)

    enriched["threat_type"] = threat_type
    enriched.setdefault("threat_detected", True)
    enriched["severity"] = enriched.get("severity") or profile["default_severity"]
    enriched["owasp_category"] = enriched.get("owasp_category") or profile["owasp"]
    enriched["mitre_attack"] = _coerce_mitre_list(enriched.get("mitre_attack")) or profile["mitre_attack"]
    enriched["mitre_attack_summary"] = format_mitre_attack(enriched["mitre_attack"])

    if rule_context:
        enriched["pattern_score"] = max(
            int(enriched.get("pattern_score", 0) or 0),
            int(rule_context.get("pattern_score", 0) or 0),
        )
        enriched["rule_confidence"] = max(
            float(enriched.get("rule_confidence", 0) or 0),
            float(rule_context.get("rule_confidence", rule_context.get("confidence", 0)) or 0),
        )
        if not enriched.get("matched_lines"):
            enriched["matched_lines"] = rule_context.get("matched_lines", [])
        if not enriched.get("evidence"):
            enriched["evidence"] = "\n".join(rule_context.get("matched_lines", [])[:3])

    if "confidence" not in enriched or enriched.get("confidence") in ("", None):
        enriched["confidence"] = enriched.get("rule_confidence", 0.5)

    enriched["immediate_fix"] = enriched.get("immediate_fix") or profile["immediate_fix"]
    enriched["long_term_fix"] = enriched.get("long_term_fix") or profile["long_term_fix"]
    enriched["business_impact"] = enriched.get("business_impact") or profile["business_impact"]
    enriched["false_positive_note"] = enriched.get("false_positive_note") or profile["false_positive_note"]

    if not enriched.get("recommended_fix"):
        enriched["recommended_fix"] = (
            f"Immediate fix: {enriched['immediate_fix']} "
            f"Long-term fix: {enriched['long_term_fix']}"
        )

    return enriched


def merge_rule_and_gemini_findings(
    gemini_findings: list[dict[str, Any]],
    rule_findings: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    rule_findings = rule_findings or []
    rule_by_type = {
        normalize_threat_type(rule.get("threat_type")): rule
        for rule in rule_findings
    }

    merged: list[dict[str, Any]] = []
    covered_types: set[str] = set()

    for finding in gemini_findings or []:
        threat_type = normalize_threat_type(finding.get("threat_type"))
        covered_types.add(threat_type)
        enriched = enrich_finding(finding, rule_by_type.get(threat_type))
        enriched.setdefault("analysis_source", "Gemini AI + Rule Engine" if threat_type in rule_by_type else "Gemini AI")
        merged.append(enriched)

    for rule in rule_findings:
        threat_type = normalize_threat_type(rule.get("threat_type"))
        if threat_type in covered_types:
            continue
        rule_only = enrich_finding(rule)
        rule_only["analysis_source"] = "Rule Engine"
        rule_only["severity"] = rule_only.get("severity") or _severity_from_pattern_score(rule_only.get("pattern_score", 0))
        rule_only.setdefault("explanation", f"Rule engine matched indicators for {threat_type}.")
        rule_only.setdefault("evidence", "\n".join(rule_only.get("matched_lines", [])[:3]))
        merged.append(rule_only)

    return sorted(merged, key=_finding_sort_key, reverse=True)


def generate_top_recommendations(findings: list[dict[str, Any]], limit: int = 5) -> list[str]:
    recommendations = []
    seen: set[str] = set()
    for finding in sorted(findings or [], key=_finding_sort_key, reverse=True):
        threat_type = normalize_threat_type(finding.get("threat_type"))
        if threat_type in seen:
            continue
        seen.add(threat_type)
        severity = finding.get("severity", get_threat_profile(threat_type)["default_severity"])
        immediate_fix = finding.get("immediate_fix") or get_threat_profile(threat_type)["immediate_fix"]
        impact = finding.get("business_impact") or get_threat_profile(threat_type)["business_impact"]
        recommendations.append(f"[{severity}] {threat_type}: {immediate_fix} Business impact: {impact}")
        if len(recommendations) >= limit:
            break
    return recommendations


def build_attack_timeline(
    df: pd.DataFrame,
    rule_findings: list[dict[str, Any]],
    limit: int = 25,
) -> list[dict[str, Any]]:
    if df is None or df.empty or not rule_findings or "raw" not in df.columns:
        return []

    raw_to_threats: dict[str, list[str]] = {}
    for finding in rule_findings:
        threat_type = normalize_threat_type(finding.get("threat_type"))
        for raw in finding.get("flagged_raw", []) or finding.get("matched_lines", []):
            raw_to_threats.setdefault(raw, []).append(threat_type)

    timeline = []
    for _, row in df.iterrows():
        raw = row.get("raw", "")
        threats = raw_to_threats.get(raw, [])
        if not threats:
            continue

        timestamp_raw = str(row.get("time", "") or _extract_timestamp(raw) or "").strip()
        parsed_timestamp = _parse_timestamp(timestamp_raw)
        if not timestamp_raw and parsed_timestamp is None:
            continue

        for threat in sorted(set(threats)):
            timeline.append({
                "timestamp": timestamp_raw or parsed_timestamp.isoformat(),
                "sort_time": parsed_timestamp.isoformat() if parsed_timestamp else "",
                "source_ip": row.get("ip", ""),
                "threat_type": threat,
                "method": row.get("method", ""),
                "path": row.get("path", ""),
                "status": row.get("status", ""),
                "evidence": raw,
            })

    timeline.sort(key=lambda item: item.get("sort_time") or item.get("timestamp") or "")
    for item in timeline:
        item.pop("sort_time", None)
    return timeline[:limit]


def _coerce_mitre_list(mitre_attack: Any) -> list[dict[str, str]]:
    if not mitre_attack:
        return []
    if isinstance(mitre_attack, list):
        normalized = []
        for item in mitre_attack:
            if isinstance(item, dict):
                normalized.append({
                    "technique_id": str(item.get("technique_id", "")),
                    "technique": str(item.get("technique", "")),
                    "tactic": str(item.get("tactic", "")),
                })
            elif isinstance(item, str):
                normalized.append({"technique_id": item, "technique": "", "tactic": ""})
        return normalized
    if isinstance(mitre_attack, dict):
        return [_coerce_mitre_list([mitre_attack])[0]]
    if isinstance(mitre_attack, str):
        try:
            parsed = json.loads(mitre_attack)
            return _coerce_mitre_list(parsed)
        except json.JSONDecodeError:
            pass
        return [{"technique_id": mitre_attack, "technique": "", "tactic": ""}]
    return []


def _finding_sort_key(finding: dict[str, Any]) -> tuple[float, float, float]:
    severity = SEVERITY_ORDER.get(finding.get("severity", "Unknown"), 1)
    confidence = float(finding.get("confidence", finding.get("rule_confidence", 0.5)) or 0)
    pattern_score = float(finding.get("pattern_score", 0) or 0)
    return severity, confidence, pattern_score


def _severity_from_pattern_score(score: int | float) -> str:
    score = float(score or 0)
    if score >= 70:
        return "Critical"
    if score >= 55:
        return "High"
    if score >= 35:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Informational"


def _extract_timestamp(raw: str) -> str:
    patterns = [
        r"\[(?P<ts>\d{1,2}/[A-Za-z]{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\]",
        r"(?P<ts>\d{4}-\d{2}-\d{2}[T\s]\d{2}:\d{2}:\d{2}(?:Z|[+-]\d{2}:?\d{2})?)",
        r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})",
    ]
    for pattern in patterns:
        match = re.search(pattern, raw)
        if match:
            return match.group("ts")
    return ""


def _parse_timestamp(timestamp: str) -> datetime | None:
    if not timestamp:
        return None
    candidates = [
        "%d/%b/%Y:%H:%M:%S %z",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d %H:%M:%S%z",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%d %H:%M:%S",
        "%b %d %H:%M:%S",
    ]
    normalized = timestamp.replace("+0000", "+00:00") if timestamp.endswith("+0000") else timestamp
    for fmt in candidates:
        try:
            parsed = datetime.strptime(normalized, fmt)
            if fmt == "%b %d %H:%M:%S":
                parsed = parsed.replace(year=datetime.now().year)
            return parsed
        except ValueError:
            continue
    return None
