import re
import pandas as pd
from collections import defaultdict

# ─── Attack Signature Patterns ────────────────────────────────────────────────

PATTERNS = {
    "SQL Injection": {
        "patterns": [
            r"(?i)(union\s+select|select\s+.+from|insert\s+into|drop\s+table|delete\s+from)",
            r"(?i)('|\%27)\s*(or|and)\s*('|\%27)?\s*\d",
            r"(?i)(--\s*$|;\s*--|\%23|\%27|\%22)",
            r"(?i)(sleep\s*\(|benchmark\s*\(|waitfor\s+delay)",
            r"(?i)(1\s*=\s*1|1\s*=\s*'1'|or\s+1\s*=\s*1)",
            r"(?i)(\bor\b|\band\b).{0,20}(=|like|<|>)",
        ],
        "score": 40,
        "owasp": "A03:2021 – Injection"
    },
    "XSS": {
        "patterns": [
            r"(?i)<\s*script[\s>]",
            r"(?i)javascript\s*:",
            r"(?i)on(load|click|mouseover|error|focus|blur)\s*=",
            r"(?i)<\s*img[^>]+onerror\s*=",
            r"(?i)(alert|confirm|prompt)\s*\(",
            r"(?i)<\s*iframe",
        ],
        "score": 35,
        "owasp": "A03:2021 – Injection"
    },
    "Path Traversal": {
        "patterns": [
            r"(?i)(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e/|\.\.%2f)",
            r"(?i)(\/etc\/passwd|\/etc\/shadow|\/windows\/win\.ini|\/boot\.ini)",
            r"(?i)(file\s*=|page\s*=|include\s*=).{0,5}(\.\.|%2e%2e)",
        ],
        "score": 38,
        "owasp": "A01:2021 – Broken Access Control"
    },
    "Brute Force": {
        "patterns": [],   # Detected by frequency analysis below
        "score": 30,
        "owasp": "A07:2021 – Identification and Authentication Failures"
    },
    "Suspicious User-Agent": {
        "patterns": [
            r"(?i)(sqlmap|nikto|nmap|masscan|nessus|openvas|acunetix|burpsuite|dirbuster|gobuster|hydra|medusa|metasploit|havij|w3af)",
            r"(?i)(scanner|crawler|exploit|attack|hack|vuln)",
            r"(?i)(python-requests|libwww-perl|curl\/[0-9])",
        ],
        "score": 25,
        "owasp": "A05:2021 – Security Misconfiguration"
    },
    "Sensitive File Access": {
        "patterns": [
            r"(?i)(\.env|config\.php\.bak|\.git\/|web\.config|\.htpasswd|\.htaccess|wp-config\.php)",
            r"(?i)(phpMyAdmin|phpmyadmin|adminer\.php|setup-config\.php)",
            r"(?i)(backup\.sql|dump\.sql|database\.sql)",
        ],
        "score": 30,
        "owasp": "A05:2021 – Security Misconfiguration"
    },
    "Command Injection": {
        "patterns": [
            r"(?i)(\||\;|\`|\$\()\s*(ls|cat|whoami|id|pwd|wget|curl|bash|sh|nc|ncat)",
            r"(?i)(system\s*\(|exec\s*\(|shell_exec\s*\(|passthru\s*\(|popen\s*\()",
            r"(?i)(subprocess\.run|subprocess\.call|os\.system|os\.popen)",
        ],
        "score": 45,
        "owasp": "A03:2021 – Injection"
    },
    "Hardcoded Credentials": {
        "patterns": [
            r"(?i)(password\s*=\s*[\"'][^\"']{3,}[\"'])",
            r"(?i)(secret\s*=\s*[\"'][^\"']{3,}[\"'])",
            r"(?i)(api_key\s*=\s*[\"'][^\"']{8,}[\"'])",
            r"(?i)(passwd\s*=\s*[\"'][^\"']{3,}[\"'])",
        ],
        "score": 35,
        "owasp": "A02:2021 – Cryptographic Failures"
    },
    "Weak Cryptography": {
        "patterns": [
            r"(?i)\bmd5\s*\(",
            r"(?i)\bsha1\s*\(",
            r"(?i)\bdes\b|\b3des\b|\brc4\b",
        ],
        "score": 25,
        "owasp": "A02:2021 – Cryptographic Failures"
    },
}

# ─── Brute Force Detection ─────────────────────────────────────────────────────

BRUTE_FORCE_THRESHOLD = 5   # same IP + same path + 401/403 within log window
BRUTE_FORCE_MIN_FAILS = 5

def detect_brute_force(df: pd.DataFrame) -> list[dict]:
    """Detect brute force by counting 401/403 responses per IP per path."""
    findings = []
    if "ip" not in df.columns or "status" not in df.columns:
        return findings

    fail_df = df[df["status"].isin([401, 403])].copy()
    if fail_df.empty:
        return findings

    groups = fail_df.groupby(["ip", "path"]).size().reset_index(name="count")
    brute = groups[groups["count"] >= BRUTE_FORCE_MIN_FAILS]

    for _, row in brute.iterrows():
        findings.append({
            "threat_type": "Brute Force",
            "pattern_score": PATTERNS["Brute Force"]["score"],
            "owasp_category": PATTERNS["Brute Force"]["owasp"],
            "matched_lines": [
                f"IP {row['ip']} made {row['count']} failed login attempts on {row['path']}"
            ],
            "flagged_raw": [
                r["raw"] for _, r in fail_df[
                    (fail_df["ip"] == row["ip"]) & (fail_df["path"] == row["path"])
                ].head(10).iterrows()
            ]
        })
    return findings

# ─── Main Detection Function ───────────────────────────────────────────────────

def run_rule_detection(df: pd.DataFrame, raw_text: str = "") -> list[dict]:
    """
    Run all rule-based detectors on a DataFrame (from log) or raw text (from code).
    Returns a list of finding dicts with matched lines.
    """
    findings = []
    scan_text = raw_text

    # If it's a log DataFrame, also build a combined text for pattern scanning
    if not df.empty and "raw" in df.columns:
        scan_lines = df["raw"].tolist()
    else:
        scan_lines = raw_text.splitlines()

    # Per-pattern scanning
    threat_hits: dict[str, dict] = defaultdict(lambda: {"matched_lines": [], "pattern_score": 0, "owasp_category": ""})

    for threat_name, cfg in PATTERNS.items():
        if threat_name == "Brute Force":
            continue  # handled separately

        for line in scan_lines:
            for pattern in cfg["patterns"]:
                if re.search(pattern, line):
                    threat_hits[threat_name]["matched_lines"].append(line)
                    threat_hits[threat_name]["pattern_score"] = cfg["score"]
                    threat_hits[threat_name]["owasp_category"] = cfg["owasp"]
                    break  # one match per line per threat is enough

    for threat_name, data in threat_hits.items():
        if data["matched_lines"]:
            findings.append({
                "threat_type": threat_name,
                "pattern_score": data["pattern_score"],
                "owasp_category": data["owasp_category"],
                "matched_lines": list(set(data["matched_lines"]))[:20],  # deduplicate, cap at 20
                "flagged_raw": list(set(data["matched_lines"]))[:20]
            })

    # Brute force (log only)
    if not df.empty:
        findings.extend(detect_brute_force(df))

    return findings

def get_flagged_content_for_gemini(findings: list[dict], max_chars: int = 3000) -> str:
    """Bundle flagged lines into a compact string for Gemini prompt."""
    parts = []
    total = 0
    for f in findings:
        header = f"[{f['threat_type']}]"
        for line in f.get("flagged_raw", []):
            entry = f"{header} {line}\n"
            if total + len(entry) > max_chars:
                break
            parts.append(entry)
            total += len(entry)
    return "".join(parts)

def summarize_rule_findings(findings: list[dict]) -> str:
    """Human-readable summary of rule-based findings for Gemini context."""
    if not findings:
        return "No suspicious patterns detected by rule-based filter."
    lines = []
    for f in findings:
        lines.append(
            f"- {f['threat_type']}: {len(f.get('matched_lines', []))} line(s) flagged "
            f"(pattern score: {f['pattern_score']}, {f['owasp_category']})"
        )
    return "\n".join(lines)
