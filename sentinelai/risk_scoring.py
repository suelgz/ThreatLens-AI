from __future__ import annotations


SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High": 30,
    "Medium": 18,
    "Low": 8,
    "Informational": 2,
    "Unknown": 10,
}

THREAT_MULTIPLIERS = {
    "Command Injection": 1.5,
    "SQL Injection": 1.4,
    "Hardcoded Credentials": 1.3,
    "Path Traversal": 1.3,
    "Exposed Config Files": 1.3,
    "XSS": 1.2,
    "Brute Force": 1.1,
    "Sensitive File Access": 1.1,
    "Weak Cryptography": 1.0,
    "Suspicious User-Agent": 0.9,
}

ASSET_SENSITIVITY = {
    "login": 1.3,
    "admin": 1.4,
    "password": 1.4,
    "config": 1.2,
    "database": 1.3,
    "payment": 1.5,
    "secret": 1.4,
    "token": 1.3,
    "default": 1.0,
}

SCORE_LABELS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0, "Informational"),
]


def compute_risk_score(findings: list, rule_findings: list | None = None) -> tuple[int, str]:
    """
    Compute a 0-100 composite risk score from Gemini findings and rule signals.

    The score now accounts for rule confidence and pattern strength, so high-risk
    rule-only detections still influence the final risk posture.
    """
    rule_findings = rule_findings or []
    findings = findings or []

    if not findings and not rule_findings:
        return 0, "Clean"

    base = 0.0
    confidences: list[float] = []
    asset_bonus = 1.0

    for finding in findings:
        severity = finding.get("severity", "Unknown")
        threat_type = finding.get("threat_type", "")
        severity_score = SEVERITY_WEIGHTS.get(severity, 10)
        multiplier = THREAT_MULTIPLIERS.get(threat_type, 1.0)
        confidence = max(
            float(finding.get("confidence", 0.5) or 0.5),
            float(finding.get("rule_confidence", 0) or 0),
        )
        base += severity_score * multiplier
        confidences.append(confidence)
        asset_bonus = max(asset_bonus, _asset_sensitivity(finding))

    if not findings and rule_findings:
        for rule in rule_findings:
            threat_type = rule.get("threat_type", "")
            multiplier = THREAT_MULTIPLIERS.get(threat_type, 1.0)
            confidence = float(rule.get("rule_confidence", rule.get("confidence", 0.5)) or 0.5)
            pattern_score = float(rule.get("pattern_score", 0) or 0)
            base += min(pattern_score, 75) * multiplier * 0.55
            confidences.append(confidence)
            asset_bonus = max(asset_bonus, _asset_sensitivity(rule))

    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5

    total_flagged = sum(len(rule.get("matched_lines", [])) for rule in rule_findings)
    frequency_bonus = min(total_flagged * 0.3, 12)

    pattern_boost = 0.0
    if rule_findings:
        max_pattern = max((rule.get("pattern_score", 0) for rule in rule_findings), default=0)
        avg_rule_confidence = sum(
            float(rule.get("rule_confidence", rule.get("confidence", 0.5)) or 0.5)
            for rule in rule_findings
        ) / len(rule_findings)
        pattern_boost = max_pattern * 0.12 * avg_rule_confidence

    raw_score = (base * avg_confidence * asset_bonus) + frequency_bonus + pattern_boost
    final_score = int(min(max(raw_score, 0), 100))

    label = "Clean"
    for threshold, severity_label in SCORE_LABELS:
        if final_score >= threshold:
            label = severity_label
            break

    return final_score, label


def get_severity_color(severity: str) -> str:
    """Return Streamlit-compatible color string for severity badges."""
    colors = {
        "Critical": "#FF2D2D",
        "High": "#FF6B35",
        "Medium": "#FFB700",
        "Low": "#4CAF50",
        "Informational": "#2196F3",
        "Clean": "#4CAF50",
    }
    return colors.get(severity, "#888888")


def get_score_breakdown(findings: list, rule_findings: list | None = None) -> dict:
    """Return a display-friendly breakdown of score inputs."""
    findings = findings or []
    rule_findings = rule_findings or []

    if not findings and not rule_findings:
        return {}

    severity_counts: dict[str, int] = {}
    for finding in findings or rule_findings:
        severity = finding.get("severity", "Unknown")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

    confidences = [
        max(float(f.get("confidence", 0.5) or 0.5), float(f.get("rule_confidence", 0) or 0))
        for f in findings
    ]
    avg_confidence = round(sum(confidences) / len(confidences), 2) if confidences else 0.5

    rule_confidences = [
        float(rule.get("rule_confidence", rule.get("confidence", 0.5)) or 0.5)
        for rule in rule_findings
    ]
    avg_rule_confidence = (
        round(sum(rule_confidences) / len(rule_confidences), 2)
        if rule_confidences else 0
    )

    return {
        "finding_count": len(findings),
        "severity_distribution": severity_counts,
        "avg_gemini_confidence": avg_confidence,
        "avg_rule_confidence": avg_rule_confidence,
        "flagged_lines_count": sum(len(rule.get("matched_lines", [])) for rule in rule_findings),
        "rule_threats_detected": len(rule_findings),
    }


def _asset_sensitivity(finding: dict) -> float:
    evidence = " ".join([
        str(finding.get("evidence", "")),
        str(finding.get("owasp_category", "")),
        " ".join(finding.get("matched_lines", []) or []),
    ]).lower()
    asset_bonus = 1.0
    for keyword, multiplier in ASSET_SENSITIVITY.items():
        if keyword != "default" and keyword in evidence:
            asset_bonus = max(asset_bonus, multiplier)
    return asset_bonus
