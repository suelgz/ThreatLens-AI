from typing import List

# ─── Severity weights ─────────────────────────────────────────────────────────

SEVERITY_WEIGHTS = {
    "Critical": 40,
    "High":     30,
    "Medium":   18,
    "Low":       8,
    "Informational": 2,
    "Unknown":  10
}

THREAT_MULTIPLIERS = {
    "SQL Injection":             1.4,
    "Command Injection":         1.5,
    "Path Traversal":            1.3,
    "XSS":                       1.2,
    "Brute Force":               1.1,
    "Hardcoded Credentials":     1.3,
    "Weak Cryptography":         1.0,
    "Suspicious User-Agent":     0.9,
    "Sensitive File Access":     1.1,
}

ASSET_SENSITIVITY = {
    "login":     1.3,
    "admin":     1.4,
    "password":  1.4,
    "config":    1.2,
    "database":  1.3,
    "payment":   1.5,
    "default":   1.0
}

SCORE_LABELS = [
    (80, "Critical"),
    (60, "High"),
    (40, "Medium"),
    (20, "Low"),
    (0,  "Informational"),
]


def compute_risk_score(findings: list, rule_findings: list = None) -> tuple[int, str]:
    """
    Compute a 0–100 composite risk score from Gemini findings + rule-based signals.

    Formula:
        base_score  = weighted sum of per-finding severity scores
        confidence  = average Gemini confidence across findings
        frequency   = bonus for many findings (capped)
        asset_sens  = multiplier if sensitive paths are involved
        final_score = clamp(base_score * confidence * asset_sens + frequency_bonus, 0, 100)
    """
    if not findings:
        return 0, "Clean"

    # 1. Base score from Gemini severities
    base = 0
    confidences = []
    asset_bonus = 1.0

    for f in findings:
        severity = f.get("severity", "Unknown")
        sev_score = SEVERITY_WEIGHTS.get(severity, 10)
        threat_type = f.get("threat_type", "")
        multiplier = THREAT_MULTIPLIERS.get(threat_type, 1.0)
        base += sev_score * multiplier

        conf = float(f.get("confidence", 0.5))
        confidences.append(conf)

        # Check evidence/path for asset sensitivity
        evidence = (f.get("evidence", "") + f.get("owasp_category", "")).lower()
        for keyword, sens_mult in ASSET_SENSITIVITY.items():
            if keyword in evidence:
                asset_bonus = max(asset_bonus, sens_mult)

    # 2. Confidence factor (average Gemini confidence)
    avg_confidence = sum(confidences) / len(confidences) if confidences else 0.5

    # 3. Frequency bonus from rule findings
    freq_bonus = 0
    if rule_findings:
        total_flagged = sum(len(r.get("matched_lines", [])) for r in rule_findings)
        freq_bonus = min(total_flagged * 0.3, 12)  # cap at 12 points

    # 4. Pattern score boost from rule findings
    pattern_boost = 0
    if rule_findings:
        max_pattern = max((r.get("pattern_score", 0) for r in rule_findings), default=0)
        pattern_boost = max_pattern * 0.15  # 15% of the max pattern score

    # 5. Final formula
    raw_score = (base * avg_confidence * asset_bonus) + freq_bonus + pattern_boost
    final_score = int(min(max(raw_score, 0), 100))

    # 6. Determine label
    label = "Clean"
    for threshold, lbl in SCORE_LABELS:
        if final_score >= threshold:
            label = lbl
            break

    return final_score, label


def get_severity_color(severity: str) -> str:
    """Return Streamlit-compatible color string for severity badges."""
    colors = {
        "Critical":      "#FF2D2D",
        "High":          "#FF6B35",
        "Medium":        "#FFB700",
        "Low":           "#4CAF50",
        "Informational": "#2196F3",
        "Clean":         "#4CAF50",
    }
    return colors.get(severity, "#888888")


def get_score_breakdown(findings: list, rule_findings: list = None) -> dict:
    """Return a breakdown dict explaining how the score was computed — for display."""
    if not findings:
        return {}

    sev_counts = {}
    for f in findings:
        s = f.get("severity", "Unknown")
        sev_counts[s] = sev_counts.get(s, 0) + 1

    confidences = [float(f.get("confidence", 0.5)) for f in findings]
    avg_conf = round(sum(confidences) / len(confidences), 2) if confidences else 0.5

    freq_count = 0
    if rule_findings:
        freq_count = sum(len(r.get("matched_lines", [])) for r in rule_findings)

    return {
        "finding_count": len(findings),
        "severity_distribution": sev_counts,
        "avg_gemini_confidence": avg_conf,
        "flagged_lines_count": freq_count,
        "rule_threats_detected": len(rule_findings) if rule_findings else 0
    }
