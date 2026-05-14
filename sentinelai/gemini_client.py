import json
import re
from google import genai
from google.genai import types

MODEL_NAME = "gemini-2.0-flash"

def _get_client(api_key: str):
    return genai.Client(api_key=api_key)

def _extract_json(text: str):
    """Robustly extract JSON from Gemini output even if it wraps in markdown fences."""
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        for start_char, end_char in [("[", "]"), ("{", "}")]:
            start = text.find(start_char)
            end = text.rfind(end_char)
            if start != -1 and end != -1:
                try:
                    return json.loads(text[start:end+1])
                except json.JSONDecodeError:
                    continue
    return None

LOG_ANALYSIS_PROMPT = """You are SentinelAI, a senior cybersecurity analyst embedded in a threat detection system.

Analyze the following security log entries pre-flagged as suspicious by an automated rule-based filter.

FLAGGED LOG ENTRIES:
{log_content}

PRE-DETECTION LABELS (from rule-based filter):
{pre_labels}

Perform deep analysis and return a structured JSON array. Each element is one threat finding.

RULES:
- Respond ONLY with valid JSON array. No markdown, no extra text.
- If no real threats, return: []
- Quote exact suspicious log entry in evidence field.
- Explanation must be understandable by a junior analyst.
- recommended_fix must be practical and specific.

Return exactly this structure:
[
  {{
    "threat_detected": true,
    "threat_type": "SQL Injection | XSS | Brute Force | Path Traversal | Command Injection | Suspicious User-Agent | Sensitive File Access | Other",
    "severity": "Critical | High | Medium | Low | Informational",
    "confidence": 0.0,
    "evidence": "exact log line that triggered this",
    "explanation": "clear explanation of what this attack is and why it is dangerous",
    "owasp_category": "A03:2021 - Injection",
    "recommended_fix": "specific steps to block or mitigate this threat",
    "business_impact": "what damage could occur if this attack succeeds",
    "false_positive_note": "when this might be a false positive"
  }}
]"""

CODE_ANALYSIS_PROMPT = """You are SentinelAI, a senior application security engineer specializing in OWASP vulnerabilities.

Analyze the following code snippet for security vulnerabilities.

LANGUAGE: {language}

CODE:
{code_snippet}

PRE-DETECTED PATTERNS (from static analysis):
{pre_labels}

RULES:
- Respond ONLY with valid JSON array. No markdown, no extra text outside JSON.
- Each vulnerability is a separate object in the array.
- Include exact vulnerable line(s) in evidence.
- recommended_fix must include a corrected code example where possible.
- If code is secure, return: []

Return exactly this structure:
[
  {{
    "threat_detected": true,
    "threat_type": "SQL Injection | XSS | CSRF | Command Injection | Path Traversal | Hardcoded Credentials | Insecure Deserialization | Weak Cryptography | Broken Auth | Other",
    "severity": "Critical | High | Medium | Low | Informational",
    "confidence": 0.0,
    "evidence": "exact vulnerable line(s) from the code",
    "explanation": "why this code is vulnerable and how an attacker could exploit it",
    "owasp_category": "A03:2021 - Injection",
    "recommended_fix": "corrected code or specific fix instructions",
    "business_impact": "real-world consequence if this vulnerability is exploited",
    "false_positive_note": "conditions under which this would actually be safe"
  }}
]"""

EXECUTIVE_SUMMARY_PROMPT = """You are SentinelAI generating an executive security report for a non-technical business audience.

ANALYSIS FINDINGS:
{findings_json}

OVERALL RISK SCORE: {risk_score}/100
SEVERITY LABEL: {severity_label}

Write a clear executive summary that a CEO or business manager can act on.

RULES:
- Respond ONLY with valid JSON object. No markdown, no text outside JSON.
- Use plain language. Avoid jargon.
- Be honest about risk level.

Return exactly this structure:
{{
  "overall_status": "Critical | High Risk | Medium Risk | Low Risk | Clean",
  "summary_paragraph": "2-3 sentence plain-English summary of the security situation",
  "top_priority_action": "the single most important thing to do right now",
  "estimated_business_risk": "description of potential damage if issues are not addressed within 48 hours",
  "positive_notes": "any strengths or reassuring context",
  "recommended_next_steps": ["step 1", "step 2", "step 3"]
}}"""

TURKISH_EXPLANATION_PROMPT = """Sen SentinelAI'sin. Teknik bilgisi olmayan kullanicilaratilgisiz Turk dili ile siber guvenlik analizi yapan bir asistansin.

Asagidaki teknik guvenlik bulgusunu Turkce olarak acikla. Hedef kitle: kucuk isletme sahibi veya teknik olmayan yonetici.

TEKNIK BULGU:
{technical_finding}

KURAL:
- Sadece gecerli JSON dondur. JSON disinda hicbir metin olmasin.

Bu yapiyi dondur:
{{
  "basit_aciklama": "Teknik olmayan birinin anlayacagi sade Turkce aciklama",
  "tehlike_seviyesi": "Kritik | Yuksek | Orta | Dusuk",
  "ne_olabilir": "Bu acik kotüye kullanilirsa ne olur (somut senaryo)",
  "hemen_yapilacaklar": ["adim 1", "adim 2", "adim 3"],
  "is_etkisi": "Bu guvenlik acigi isletmenize nasil zarar verebilir"
}}"""


def _call_gemini(api_key: str, prompt: str) -> str:
    client = _get_client(api_key)
    response = client.models.generate_content(
        model=MODEL_NAME,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            max_output_tokens=4096,
        )
    )
    return response.text


def analyze_logs(log_content: str, pre_labels: str, api_key: str) -> list:
    prompt = LOG_ANALYSIS_PROMPT.format(
        log_content=log_content[:4000],
        pre_labels=pre_labels
    )
    try:
        text = _call_gemini(api_key, prompt)
        result = _extract_json(text)
        return result if isinstance(result, list) else []
    except Exception as e:
        return [_error_finding(str(e))]


def analyze_code(code_snippet: str, language: str, pre_labels: str, api_key: str) -> list:
    prompt = CODE_ANALYSIS_PROMPT.format(
        language=language,
        code_snippet=code_snippet[:4000],
        pre_labels=pre_labels
    )
    try:
        text = _call_gemini(api_key, prompt)
        result = _extract_json(text)
        return result if isinstance(result, list) else []
    except Exception as e:
        return [_error_finding(str(e))]


def generate_executive_summary(findings: list, risk_score: int, severity_label: str, api_key: str) -> dict:
    prompt = EXECUTIVE_SUMMARY_PROMPT.format(
        findings_json=json.dumps(findings, indent=2)[:3000],
        risk_score=risk_score,
        severity_label=severity_label
    )
    try:
        text = _call_gemini(api_key, prompt)
        result = _extract_json(text)
        return result if isinstance(result, dict) else _default_summary(severity_label)
    except Exception as e:
        return _default_summary(severity_label, str(e))


def translate_to_turkish(finding: dict, api_key: str) -> dict:
    prompt = TURKISH_EXPLANATION_PROMPT.format(
        technical_finding=json.dumps(finding, indent=2, ensure_ascii=False)[:2000]
    )
    try:
        text = _call_gemini(api_key, prompt)
        result = _extract_json(text)
        return result if isinstance(result, dict) else {}
    except Exception as e:
        return {"error": str(e)}


def test_api_key(api_key: str) -> tuple:
    try:
        client = _get_client(api_key)
        resp = client.models.generate_content(
            model=MODEL_NAME,
            contents="Reply with the single word: OK"
        )
        return True, resp.text.strip()
    except Exception as e:
        return False, str(e)


def _error_finding(error_msg: str) -> dict:
    return {
        "threat_detected": False, "threat_type": "API Error",
        "severity": "Unknown", "confidence": 0,
        "evidence": "", "explanation": f"Gemini API error: {error_msg}",
        "owasp_category": "", "recommended_fix": "Check your API key and try again.",
        "business_impact": "", "false_positive_note": ""
    }


def _default_summary(severity_label: str, error: str = "") -> dict:
    return {
        "overall_status": severity_label,
        "summary_paragraph": f"Analysis completed with severity: {severity_label}. {error}",
        "top_priority_action": "Review findings in detail.",
        "estimated_business_risk": "Unknown — please review manually.",
        "positive_notes": "",
        "recommended_next_steps": ["Review all findings", "Consult a security professional"]
    }
