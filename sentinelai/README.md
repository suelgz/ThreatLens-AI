# 🛡️ SentinelAI — Gemini-Powered Cyber Threat Analyzer

**BTK Akademi & Google Hackathon 2026 Project**

A Gemini-powered cybersecurity assistant that analyzes security logs and vulnerable code,
detects threats, maps them to OWASP Top 10, scores risk, and generates professional reports.

---

## 🚀 Quick Start

### 1. Install dependencies
```bash
pip install -r requirements.txt
```

### 2. Run the app
```bash
streamlit run app.py
```

### 3. Get a Gemini API key
1. Go to https://aistudio.google.com/
2. Click "Get API key"
3. Paste it in the sidebar when the app opens

---

## 📁 Project Structure

```
sentinelai/
├── app.py                  # Streamlit dashboard (main entry)
├── gemini_client.py        # Gemini API calls + prompt templates
├── log_parser.py           # Apache/Nginx log parser
├── rule_detector.py        # Regex-based attack pattern detection
├── risk_scoring.py         # Risk score formula (0-100)
├── report_generator.py     # Text/PDF report builder
├── database.py             # SQLite history storage
├── requirements.txt
├── .streamlit/config.toml  # Dark theme config
├── sample_data/
│   ├── apache_access.log   # Sample log with SQLi, XSS, brute force
│   ├── vulnerable_login.php
│   └── vulnerable_flask.py
└── exports/                # Generated reports saved here
```

---

## ⚡ Features

| Feature | Status |
|---|---|
| Apache/Nginx log parsing | ✅ |
| Rule-based pre-detection (9 threat types) | ✅ |
| Gemini AI deep analysis | ✅ |
| Risk score 0–100 formula | ✅ |
| OWASP Top 10 mapping | ✅ |
| Executive summary for managers | ✅ |
| Turkish / English toggle | ✅ |
| Analysis history (SQLite) | ✅ |
| Report export (.txt + JSON) | ✅ |
| Code vulnerability analysis | ✅ |
| Interactive Plotly charts | ✅ |

---

## 🎯 Threat Detection Coverage

- SQL Injection → A03:2021
- XSS → A03:2021
- Path Traversal → A01:2021
- Command Injection → A03:2021
- Brute Force → A07:2021
- Hardcoded Credentials → A02:2021
- Weak Cryptography → A02:2021
- Sensitive File Access → A05:2021
- Suspicious Scanner Tools → A05:2021

---

## ⚠️ Ethical Notice

SentinelAI is designed exclusively for **defensive, educational use**.
- Only analyzes uploaded files and pasted code
- Never performs live scanning or network probing
- All sample data is intentionally crafted for demonstration
- No real systems are targeted or tested

---

## 🔑 Risk Scoring Formula

```
raw_score = (severity_weight × threat_multiplier × avg_confidence × asset_sensitivity)
           + frequency_bonus + pattern_boost

final_score = clamp(raw_score, 0, 100)
```

Score → Label mapping:
- 80–100: Critical
- 60–79: High
- 40–59: Medium
- 20–39: Low
- 0–19: Informational
