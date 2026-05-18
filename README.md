# ThreatLens AI

ThreatLens AI is a Streamlit-based cybersecurity analysis assistant that helps review uploaded logs and source code for common attack patterns. It combines deterministic rule-based detection with Gemini-powered analysis, then produces risk scoring, OWASP Top 10 mapping, MITRE ATT&CK mapping, remediation guidance, history storage, and exportable reports.

The project is designed for defensive security review, education, demos, and early triage. It does not perform live network scanning or exploitation.

## Live Demo

ThreatLens AI is ready to run on Streamlit Community Cloud. The Streamlit main file path is:

```text
sentinelai/app.py
```

For public demos, users can click Demo Mode to load sample Apache logs and run the local rule-based pre-scan without entering an API key. Gemini enrichment, executive summaries, and Turkish AI explanations require a Gemini API key.

## What ThreatLens AI Does

ThreatLens AI accepts a log file or code snippet and runs a two-stage analysis pipeline:

1. Rule engine pre-scan flags suspicious evidence with regex and frequency-based detections.
2. Gemini performs contextual analysis on the flagged evidence.
3. Findings are enriched with OWASP Top 10, MITRE ATT&CK, confidence, remediation, business impact, and false-positive notes.
4. A composite risk score is calculated from severity, rule confidence, Gemini confidence, pattern strength, frequency, and asset sensitivity.
5. Results are stored in SQLite and can be exported as text or JSON reports.

## Architecture Overview

```text
sentinelai/
|-- app.py                  Streamlit dashboard and workflow orchestration
|-- log_parser.py           Apache/generic log parsing and log statistics
|-- rule_detector.py        Rule-based threat detection and confidence scoring
|-- threat_knowledge.py     OWASP, MITRE, remediation, impact, recommendations
|-- gemini_client.py        Gemini prompts, JSON parsing, AI enrichment
|-- risk_scoring.py         Composite risk score and score breakdown
|-- report_generator.py     Text report generation
|-- database.py             SQLite history and migration helpers
|-- sample_data/            Demo logs and vulnerable code samples
|-- requirements.txt        Python dependencies
```

## Features

- Log upload and code analysis through a Streamlit UI
- Rule-based detections for:
  - SQL Injection
  - XSS
  - Brute Force
  - Path Traversal
  - Command Injection
  - Suspicious User-Agents
  - Exposed Config Files
  - Sensitive File Access
  - Weak Cryptography
  - Hardcoded Secrets
- Rule confidence scoring for every rule-based finding
- Gemini-powered deep analysis for suspicious evidence
- OWASP Top 10 mapping
- MITRE ATT&CK mapping per threat type
- Immediate fix, long-term fix, business impact, and false-positive notes
- Simple attack timeline from parsed log timestamps
- Top recommendations generated from highest-risk findings
- Composite risk score from 0 to 100
- SQLite analysis history
- Exportable text and JSON reports
- English/Turkish UI labels, report labels, and explanation support
- Demo Mode for loading sample logs without uploading a file
- Gemini API key status messaging and local/Gemini readiness indicator
- Mobile-friendly sidebar and layout adjustments

## How To Run

From the repository root:

```bash
cd sentinelai
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
streamlit run app.py
```

On macOS/Linux, activate the virtual environment with:

```bash
source .venv/bin/activate
```

Then open the Streamlit URL shown in the terminal and paste your Gemini API key in the sidebar.

## Streamlit Community Cloud Deployment

1. Push the repository to GitHub.
2. In Streamlit Community Cloud, create a new app from the repository.
3. Set the main file path to `sentinelai/app.py`.
4. Keep the Python dependencies in `sentinelai/requirements.txt`; the root `requirements.txt` points Streamlit Cloud to that file.
5. Optional: add `GEMINI_API_KEY` in Streamlit app secrets for a prefilled private default key.
6. Deploy the app.

Do not commit API keys to GitHub. If no Streamlit secret is configured, users can paste their Gemini API key into the sidebar at runtime. The key is used only for the current Streamlit session and is not stored in the repository.

## Gemini API Key

ThreatLens AI uses Gemini for contextual analysis and executive summaries.

1. Visit Google AI Studio.
2. Create a Gemini API key.
3. Paste the key into the ThreatLens AI sidebar.
4. Click the validation button before running Gemini analysis.

The rule engine can still show pre-scan signals, confidence, MITRE mapping, and remediation context before AI analysis.

## Sample Use Cases

- Review Apache access logs for SQL injection, XSS, traversal, scanners, and brute force attempts.
- Analyze a vulnerable PHP login form for SQL injection and hardcoded secrets.
- Analyze a Flask snippet for weak secrets, command injection, or unsafe crypto usage.
- Generate an executive report for a manager after an incident triage exercise.
- Demonstrate OWASP Top 10 and MITRE ATT&CK mapping in a cybersecurity class or hackathon project.

## Report Contents

Exported reports include:

- Executive summary
- Overall risk score and severity
- Top recommendations
- Attack timeline when timestamps are available
- Rule-based pre-scan signals and rule confidence
- Detailed findings
- OWASP Top 10 mapping
- MITRE ATT&CK mapping
- Evidence
- Immediate and long-term recommended fixes
- Business impact
- False-positive notes
- Prioritized next steps

## Ethical Notice

ThreatLens AI is intended only for defensive, educational, and authorized security analysis.

- Only analyze logs, code, and systems you own or have explicit permission to assess.
- Do not use this project to attack, scan, or exploit third-party systems.
- The sample data is intentionally vulnerable and exists only for demonstration.
- Findings may include false positives and should be validated before production changes.

## Roadmap

- Add more log formats, including Nginx, auth.log, Windows Event exports, and JSON logs.
- Add SARIF export for CI/security tooling.
- Add optional PDF/HTML report export.
- Add CVSS-style scoring details.
- Add rule tuning profiles for web apps, APIs, and authentication logs.
- Add analyst feedback to mark findings as true positive or false positive.
- Add automated regression tests for detector patterns and risk scoring.
