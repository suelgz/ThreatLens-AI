import streamlit as st
import pandas as pd
import json
import os
from pathlib import Path
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go

# Internal modules
from database import (
    get_all_analyses, get_analysis_detail, get_stats,
    save_analysis, save_uploaded_file, delete_analysis
)
from log_parser import parse_log_file, get_log_stats
from rule_detector import run_rule_detection, get_flagged_content_for_gemini, summarize_rule_findings
from risk_scoring import compute_risk_score, get_severity_color, get_score_breakdown
from gemini_client import (
    analyze_logs, analyze_code, generate_executive_summary,
    translate_to_turkish, test_api_key
)
from report_generator import build_text_report, save_text_report

# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title="SentinelAI",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# ─── Custom CSS ───────────────────────────────────────────────────────────────

st.markdown("""
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=DM+Sans:wght@300;400;500;700&display=swap');

  :root {
    --bg:       #0A0E1A;
    --panel:    #111827;
    --border:   #1E2D40;
    --accent:   #00E5FF;
    --accent2:  #FF6B35;
    --text:     #E2E8F0;
    --muted:    #64748B;
    --critical: #FF2D2D;
    --high:     #FF6B35;
    --medium:   #FFB700;
    --low:      #22C55E;
    --info:     #3B82F6;
  }

  html, body, [class*="css"] {
    background-color: var(--bg) !important;
    color: var(--text) !important;
    font-family: 'DM Sans', sans-serif !important;
  }

  /* Sidebar */
  section[data-testid="stSidebar"] {
    background: var(--panel) !important;
    border-right: 1px solid var(--border) !important;
  }

  /* Headers */
  h1, h2, h3 { font-family: 'Space Mono', monospace !important; }
  h1 { color: var(--accent) !important; letter-spacing: -0.5px; }
  h2 { color: var(--text) !important; }
  h3 { color: var(--accent) !important; font-size: 0.95rem !important; text-transform: uppercase; letter-spacing: 2px; }

  /* Metric cards */
  [data-testid="metric-container"] {
    background: var(--panel) !important;
    border: 1px solid var(--border) !important;
    border-radius: 8px !important;
    padding: 12px !important;
  }

  /* Buttons */
  .stButton > button {
    background: transparent !important;
    border: 1px solid var(--accent) !important;
    color: var(--accent) !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.8rem !important;
    letter-spacing: 1px !important;
    border-radius: 4px !important;
    transition: all 0.2s !important;
  }
  .stButton > button:hover {
    background: var(--accent) !important;
    color: var(--bg) !important;
  }

  /* Primary button */
  .primary-btn > button {
    background: var(--accent) !important;
    color: var(--bg) !important;
    font-weight: 700 !important;
  }

  /* Inputs */
  .stTextInput > div > div > input,
  .stTextArea > div > div > textarea,
  .stSelectbox > div > div {
    background: var(--panel) !important;
    border: 1px solid var(--border) !important;
    color: var(--text) !important;
    border-radius: 6px !important;
  }

  /* File uploader */
  [data-testid="stFileUploader"] {
    border: 1px dashed var(--border) !important;
    border-radius: 8px !important;
    background: var(--panel) !important;
  }

  /* Cards */
  .sentinel-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 20px;
    margin: 10px 0;
    transition: border-color 0.2s;
  }
  .sentinel-card:hover { border-color: var(--accent); }

  /* Severity badges */
  .badge {
    display: inline-block;
    padding: 3px 12px;
    border-radius: 20px;
    font-family: 'Space Mono', monospace;
    font-size: 0.75rem;
    font-weight: 700;
    letter-spacing: 1px;
  }
  .badge-critical { background: rgba(255,45,45,0.15); color: #FF2D2D; border: 1px solid #FF2D2D; }
  .badge-high     { background: rgba(255,107,53,0.15); color: #FF6B35; border: 1px solid #FF6B35; }
  .badge-medium   { background: rgba(255,183,0,0.15);  color: #FFB700; border: 1px solid #FFB700; }
  .badge-low      { background: rgba(34,197,94,0.15);  color: #22C55E; border: 1px solid #22C55E; }
  .badge-info     { background: rgba(59,130,246,0.15); color: #3B82F6; border: 1px solid #3B82F6; }
  .badge-clean    { background: rgba(34,197,94,0.15);  color: #22C55E; border: 1px solid #22C55E; }

  /* Score ring placeholder */
  .score-display {
    font-family: 'Space Mono', monospace;
    font-size: 3rem;
    font-weight: 700;
    text-align: center;
    line-height: 1;
  }

  /* Finding block */
  .finding-block {
    background: #0D1421;
    border-left: 3px solid var(--accent2);
    border-radius: 0 8px 8px 0;
    padding: 16px;
    margin: 8px 0;
    font-size: 0.9rem;
  }
  .finding-block.critical { border-left-color: #FF2D2D; }
  .finding-block.high     { border-left-color: #FF6B35; }
  .finding-block.medium   { border-left-color: #FFB700; }
  .finding-block.low      { border-left-color: #22C55E; }

  /* Evidence code block */
  .evidence-code {
    background: #070B14;
    border: 1px solid #1E2D40;
    border-radius: 4px;
    padding: 8px 12px;
    font-family: 'Space Mono', monospace;
    font-size: 0.78rem;
    color: #00E5FF;
    margin: 8px 0;
    word-break: break-all;
    overflow-x: auto;
  }

  /* Status bar */
  .status-bar {
    background: linear-gradient(90deg, #00E5FF10, transparent);
    border-left: 3px solid var(--accent);
    padding: 10px 16px;
    border-radius: 0 6px 6px 0;
    margin: 8px 0;
    font-size: 0.85rem;
    color: var(--accent);
    font-family: 'Space Mono', monospace;
  }

  /* Divider */
  hr { border-color: var(--border) !important; }

  /* Tabs */
  .stTabs [data-baseweb="tab-list"] {
    background: var(--panel) !important;
    border-bottom: 1px solid var(--border) !important;
  }
  .stTabs [data-baseweb="tab"] {
    color: var(--muted) !important;
    font-family: 'Space Mono', monospace !important;
    font-size: 0.8rem !important;
  }
  .stTabs [aria-selected="true"] {
    color: var(--accent) !important;
    border-bottom: 2px solid var(--accent) !important;
  }

  /* Expander */
  details { border: 1px solid var(--border) !important; border-radius: 6px !important; }
  details summary { color: var(--accent) !important; font-family: 'Space Mono', monospace !important; }

  /* Scrollbar */
  ::-webkit-scrollbar { width: 6px; height: 6px; }
  ::-webkit-scrollbar-track { background: var(--bg); }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 3px; }
  ::-webkit-scrollbar-thumb:hover { background: var(--accent); }

  /* Table */
  .dataframe { background: var(--panel) !important; border: 1px solid var(--border) !important; }
  .stDataFrame { border: 1px solid var(--border) !important; border-radius: 6px !important; }

  /* Alert override */
  .stAlert { border-radius: 6px !important; }

  /* Logo */
  .logo-title {
    font-family: 'Space Mono', monospace;
    font-size: 1.6rem;
    font-weight: 700;
    color: #00E5FF;
    letter-spacing: 2px;
  }
  .logo-sub {
    font-family: 'DM Sans', sans-serif;
    font-size: 0.75rem;
    color: #64748B;
    letter-spacing: 3px;
    text-transform: uppercase;
  }
</style>
""", unsafe_allow_html=True)

# ─── Session State Defaults ───────────────────────────────────────────────────

def init_state():
    defaults = {
        "api_key": "",
        "api_key_valid": False,
        "last_findings": [],
        "last_rule_findings": [],
        "last_risk_score": 0,
        "last_severity": "Clean",
        "last_exec_summary": {},
        "last_analysis_id": None,
        "last_analysis_type": "",
        "last_input_name": "",
        "language": "en",
        "analyzing": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ─── Helpers ──────────────────────────────────────────────────────────────────

SAMPLE_DATA_DIR = Path(__file__).parent / "sample_data"

def severity_badge(severity: str) -> str:
    cls = severity.lower() if severity.lower() in ["critical","high","medium","low","clean"] else "info"
    return f'<span class="badge badge-{cls}">{severity}</span>'

def finding_card(f: dict, idx: int):
    sev = f.get("severity", "Unknown").lower()
    conf_pct = int(float(f.get("confidence", 0)) * 100)
    owasp = f.get("owasp_category", "")
    
    st.markdown(f"""
    <div class="finding-block {sev}">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px">
        <span style="font-family:'Space Mono',monospace; font-weight:700; font-size:0.95rem">
          #{idx} &nbsp; {f.get('threat_type','Unknown')}
        </span>
        <div>
          {severity_badge(f.get('severity','Unknown'))}
          &nbsp;
          <span style="color:#64748B; font-size:0.78rem; font-family:'Space Mono',monospace">
            {conf_pct}% confidence
          </span>
        </div>
      </div>
      <div style="color:#94A3B8; font-size:0.78rem; margin-bottom:8px">
        📌 {owasp}
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander("📋 Evidence & Analysis", expanded=(idx == 1)):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown("**Evidence**")
            st.markdown(f'<div class="evidence-code">{f.get("evidence","N/A")}</div>', unsafe_allow_html=True)
            st.markdown("**Explanation**")
            st.write(f.get("explanation", ""))
            st.markdown("**False Positive Note**")
            st.caption(f.get("false_positive_note", "None noted."))
        with col2:
            st.markdown("**Business Impact**")
            st.warning(f.get("business_impact", "Unknown"))
            st.markdown("**Recommended Fix**")
            st.success(f.get("recommended_fix", "No fix available."))

def render_score_gauge(score: int, severity: str):
    color = get_severity_color(severity)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": "Risk Score", "font": {"color": "#94A3B8", "family": "Space Mono", "size": 13}},
        number={"font": {"color": color, "family": "Space Mono", "size": 42}},
        gauge={
            "axis": {"range": [0, 100], "tickcolor": "#64748B",
                     "tickfont": {"color": "#64748B", "size": 10}},
            "bar": {"color": color, "thickness": 0.25},
            "bgcolor": "#111827",
            "bordercolor": "#1E2D40",
            "steps": [
                {"range": [0, 20],  "color": "#0D1421"},
                {"range": [20, 40], "color": "#0D1421"},
                {"range": [40, 60], "color": "#0D1421"},
                {"range": [60, 80], "color": "#0D1421"},
                {"range": [80, 100],"color": "#0D1421"},
            ],
            "threshold": {"line": {"color": color, "width": 3}, "thickness": 0.75, "value": score}
        }
    ))
    fig.update_layout(
        paper_bgcolor="#111827", plot_bgcolor="#111827",
        font={"color": "#E2E8F0"},
        height=220, margin=dict(t=30, b=10, l=20, r=20)
    )
    return fig

# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    st.markdown('<div class="logo-title">🛡️ SentinelAI</div>', unsafe_allow_html=True)
    st.markdown('<div class="logo-sub">Gemini Threat Analyzer</div>', unsafe_allow_html=True)
    st.markdown("---")

    # API Key Input
    st.markdown("### ⚙️ Configuration")
    api_key_input = st.text_input(
        "Gemini API Key",
        value=st.session_state.api_key,
        type="password",
        placeholder="AIza...",
        help="Get your key at https://makersuite.google.com"
    )

    if api_key_input != st.session_state.api_key:
        st.session_state.api_key = api_key_input
        st.session_state.api_key_valid = False

    if st.session_state.api_key and not st.session_state.api_key_valid:
        if st.button("🔑 Validate Key"):
            with st.spinner("Testing..."):
                ok, msg = test_api_key(st.session_state.api_key)
                st.session_state.api_key_valid = ok
                if ok:
                    st.success("API key valid ✓")
                else:
                    st.error(f"Invalid: {msg[:80]}")

    if st.session_state.api_key_valid:
        st.markdown('<div class="status-bar">● API CONNECTED</div>', unsafe_allow_html=True)

    # Language Toggle
    st.markdown("---")
    st.markdown("### 🌐 Language")
    lang = st.radio("Explanation Language", ["🇬🇧 English", "🇹🇷 Türkçe"], horizontal=True,
                    label_visibility="collapsed")
    st.session_state.language = "tr" if "Türkçe" in lang else "en"

    # Navigation
    st.markdown("---")
    st.markdown("### 📂 Navigation")
    page = st.radio(
        "Go to",
        ["🏠 Home", "📋 Analyze Logs", "💻 Analyze Code", "📊 Results", "🕐 History", "📄 Reports"],
        label_visibility="collapsed"
    )

    # Stats quick view
    st.markdown("---")
    stats = get_stats()
    st.markdown("### 📈 Session Stats")
    st.metric("Total Analyses", stats["total_analyses"])
    st.metric("Avg Risk Score", f"{stats['avg_risk_score']}/100")

# ─── Page: Home ───────────────────────────────────────────────────────────────

if "Home" in page:
    st.markdown("# 🛡️ SentinelAI")
    st.markdown("**Gemini-Powered Cyber Threat & Vulnerability Analyzer**")
    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("🔍 Analyses Run", stats["total_analyses"])
    with col2:
        st.metric("⚠️ Critical Found",
                  stats["by_severity"].get("Critical", 0) + stats["by_severity"].get("High", 0))
    with col3:
        st.metric("📊 Avg Risk Score", f"{stats['avg_risk_score']}/100")
    with col4:
        st.metric("🎯 Threats Detected",
                  sum(1 for t in stats["top_threats"] if t.get("cnt", 0) > 0))

    st.markdown("---")

    col_l, col_r = st.columns([3, 2])

    with col_l:
        st.markdown("### 🚀 What SentinelAI Does")
        st.markdown("""
        <div class="sentinel-card">
        <p>SentinelAI is an AI-powered security assistant that transforms raw log files and
        vulnerable code into structured, actionable threat intelligence — in seconds.</p>
        <br>
        <b>How it works:</b><br>
        <ol style="margin-left:16px; color:#94A3B8; line-height:2">
          <li>📤 Upload a log file or paste a code snippet</li>
          <li>🔍 Rule-based engine flags suspicious patterns</li>
          <li>🤖 Gemini performs deep contextual analysis</li>
          <li>📊 Risk score is computed (0–100 formula)</li>
          <li>🗺️ Findings mapped to OWASP Top 10</li>
          <li>📄 Download a full security report</li>
        </ol>
        </div>
        """, unsafe_allow_html=True)

        st.markdown("### 🎯 Threat Detection Coverage")
        coverage = {
            "SQL Injection": "A03:2021",
            "XSS (Cross-Site Scripting)": "A03:2021",
            "Path Traversal": "A01:2021",
            "Command Injection": "A03:2021",
            "Brute Force": "A07:2021",
            "Hardcoded Credentials": "A02:2021",
            "Weak Cryptography": "A02:2021",
            "Sensitive File Access": "A05:2021",
            "Suspicious Scanner Tools": "A05:2021",
        }
        for threat, owasp in coverage.items():
            st.markdown(
                f'<div style="display:flex;justify-content:space-between;padding:6px 0;'
                f'border-bottom:1px solid #1E2D40;font-size:0.88rem">'
                f'<span>⚔️ {threat}</span>'
                f'<span style="color:#00E5FF;font-family:monospace">{owasp}</span></div>',
                unsafe_allow_html=True
            )

    with col_r:
        st.markdown("### 📊 Threat Distribution")
        if stats["top_threats"]:
            threat_df = pd.DataFrame(stats["top_threats"])
            fig = px.bar(
                threat_df, x="cnt", y="threat_type", orientation="h",
                color_discrete_sequence=["#00E5FF"],
                labels={"cnt": "Count", "threat_type": "Threat Type"}
            )
            fig.update_layout(
                paper_bgcolor="#111827", plot_bgcolor="#111827",
                font={"color": "#E2E8F0", "family": "DM Sans"},
                showlegend=False, height=300,
                xaxis={"gridcolor": "#1E2D40"},
                yaxis={"gridcolor": "#1E2D40"},
                margin=dict(l=10, r=10, t=10, b=10)
            )
            st.plotly_chart(fig, use_container_width=True)
        else:
            st.info("Run your first analysis to see threat distribution.")

        st.markdown("### 🔴 Severity Breakdown")
        if stats["by_severity"]:
            sev_data = stats["by_severity"]
            colors = {"Critical": "#FF2D2D", "High": "#FF6B35",
                      "Medium": "#FFB700", "Low": "#22C55E",
                      "Informational": "#3B82F6", "Clean": "#22C55E"}
            fig2 = go.Figure(go.Pie(
                labels=list(sev_data.keys()),
                values=list(sev_data.values()),
                hole=0.6,
                marker={"colors": [colors.get(k, "#888") for k in sev_data.keys()]},
                textfont={"color": "#E2E8F0"}
            ))
            fig2.update_layout(
                paper_bgcolor="#111827", plot_bgcolor="#111827",
                font={"color": "#E2E8F0"},
                showlegend=True, height=250,
                margin=dict(l=10, r=10, t=10, b=10),
                legend={"font": {"color": "#E2E8F0"}}
            )
            st.plotly_chart(fig2, use_container_width=True)
        else:
            st.info("No analyses yet.")

        st.markdown("### 📁 Quick Start")
        st.markdown("""
        <div class="sentinel-card">
        <p style="font-size:0.85rem; color:#94A3B8">
          Try with built-in sample files:<br>
          → <code>apache_access.log</code> — SQLi + Brute Force<br>
          → <code>vulnerable_login.php</code> — Auth + SQLi<br>
          → <code>vulnerable_flask.py</code> — Multi-vuln Flask
        </p>
        </div>
        """, unsafe_allow_html=True)

# ─── Page: Analyze Logs ───────────────────────────────────────────────────────

elif "Analyze Logs" in page:
    st.markdown("# 📋 Log Analysis")
    st.markdown("Upload a security log file or use a sample to detect attack patterns.")
    st.markdown("---")

    if not st.session_state.api_key_valid:
        st.warning("⚠️ Please enter and validate your Gemini API key in the sidebar first.")

    source = st.radio("Input Source", ["📤 Upload File", "📁 Use Sample Log"],
                      horizontal=True, label_visibility="collapsed")

    log_content = ""
    log_filename = ""

    if "Upload" in source:
        uploaded = st.file_uploader("Upload Log File",
                                    type=["log", "txt", "csv"],
                                    label_visibility="collapsed")
        if uploaded:
            log_content = uploaded.read().decode("utf-8", errors="ignore")
            log_filename = uploaded.name
            st.success(f"✓ Loaded: **{log_filename}** ({len(log_content):,} bytes)")
    else:
        sample_path = SAMPLE_DATA_DIR / "apache_access.log"
        if sample_path.exists():
            log_content = sample_path.read_text()
            log_filename = "apache_access.log (sample)"
            st.info("📁 Using built-in Apache access log sample with SQL injection, brute force, XSS, and path traversal examples.")

    if log_content:
        df, fmt = parse_log_file(log_content)
        log_stats = get_log_stats(df)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric("📄 Total Lines", log_stats.get("total_lines", 0))
        with col2:
            st.metric("🖥️ Unique IPs", log_stats.get("unique_ips", "N/A"))
        with col3:
            st.metric("📂 Format Detected", fmt.upper())

        with st.expander("🔍 Preview Log Data", expanded=False):
            if not df.empty and "raw" in df.columns:
                st.dataframe(
                    df[["ip", "method", "path", "status", "agent"]].head(20)
                    if "ip" in df.columns else df.head(20),
                    use_container_width=True, height=200
                )

        st.markdown("---")
        st.markdown("### 🔎 Rule-Based Pre-Scan")

        rule_findings = run_rule_detection(df, log_content)

        if rule_findings:
            st.markdown(f'<div class="status-bar">⚠️ {len(rule_findings)} THREAT PATTERN(S) DETECTED BY RULE ENGINE</div>',
                        unsafe_allow_html=True)
            for rf in rule_findings:
                col_a, col_b = st.columns([3, 1])
                with col_a:
                    st.markdown(
                        f'<div style="padding:8px 0; border-bottom:1px solid #1E2D40">'
                        f'<span style="color:#00E5FF;font-family:monospace">▶ {rf["threat_type"]}</span>'
                        f' &nbsp; <span style="color:#64748B;font-size:0.8rem">'
                        f'{len(rf["matched_lines"])} line(s) flagged</span></div>',
                        unsafe_allow_html=True
                    )
                with col_b:
                    st.markdown(
                        f'<span style="color:#64748B;font-size:0.8rem">{rf["owasp_category"]}</span>',
                        unsafe_allow_html=True
                    )
        else:
            st.success("✅ No suspicious patterns detected by rule engine.")

        st.markdown("---")

        col_btn, col_info = st.columns([2, 3])
        with col_btn:
            analyze_btn = st.button(
                "🤖 Analyze with Gemini AI",
                disabled=not (st.session_state.api_key_valid and bool(rule_findings)),
                use_container_width=True
            )
        with col_info:
            if not rule_findings:
                st.info("No suspicious patterns to send to Gemini.")
            elif not st.session_state.api_key_valid:
                st.warning("Validate API key first.")
            else:
                st.markdown(
                    f'<div class="status-bar">📡 {len(rule_findings)} threat pattern(s) ready for Gemini analysis</div>',
                    unsafe_allow_html=True
                )

        if analyze_btn and rule_findings and st.session_state.api_key_valid:
            with st.spinner("🤖 Gemini is analyzing threat patterns..."):
                flagged_content = get_flagged_content_for_gemini(rule_findings)
                pre_labels = summarize_rule_findings(rule_findings)

                findings = analyze_logs(
                    flagged_content, pre_labels, st.session_state.api_key
                )

                risk_score, severity_label = compute_risk_score(findings, rule_findings)

                exec_summary = {}
                if findings:
                    with st.spinner("📝 Generating executive summary..."):
                        exec_summary = generate_executive_summary(
                            findings, risk_score, severity_label, st.session_state.api_key
                        )

                # Save to DB
                analysis_id = save_analysis(
                    analysis_type="log",
                    input_filename=log_filename,
                    input_preview=log_content[:500],
                    risk_score=risk_score,
                    severity_label=severity_label,
                    findings=findings,
                    executive_summary=json.dumps(exec_summary),
                    language=st.session_state.language
                )

                save_uploaded_file(
                    analysis_id, log_filename,
                    len(log_content.encode()), "log",
                    line_count=log_stats.get("total_lines", 0),
                    flagged_count=len(rule_findings)
                )

                # Store in session
                st.session_state.last_findings = findings
                st.session_state.last_rule_findings = rule_findings
                st.session_state.last_risk_score = risk_score
                st.session_state.last_severity = severity_label
                st.session_state.last_exec_summary = exec_summary
                st.session_state.last_analysis_id = analysis_id
                st.session_state.last_analysis_type = "log"
                st.session_state.last_input_name = log_filename

            st.success(f"✅ Analysis complete! Found {len(findings)} threats. View in Results page.")
            st.rerun()

# ─── Page: Analyze Code ───────────────────────────────────────────────────────

elif "Analyze Code" in page:
    st.markdown("# 💻 Code Vulnerability Analysis")
    st.markdown("Paste code or load a sample to detect security vulnerabilities.")
    st.markdown("---")

    if not st.session_state.api_key_valid:
        st.warning("⚠️ Please enter and validate your Gemini API key in the sidebar first.")

    col1, col2 = st.columns([3, 1])
    with col1:
        source = st.radio("Source", ["✏️ Paste Code", "📁 Load Sample"],
                          horizontal=True, label_visibility="collapsed")
    with col2:
        language = st.selectbox("Language", ["PHP", "Python", "JavaScript", "Java", "Other"])

    code_input = ""
    code_filename = f"snippet.{language.lower()}"

    if "Paste" in source:
        code_input = st.text_area(
            "Code Snippet",
            placeholder="Paste your code here...",
            height=300,
            label_visibility="collapsed"
        )
    else:
        sample_files = {
            "PHP": SAMPLE_DATA_DIR / "vulnerable_login.php",
            "Python": SAMPLE_DATA_DIR / "vulnerable_flask.py",
        }
        sample_path = sample_files.get(language)
        if sample_path and sample_path.exists():
            code_input = sample_path.read_text()
            code_filename = sample_path.name
            st.info(f"📁 Loaded: **{code_filename}**")
            st.code(code_input, language=language.lower())
        else:
            st.warning(f"No sample available for {language}. Try PHP or Python.")

    if code_input:
        # Rule-based pre-scan on raw text
        st.markdown("---")
        st.markdown("### 🔎 Static Analysis Pre-Scan")
        empty_df = pd.DataFrame()
        rule_findings = run_rule_detection(empty_df, code_input)

        if rule_findings:
            st.markdown(
                f'<div class="status-bar">⚠️ {len(rule_findings)} VULNERABILITY PATTERN(S) DETECTED</div>',
                unsafe_allow_html=True
            )
            for rf in rule_findings:
                st.markdown(
                    f'<div style="padding:8px 0; border-bottom:1px solid #1E2D40">'
                    f'<span style="color:#FF6B35;font-family:monospace">▶ {rf["threat_type"]}</span>'
                    f' — <span style="color:#64748B;font-size:0.8rem">'
                    f'{rf["owasp_category"]}</span></div>',
                    unsafe_allow_html=True
                )
        else:
            st.info("No obvious patterns detected. Gemini may still find subtle issues.")

        col_btn, _ = st.columns([2, 3])
        with col_btn:
            analyze_btn = st.button(
                "🤖 Analyze with Gemini AI",
                disabled=not st.session_state.api_key_valid,
                use_container_width=True
            )

        if analyze_btn and st.session_state.api_key_valid:
            with st.spinner("🤖 Gemini is reviewing your code for vulnerabilities..."):
                pre_labels = summarize_rule_findings(rule_findings)
                findings = analyze_code(
                    code_input, language, pre_labels, st.session_state.api_key
                )
                risk_score, severity_label = compute_risk_score(findings, rule_findings)

                exec_summary = {}
                if findings:
                    exec_summary = generate_executive_summary(
                        findings, risk_score, severity_label, st.session_state.api_key
                    )

                analysis_id = save_analysis(
                    analysis_type="code",
                    input_filename=code_filename,
                    input_preview=code_input[:500],
                    risk_score=risk_score,
                    severity_label=severity_label,
                    findings=findings,
                    executive_summary=json.dumps(exec_summary),
                    language=st.session_state.language
                )

                st.session_state.last_findings = findings
                st.session_state.last_rule_findings = rule_findings
                st.session_state.last_risk_score = risk_score
                st.session_state.last_severity = severity_label
                st.session_state.last_exec_summary = exec_summary
                st.session_state.last_analysis_id = analysis_id
                st.session_state.last_analysis_type = "code"
                st.session_state.last_input_name = code_filename

            st.success(f"✅ Analysis complete! Found {len(findings)} vulnerabilities.")
            st.rerun()

# ─── Page: Results ────────────────────────────────────────────────────────────

elif "Results" in page:
    st.markdown("# 📊 Analysis Results")

    if not st.session_state.last_findings and st.session_state.last_risk_score == 0:
        st.info("No results yet. Run an analysis from 'Analyze Logs' or 'Analyze Code'.")
    else:
        findings = st.session_state.last_findings
        risk_score = st.session_state.last_risk_score
        severity = st.session_state.last_severity
        exec_summary = st.session_state.last_exec_summary
        rule_findings = st.session_state.last_rule_findings

        # Top summary bar
        col_score, col_info, col_actions = st.columns([2, 4, 2])

        with col_score:
            st.plotly_chart(render_score_gauge(risk_score, severity), use_container_width=True)
            st.markdown(
                f'<div style="text-align:center">{severity_badge(severity)}</div>',
                unsafe_allow_html=True
            )

        with col_info:
            st.markdown(f"### Analysis: `{st.session_state.last_input_name}`")

            breakdown = get_score_breakdown(findings, rule_findings)
            col_a, col_b, col_c, col_d = st.columns(4)
            col_a.metric("Findings", breakdown.get("finding_count", 0))
            col_b.metric("Avg Confidence",
                         f"{int(breakdown.get('avg_gemini_confidence', 0)*100)}%")
            col_c.metric("Flagged Lines", breakdown.get("flagged_lines_count", 0))
            col_d.metric("Rule Triggers", breakdown.get("rule_threats_detected", 0))

            # Severity distribution bar
            sev_dist = breakdown.get("severity_distribution", {})
            if sev_dist:
                sev_df = pd.DataFrame(list(sev_dist.items()), columns=["Severity", "Count"])
                colors = {"Critical":"#FF2D2D","High":"#FF6B35","Medium":"#FFB700",
                          "Low":"#22C55E","Informational":"#3B82F6"}
                fig = px.bar(sev_df, x="Count", y="Severity", orientation="h",
                             color="Severity",
                             color_discrete_map=colors)
                fig.update_layout(
                    paper_bgcolor="#111827", plot_bgcolor="#111827",
                    font={"color":"#E2E8F0"}, showlegend=False,
                    height=160, margin=dict(l=0,r=10,t=10,b=0),
                    xaxis={"gridcolor":"#1E2D40"},
                    yaxis={"gridcolor":"#1E2D40"}
                )
                st.plotly_chart(fig, use_container_width=True)

        with col_actions:
            st.markdown("### Quick Actions")
            if st.button("📄 Generate Report", use_container_width=True):
                report_text = build_text_report(
                    st.session_state.last_analysis_type,
                    st.session_state.last_input_name,
                    risk_score, severity, findings, exec_summary
                )
                st.download_button(
                    "⬇️ Download .txt",
                    data=report_text,
                    file_name=f"sentinelai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )

            if st.button("🗑️ Clear Results", use_container_width=True):
                for k in ["last_findings","last_risk_score","last_severity",
                          "last_exec_summary","last_rule_findings","last_input_name"]:
                    st.session_state[k] = [] if "findings" in k else ({} if "summary" in k else (0 if "score" in k else ""))
                st.rerun()

        st.markdown("---")

        # Tabs
        tab1, tab2, tab3 = st.tabs(["🎯 Threat Findings", "📋 Executive Summary", "🗺️ OWASP Map"])

        with tab1:
            if not findings:
                st.success("✅ No threats detected in this analysis.")
            else:
                for i, f in enumerate(findings, 1):
                    finding_card(f, i)

                    # Turkish translation
                    if st.session_state.language == "tr" and st.session_state.api_key_valid:
                        with st.expander(f"🇹🇷 Türkçe Açıklama — Bulgu #{i}"):
                            with st.spinner("Türkçeye çevriliyor..."):
                                tr = translate_to_turkish(f, st.session_state.api_key)
                            if tr:
                                st.markdown(f"**Basit Açıklama:** {tr.get('basit_aciklama','')}")
                                st.markdown(f"**Ne Olabilir:** {tr.get('ne_olabilir','')}")
                                st.markdown(f"**İş Etkisi:** {tr.get('is_etkisi','')}")
                                steps = tr.get("hemen_yapilacaklar", [])
                                if steps:
                                    st.markdown("**Hemen Yapılacaklar:**")
                                    for s in steps:
                                        st.markdown(f"  • {s}")

        with tab2:
            if exec_summary:
                status = exec_summary.get("overall_status", severity)
                st.markdown(
                    f'<div class="sentinel-card">'
                    f'<h3 style="font-family:Space Mono;color:#00E5FF;margin-top:0">Executive Summary</h3>'
                    f'<p style="font-size:1rem;line-height:1.7">{exec_summary.get("summary_paragraph","")}</p>'
                    f'</div>',
                    unsafe_allow_html=True
                )
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown("**🚨 Top Priority Action**")
                    st.error(exec_summary.get("top_priority_action", "N/A"))
                    st.markdown("**💼 Business Risk**")
                    st.warning(exec_summary.get("estimated_business_risk", "N/A"))
                with col2:
                    st.markdown("**✅ Positive Notes**")
                    st.success(exec_summary.get("positive_notes", "N/A"))
                    st.markdown("**📋 Recommended Next Steps**")
                    for i, step in enumerate(exec_summary.get("recommended_next_steps", []), 1):
                        st.markdown(f"{i}. {step}")
            else:
                st.info("Executive summary not available.")

        with tab3:
            owasp_map = {}
            for f in findings:
                cat = f.get("owasp_category", "Unknown")
                owasp_map.setdefault(cat, []).append(f.get("threat_type", "Unknown"))

            if owasp_map:
                for cat, threats in owasp_map.items():
                    code_prefix = cat[:8] if len(cat) >= 8 else cat
                    with st.expander(f"📌 {cat}", expanded=True):
                        for t in threats:
                            st.markdown(f"  ⚔️ {t}")
                        st.caption(f"Reference: https://owasp.org/Top10/")
            else:
                st.info("No OWASP mappings available.")

# ─── Page: History ────────────────────────────────────────────────────────────

elif "History" in page:
    st.markdown("# 🕐 Analysis History")
    st.markdown("---")

    analyses = get_all_analyses(50)

    if not analyses:
        st.info("No analyses yet. Start by analyzing a log or code file.")
    else:
        # Filter controls
        col1, col2 = st.columns([2, 1])
        with col1:
            search = st.text_input("🔍 Search by filename", placeholder="e.g. apache, flask...")
        with col2:
            filter_type = st.selectbox("Filter by type", ["All", "log", "code"])

        filtered = [
            a for a in analyses
            if (not search or search.lower() in (a.get("input_filename") or "").lower())
            and (filter_type == "All" or a.get("analysis_type") == filter_type)
        ]

        st.markdown(f"**{len(filtered)} record(s)**")

        for a in filtered:
            sev = a.get("severity_label", "Unknown")
            sev_badge = severity_badge(sev)
            score = a.get("overall_risk_score", 0)
            created = a.get("created_at", "")[:16].replace("T", " ")
            a_type = a.get("analysis_type", "").upper()
            fname = a.get("input_filename", "Unknown")
            n_findings = a.get("total_findings", 0)

            with st.expander(
                f"{sev_badge} {fname} — Score: {score}/100 — {created}",
                expanded=False
            ):
                col_d, col_act = st.columns([4, 1])
                with col_d:
                    st.markdown(f"**Type:** {a_type} &nbsp;|&nbsp; **Findings:** {n_findings} &nbsp;|&nbsp; **Language:** {a.get('language','en').upper()}")
                    detail = get_analysis_detail(a["id"])
                    for finding in detail.get("findings", []):
                        st.markdown(
                            f'<div style="padding:4px 0;border-bottom:1px solid #1E2D40;font-size:0.85rem">'
                            f'<span style="color:#00E5FF">{finding["threat_type"]}</span>'
                            f' — {finding["severity"]} — {finding["owasp_category"]}</div>',
                            unsafe_allow_html=True
                        )
                with col_act:
                    if st.button(f"🗑️ Delete", key=f"del_{a['id']}"):
                        delete_analysis(a["id"])
                        st.rerun()

                    # Quick report download
                    detail2 = get_analysis_detail(a["id"])
                    report_text = build_text_report(
                        a.get("analysis_type",""),
                        fname, score, sev,
                        detail2.get("findings", []),
                        {}
                    )
                    st.download_button(
                        "📄 Export",
                        data=report_text,
                        file_name=f"sentinel_{a['id']}.txt",
                        key=f"exp_{a['id']}"
                    )

# ─── Page: Reports ────────────────────────────────────────────────────────────

elif "Reports" in page:
    st.markdown("# 📄 Report Export")
    st.markdown("---")

    if not st.session_state.last_findings and st.session_state.last_risk_score == 0:
        st.info("No active analysis. Run an analysis first, then export here.")
    else:
        findings = st.session_state.last_findings
        risk_score = st.session_state.last_risk_score
        severity = st.session_state.last_severity
        exec_summary = st.session_state.last_exec_summary

        st.markdown("### 📊 Current Analysis Summary")
        col1, col2, col3 = st.columns(3)
        col1.metric("Risk Score", f"{risk_score}/100")
        col2.metric("Severity", severity)
        col3.metric("Findings", len(findings))

        st.markdown("---")
        st.markdown("### ⬇️ Download Report")

        report_text = build_text_report(
            st.session_state.last_analysis_type,
            st.session_state.last_input_name,
            risk_score, severity, findings, exec_summary,
            language=st.session_state.language
        )

        st.text_area("Report Preview", value=report_text[:3000] + "\n...", height=400,
                     label_visibility="collapsed")

        st.download_button(
            label="📥 Download Full Report (.txt)",
            data=report_text,
            file_name=f"sentinelai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )

        st.markdown("---")
        st.markdown("### 📋 Raw JSON Export")
        json_export = json.dumps({
            "analysis_type": st.session_state.last_analysis_type,
            "input_name": st.session_state.last_input_name,
            "risk_score": risk_score,
            "severity": severity,
            "findings": findings,
            "executive_summary": exec_summary,
            "exported_at": datetime.now().isoformat()
        }, indent=2, ensure_ascii=False)

        st.download_button(
            label="📥 Download JSON",
            data=json_export,
            file_name=f"sentinelai_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
