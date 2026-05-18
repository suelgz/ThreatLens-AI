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
    GeminiAPIError, translate_to_turkish, test_api_key
)
from i18n import APP_NAME, translate_text
from report_generator import build_text_report
from threat_knowledge import (
    build_attack_timeline,
    format_mitre_attack,
    generate_top_recommendations,
    merge_rule_and_gemini_findings,
)

# ─── Page Config ──────────────────────────────────────────────────────────────

st.set_page_config(
    page_title=APP_NAME,
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

  .confidence-badge {
    display: inline-block;
    padding: 3px 8px;
    border-radius: 999px;
    border: 1px solid #1E2D40;
    background: #0A0E1A;
    color: #94A3B8;
    font-family: 'Space Mono', monospace;
    font-size: 0.68rem;
    margin-left: 6px;
    white-space: nowrap;
  }

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

  @media (max-width: 768px) {
    .block-container {
      padding-left: 1rem !important;
      padding-right: 1rem !important;
    }

    section[data-testid="stSidebar"] {
      width: min(88vw, 22rem) !important;
    }

    .logo-title {
      font-size: 1.25rem;
      letter-spacing: 1px;
    }

    .logo-sub {
      font-size: 0.68rem;
      letter-spacing: 1.5px;
    }

    [data-testid="column"] {
      width: 100% !important;
      flex: 1 1 100% !important;
      min-width: 100% !important;
    }

    .finding-block {
      padding: 12px;
    }

    .stButton > button,
    .stDownloadButton > button {
      width: 100% !important;
      min-height: 42px;
      white-space: normal !important;
    }

    .badge,
    .confidence-badge {
      margin-top: 4px;
    }
  }
</style>
""", unsafe_allow_html=True)

# ─── Session State Defaults ───────────────────────────────────────────────────

def get_secret_api_key() -> str:
    try:
        return st.secrets.get("GEMINI_API_KEY", "")
    except Exception:
        return ""


def init_state():
    default_api_key = get_secret_api_key()
    defaults = {
        "api_key": default_api_key,
        "api_key_valid": False,
        "last_findings": [],
        "last_rule_findings": [],
        "last_risk_score": 0,
        "last_severity": "Clean",
        "last_exec_summary": {},
        "last_top_recommendations": [],
        "last_attack_timeline": [],
        "last_analysis_id": None,
        "last_analysis_type": "",
        "last_input_name": "",
        "language": "en",
        "api_key_error": "",
        "demo_log_loaded": False,
        "page": "home",
        "analyzing": False,
    }
    for k, v in defaults.items():
        if k not in st.session_state:
            st.session_state[k] = v

init_state()

# ─── Helpers ──────────────────────────────────────────────────────────────────

SAMPLE_DATA_DIR = Path(__file__).parent / "sample_data"

def t(key: str, **kwargs) -> str:
    return translate_text(key, st.session_state.get("language", "en"), **kwargs)

def severity_badge(severity: str) -> str:
    cls = severity.lower() if severity.lower() in ["critical","high","medium","low","clean"] else "info"
    return f'<span class="badge badge-{cls}">{severity}</span>'

def finding_card(f: dict, idx: int):
    sev = f.get("severity", "Unknown").lower()
    conf_pct = int(float(f.get("confidence", 0)) * 100)
    rule_conf_pct = int(float(f.get("rule_confidence", 0) or 0) * 100)
    owasp = f.get("owasp_category", "")
    mitre = f.get("mitre_attack_summary") or format_mitre_attack(f.get("mitre_attack"))
    source = f.get("analysis_source", "Gemini AI")
    
    st.markdown(f"""
    <div class="finding-block {sev}">
      <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:10px">
        <span style="font-family:'Space Mono',monospace; font-weight:700; font-size:0.95rem">
          #{idx} &nbsp; {f.get('threat_type','Unknown')}
        </span>
        <div>
          {severity_badge(f.get('severity','Unknown'))}
          <span class="confidence-badge">{t('ai_confidence')} {conf_pct}%</span>
          <span class="confidence-badge">{t('rule_confidence_short')} {rule_conf_pct}%</span>
        </div>
      </div>
      <div style="color:#94A3B8; font-size:0.78rem; margin-bottom:8px">
        📌 {owasp}<br/>
        MITRE ATT&CK: {mitre}<br/>
        {t('source_label')}: {source}
      </div>
    </div>
    """, unsafe_allow_html=True)

    with st.expander(f"📋 {t('evidence_analysis')}", expanded=(idx == 1)):
        col1, col2 = st.columns(2)
        with col1:
            st.markdown(f"**{t('evidence')}**")
            st.markdown(f'<div class="evidence-code">{f.get("evidence","N/A")}</div>', unsafe_allow_html=True)
            st.markdown(f"**{t('explanation')}**")
            st.write(f.get("explanation", ""))
            st.markdown(f"**{t('false_positive_note')}**")
            st.caption(f.get("false_positive_note", t("none_noted")))
        with col2:
            st.markdown(f"**{t('business_impact')}**")
            st.warning(f.get("business_impact", t("unknown")))
            st.markdown(f"**{t('immediate_fix')}**")
            st.success(f.get("immediate_fix") or f.get("recommended_fix", t("no_fix")))
            st.markdown(f"**{t('long_term_fix')}**")
            st.info(f.get("long_term_fix", t("no_long_term_fix")))

def render_score_gauge(score: int, severity: str):
    color = get_severity_color(severity)
    fig = go.Figure(go.Indicator(
        mode="gauge+number",
        value=score,
        domain={"x": [0, 1], "y": [0, 1]},
        title={"text": t("score"), "font": {"color": "#94A3B8", "family": "Space Mono", "size": 13}},
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

def build_json_export(
    analysis_type: str,
    input_name: str,
    risk_score: int,
    severity: str,
    findings: list[dict],
    exec_summary: dict,
    rule_findings: list[dict] | None = None,
    top_recommendations: list[str] | None = None,
    attack_timeline: list[dict] | None = None,
) -> str:
    return json.dumps({
        "app": APP_NAME,
        "analysis_type": analysis_type,
        "input_name": input_name,
        "risk_score": risk_score,
        "severity": severity,
        "findings": findings,
        "rule_findings": rule_findings or [],
        "executive_summary": exec_summary,
        "top_recommendations": top_recommendations or [],
        "attack_timeline": attack_timeline or [],
        "exported_at": datetime.now().isoformat()
    }, indent=2, ensure_ascii=False)

# ─── Sidebar ──────────────────────────────────────────────────────────────────

with st.sidebar:
    language_options = ["en", "tr"]
    st.radio(
        "Language / Dil",
        language_options,
        index=language_options.index(st.session_state["language"])
        if st.session_state["language"] in language_options else 0,
        format_func=lambda code: f"🇬🇧 English" if code == "en" else "🇹🇷 Türkçe",
        horizontal=True,
        label_visibility="collapsed",
        key="language",
    )

    st.markdown(f'<div class="logo-title">🛡️ {APP_NAME}</div>', unsafe_allow_html=True)
    st.markdown(f'<div class="logo-sub">{t("sidebar_subtitle")}</div>', unsafe_allow_html=True)
    st.markdown("---")

    # API Key Input
    st.markdown(f"### ⚙️ {t('configuration')}")
    api_key_input = st.text_input(
        t("gemini_api_key"),
        value=st.session_state.api_key,
        type="password",
        placeholder="AIza...",
        help=t("api_key_help")
    )

    if api_key_input != st.session_state.api_key:
        st.session_state.api_key = api_key_input
        st.session_state.api_key_valid = False
        st.session_state.api_key_error = ""

    if not st.session_state.api_key:
        st.info(f"⚪ {t('api_missing')}")
    elif st.session_state.api_key_valid:
        st.success(f"🟢 {t('api_valid')}")
    else:
        if st.session_state.api_key_error:
            st.error(f"🔴 {t('api_failed')}: {st.session_state.api_key_error[:80]}")
        else:
            st.warning(f"🟡 {t('api_not_validated')}")

        if st.button(f"🔑 {t('validate_key')}"):
            with st.spinner(t("testing")):
                ok, msg = test_api_key(st.session_state.api_key)
                st.session_state.api_key_valid = ok
                st.session_state.api_key_error = "" if ok else msg
            st.rerun()

    status_label = t("gemini_ready") if st.session_state.api_key_valid else t("local_ready")
    st.markdown(f'<div class="status-bar">● {status_label.upper()}</div>', unsafe_allow_html=True)

    # Navigation
    st.markdown("---")
    st.markdown(f"### 📂 {t('navigation')}")
    page_options = ["home", "logs", "code", "results", "history", "reports"]
    page_icons = {
        "home": "🏠",
        "logs": "📋",
        "code": "💻",
        "results": "📊",
        "history": "🕐",
        "reports": "📄",
    }
    page = st.radio(
        t("go_to"),
        page_options,
        index=page_options.index(st.session_state.page)
        if st.session_state.page in page_options else 0,
        format_func=lambda key: f"{page_icons[key]} {t('page_' + key)}",
        label_visibility="collapsed",
        key="page_selector",
    )
    st.session_state.page = page

    # Stats quick view
    st.markdown("---")
    stats = get_stats()
    st.markdown(f"### 📈 {t('session_stats')}")
    st.metric(t("total_analyses"), stats["total_analyses"])
    st.metric(t("avg_risk_score"), f"{stats['avg_risk_score']}/100")

# ─── Page: Home ───────────────────────────────────────────────────────────────

if page == "home":
    st.markdown(f"# 🛡️ {APP_NAME}")
    st.markdown(f"**{t('app_subtitle')}**")
    st.markdown("---")

    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric(f"🔍 {t('analyses_run')}", stats["total_analyses"])
    with col2:
        st.metric(f"⚠️ {t('critical_found')}",
                  stats["by_severity"].get("Critical", 0) + stats["by_severity"].get("High", 0))
    with col3:
        st.metric(f"📊 {t('avg_risk_score')}", f"{stats['avg_risk_score']}/100")
    with col4:
        st.metric(f"🎯 {t('threats_detected')}",
                  sum(1 for t in stats["top_threats"] if t.get("cnt", 0) > 0))

    st.markdown("---")

    col_l, col_r = st.columns([3, 2])

    with col_l:
        st.markdown(f"### 🚀 {t('what_app_does')}")
        st.markdown(f"""
        <div class="sentinel-card">
        <p>{t('home_description')}</p>
        <br>
        <b>{t('how_it_works')}</b><br>
        <ol style="margin-left:16px; color:#94A3B8; line-height:2">
          <li>📤 {t('home_step_upload')}</li>
          <li>🔍 {t('home_step_rules')}</li>
          <li>🤖 {t('home_step_gemini')}</li>
          <li>📊 {t('home_step_risk')}</li>
          <li>🗺️ {t('home_step_mapping')}</li>
          <li>📄 {t('home_step_report')}</li>
        </ol>
        </div>
        """, unsafe_allow_html=True)

        st.markdown(f"### 🎯 {t('threat_detection_coverage')}")
        coverage = {
            "SQL Injection": "A03:2021",
            "XSS (Cross-Site Scripting)": "A03:2021",
            "Path Traversal": "A01:2021",
            "Command Injection": "A03:2021",
            "Brute Force": "A07:2021",
            "Hardcoded Credentials": "A02:2021",
            "Weak Cryptography": "A02:2021",
            "Exposed Config Files": "A05:2021",
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
        st.markdown(f"### 📊 {t('threat_distribution')}")
        if stats["top_threats"]:
            threat_df = pd.DataFrame(stats["top_threats"])
            fig = px.bar(
                threat_df, x="cnt", y="threat_type", orientation="h",
                color_discrete_sequence=["#00E5FF"],
                labels={"cnt": t("count"), "threat_type": t("threat_type")}
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
            st.info(t("no_analyses_yet"))

        st.markdown(f"### 🔴 {t('severity_breakdown')}")
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
            st.info(t("no_analyses_yet"))

        st.markdown(f"### 📁 {t('quick_start')}")
        st.markdown(f"""
        <div class="sentinel-card">
        <p style="font-size:0.85rem; color:#94A3B8">
          {t('quick_start_body')}<br>
          → <code>apache_access.log</code> — SQLi + Brute Force<br>
          → <code>vulnerable_login.php</code> — Auth + SQLi<br>
          → <code>vulnerable_flask.py</code> — Multi-vuln Flask
        </p>
        </div>
        """, unsafe_allow_html=True)

# ─── Page: Analyze Logs ───────────────────────────────────────────────────────

elif page == "logs":
    st.markdown(f"# 📋 {t('log_analysis')}")
    st.markdown(t("log_intro"))
    st.markdown("---")

    if not st.session_state.api_key_valid:
        st.info(f"ℹ️ {t('local_scan_available')}")

    st.markdown(f'<div class="status-bar">▶ {t("demo_mode_cta")} — {t("demo_mode_help")}</div>', unsafe_allow_html=True)
    if st.button(f"▶ {t('demo_mode')}", help=t("demo_mode_help"), use_container_width=True):
        st.session_state.demo_log_loaded = True

    upload_source = f"📤 {t('upload_file')}"
    sample_source = f"📁 {t('use_sample_log')}"
    source = st.radio(t("input_source"), [upload_source, sample_source],
                      index=1 if st.session_state.demo_log_loaded else 0,
                      horizontal=True, label_visibility="collapsed")

    log_content = ""
    log_filename = ""

    if source == upload_source:
        st.session_state.demo_log_loaded = False
        uploaded = st.file_uploader(t("upload_log_file"),
                                    type=["log", "txt", "csv"],
                                    label_visibility="collapsed")
        if uploaded:
            log_content = uploaded.read().decode("utf-8", errors="ignore")
            log_filename = uploaded.name
            st.session_state.demo_log_loaded = False
            st.success(f"✓ {t('loaded')}: **{log_filename}** ({len(log_content):,} bytes)")
    else:
        sample_path = SAMPLE_DATA_DIR / "apache_access.log"
        if sample_path.exists():
            log_content = sample_path.read_text()
            log_filename = "apache_access.log (sample)"
            st.info(f"📁 {t('using_sample_log')}")

    if log_content:
        df, fmt = parse_log_file(log_content)
        log_stats = get_log_stats(df)

        col1, col2, col3 = st.columns(3)
        with col1:
            st.metric(f"📄 {t('total_lines')}", log_stats.get("total_lines", 0))
        with col2:
            st.metric(f"🖥️ {t('unique_ips')}", log_stats.get("unique_ips", "N/A"))
        with col3:
            st.metric(f"📂 {t('format_detected')}", fmt.upper())

        with st.expander(f"🔍 {t('preview_log_data')}", expanded=False):
            if not df.empty and "raw" in df.columns:
                st.dataframe(
                    df[["ip", "method", "path", "status", "agent"]].head(20)
                    if "ip" in df.columns else df.head(20),
                    use_container_width=True, height=200
                )

        st.markdown("---")
        st.markdown(f"### 🔎 {t('rule_pre_scan')}")

        rule_findings = run_rule_detection(df, log_content)

        if rule_findings:
            st.markdown(f'<div class="status-bar">⚠️ {t("threat_patterns_detected", count=len(rule_findings)).upper()}</div>',
                        unsafe_allow_html=True)
            for rf in rule_findings:
                rule_conf_pct = int(float(rf.get("rule_confidence", rf.get("confidence", 0)) or 0) * 100)
                mitre = rf.get("mitre_attack_summary") or format_mitre_attack(rf.get("mitre_attack"))
                col_a, col_b = st.columns([3, 1])
                with col_a:
                    st.markdown(
                        f'<div style="padding:8px 0; border-bottom:1px solid #1E2D40">'
                        f'<span style="color:#00E5FF;font-family:monospace">▶ {rf["threat_type"]}</span>'
                        f' &nbsp; <span style="color:#64748B;font-size:0.8rem">'
                        f'{t("lines_flagged_confidence", lines=len(rf["matched_lines"]), confidence=rule_conf_pct)}</span>'
                        f'<br/><span style="color:#64748B;font-size:0.75rem">MITRE: {mitre}</span></div>',
                        unsafe_allow_html=True
                    )
                with col_b:
                    st.markdown(
                        f'<span style="color:#64748B;font-size:0.8rem">{rf["owasp_category"]}</span>',
                        unsafe_allow_html=True
                    )
        else:
            st.success(f"✅ {t('no_rule_patterns')}")

        attack_timeline = build_attack_timeline(df, rule_findings)
        if attack_timeline:
            with st.expander(t("attack_timeline"), expanded=False):
                timeline_df = pd.DataFrame(attack_timeline)
                st.dataframe(
                    timeline_df[["timestamp", "source_ip", "threat_type", "method", "path", "status"]],
                    use_container_width=True,
                    height=220
                )

        st.markdown("---")

        col_btn, col_info = st.columns([2, 3])
        with col_btn:
            analyze_btn = st.button(
                f"⏳ {t('analyzing')}" if st.session_state.analyzing else f"🤖 {t('analyze_with_gemini')}",
                disabled=st.session_state.analyzing or not (st.session_state.api_key_valid and bool(rule_findings)),
                use_container_width=True
            )
        with col_info:
            if not rule_findings:
                st.info(t("no_patterns_to_send"))
            elif not st.session_state.api_key_valid:
                st.info(t("local_scan_available"))
            else:
                st.markdown(
                    f'<div class="status-bar">📡 {t("ready_for_gemini", count=len(rule_findings))}</div>',
                    unsafe_allow_html=True
                )

        if analyze_btn and rule_findings and st.session_state.api_key_valid:
            st.session_state.analyzing = True
            findings = []
            exec_summary = {}
            analysis_ready = False
            try:
                with st.spinner(f"🤖 {t('gemini_logs_spinner')}"):
                    flagged_content = get_flagged_content_for_gemini(rule_findings)
                    pre_labels = summarize_rule_findings(rule_findings)

                    gemini_findings = analyze_logs(
                        flagged_content, pre_labels, st.session_state.api_key
                    )
                    findings = merge_rule_and_gemini_findings(gemini_findings, rule_findings)

                    risk_score, severity_label = compute_risk_score(findings, rule_findings)
                    top_recommendations = generate_top_recommendations(findings)

                    if findings:
                        with st.spinner(f"📝 {t('summary_spinner')}"):
                            exec_summary = generate_executive_summary(
                                findings, risk_score, severity_label, st.session_state.api_key
                            )

                    analysis_id = save_analysis(
                        analysis_type="log",
                        input_filename=log_filename,
                        input_preview=log_content[:500],
                        risk_score=risk_score,
                        severity_label=severity_label,
                        findings=findings,
                        executive_summary=json.dumps(exec_summary),
                        language=st.session_state["language"],
                        top_recommendations=top_recommendations,
                        attack_timeline=attack_timeline
                    )

                    save_uploaded_file(
                        analysis_id, log_filename,
                        len(log_content.encode()), "log",
                        line_count=log_stats.get("total_lines", 0),
                        flagged_count=len(rule_findings)
                    )

                    st.session_state.last_findings = findings
                    st.session_state.last_rule_findings = rule_findings
                    st.session_state.last_risk_score = risk_score
                    st.session_state.last_severity = severity_label
                    st.session_state.last_exec_summary = exec_summary
                    st.session_state.last_top_recommendations = top_recommendations
                    st.session_state.last_attack_timeline = attack_timeline
                    st.session_state.last_analysis_id = analysis_id
                    st.session_state.last_analysis_type = "log"
                    st.session_state.last_input_name = log_filename
                    analysis_ready = True
            except GeminiAPIError as exc:
                st.error(f"{t('gemini_error')}: {exc}")
            finally:
                st.session_state.analyzing = False

            if analysis_ready:
                st.success(f"✅ {t('analysis_complete_threats', count=len(findings))}")
                st.rerun()
    else:
        st.info(t("logs_empty_state"))

# ─── Page: Analyze Code ───────────────────────────────────────────────────────

elif page == "code":
    st.markdown(f"# 💻 {t('code_analysis')}")
    st.markdown(t("code_intro"))
    st.markdown("---")

    if not st.session_state.api_key_valid:
        st.info(f"ℹ️ {t('local_scan_available')}")

    col1, col2 = st.columns([3, 1])
    with col1:
        paste_source = f"✏️ {t('paste_code')}"
        sample_source = f"📁 {t('load_sample')}"
        source = st.radio(t("source"), [paste_source, sample_source],
                          horizontal=True, label_visibility="collapsed")
    with col2:
        language = st.selectbox(t("code_language"), ["PHP", "Python", "JavaScript", "Java", "Other"])

    code_input = ""
    code_filename = f"snippet.{language.lower()}"

    if source == paste_source:
        code_input = st.text_area(
            t("code_snippet"),
            placeholder=t("code_placeholder"),
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
            st.info(f"📁 {t('sample_loaded')}: **{code_filename}**")
            st.code(code_input, language=language.lower())
        else:
            st.warning(t("no_sample_available", language=language))

    if code_input:
        # Rule-based pre-scan on raw text
        st.markdown("---")
        st.markdown(f"### 🔎 {t('static_pre_scan')}")
        empty_df = pd.DataFrame()
        rule_findings = run_rule_detection(empty_df, code_input)

        if rule_findings:
            st.markdown(
                f'<div class="status-bar">⚠️ {t("vulnerability_patterns_detected", count=len(rule_findings)).upper()}</div>',
                unsafe_allow_html=True
            )
            for rf in rule_findings:
                rule_conf_pct = int(float(rf.get("rule_confidence", rf.get("confidence", 0)) or 0) * 100)
                mitre = rf.get("mitre_attack_summary") or format_mitre_attack(rf.get("mitre_attack"))
                st.markdown(
                    f'<div style="padding:8px 0; border-bottom:1px solid #1E2D40">'
                    f'<span style="color:#FF6B35;font-family:monospace">▶ {rf["threat_type"]}</span>'
                    f' — <span style="color:#64748B;font-size:0.8rem">'
                    f'{rf["owasp_category"]} - {t("rule_confidence_short")} {rule_conf_pct}%</span>'
                    f'<br/><span style="color:#64748B;font-size:0.75rem">MITRE: {mitre}</span></div>',
                    unsafe_allow_html=True
                )
        else:
            st.info(t("no_obvious_patterns"))

        col_btn, _ = st.columns([2, 3])
        with col_btn:
            analyze_btn = st.button(
                f"⏳ {t('analyzing')}" if st.session_state.analyzing else f"🤖 {t('analyze_with_gemini')}",
                disabled=st.session_state.analyzing or not st.session_state.api_key_valid,
                use_container_width=True
            )

        if analyze_btn and st.session_state.api_key_valid:
            st.session_state.analyzing = True
            findings = []
            exec_summary = {}
            analysis_ready = False
            try:
                with st.spinner(f"🤖 {t('gemini_code_spinner')}"):
                    pre_labels = summarize_rule_findings(rule_findings)
                    gemini_findings = analyze_code(
                        code_input, language, pre_labels, st.session_state.api_key
                    )
                    findings = merge_rule_and_gemini_findings(gemini_findings, rule_findings)
                    risk_score, severity_label = compute_risk_score(findings, rule_findings)
                    top_recommendations = generate_top_recommendations(findings)

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
                        language=st.session_state["language"],
                        top_recommendations=top_recommendations,
                        attack_timeline=[]
                    )

                    st.session_state.last_findings = findings
                    st.session_state.last_rule_findings = rule_findings
                    st.session_state.last_risk_score = risk_score
                    st.session_state.last_severity = severity_label
                    st.session_state.last_exec_summary = exec_summary
                    st.session_state.last_top_recommendations = top_recommendations
                    st.session_state.last_attack_timeline = []
                    st.session_state.last_analysis_id = analysis_id
                    st.session_state.last_analysis_type = "code"
                    st.session_state.last_input_name = code_filename
                    analysis_ready = True
            except GeminiAPIError as exc:
                st.error(f"{t('gemini_error')}: {exc}")
            finally:
                st.session_state.analyzing = False

            if analysis_ready:
                st.success(f"✅ {t('analysis_complete_vulns', count=len(findings))}")
                st.rerun()
    else:
        st.info(t("code_empty_state"))

# ─── Page: Results ────────────────────────────────────────────────────────────

elif page == "results":
    st.markdown(f"# 📊 {t('analysis_results')}")

    if not st.session_state.last_findings and st.session_state.last_risk_score == 0:
        st.info(t("no_results"))
    else:
        findings = st.session_state.last_findings
        risk_score = st.session_state.last_risk_score
        severity = st.session_state.last_severity
        exec_summary = st.session_state.last_exec_summary
        rule_findings = st.session_state.last_rule_findings
        top_recommendations = st.session_state.last_top_recommendations
        attack_timeline = st.session_state.last_attack_timeline

        # Top summary bar
        col_score, col_info, col_actions = st.columns([2, 4, 2])

        with col_score:
            st.plotly_chart(render_score_gauge(risk_score, severity), use_container_width=True)
            st.markdown(
                f'<div style="text-align:center">{severity_badge(severity)}</div>',
                unsafe_allow_html=True
            )

        with col_info:
            st.markdown(f"### {t('analysis')}: `{st.session_state.last_input_name}`")

            breakdown = get_score_breakdown(findings, rule_findings)
            col_a, col_b, col_c, col_d = st.columns(4)
            col_a.metric(t("findings"), breakdown.get("finding_count", 0))
            col_b.metric(t("avg_confidence"),
                         f"{int(breakdown.get('avg_gemini_confidence', 0)*100)}%")
            col_c.metric(t("flagged_lines"), breakdown.get("flagged_lines_count", 0))
            col_d.metric(t("rule_confidence"), f"{int(breakdown.get('avg_rule_confidence', 0)*100)}%")

            # Severity distribution bar
            sev_dist = breakdown.get("severity_distribution", {})
            if sev_dist:
                sev_df = pd.DataFrame(list(sev_dist.items()), columns=[t("severity"), t("count")])
                colors = {"Critical":"#FF2D2D","High":"#FF6B35","Medium":"#FFB700",
                          "Low":"#22C55E","Informational":"#3B82F6"}
                fig = px.bar(sev_df, x=t("count"), y=t("severity"), orientation="h",
                             color=t("severity"),
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
            st.markdown(f"### {t('quick_actions')}")
            if st.button(f"📄 {t('generate_report')}", use_container_width=True):
                report_text = build_text_report(
                    st.session_state.last_analysis_type,
                    st.session_state.last_input_name,
                    risk_score, severity, findings, exec_summary,
                    rule_findings=rule_findings,
                    attack_timeline=attack_timeline,
                    language=st.session_state["language"],
                    top_recommendations=top_recommendations
                )
                st.download_button(
                    f"⬇️ {t('download_txt')}",
                    data=report_text,
                    file_name=f"threatlens_ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
                    mime="text/plain",
                    use_container_width=True
                )

            json_export = build_json_export(
                st.session_state.last_analysis_type,
                st.session_state.last_input_name,
                risk_score,
                severity,
                findings,
                exec_summary,
                rule_findings=rule_findings,
                top_recommendations=top_recommendations,
                attack_timeline=attack_timeline,
            )
            st.download_button(
                f"⬇️ {t('download_json')}",
                data=json_export,
                file_name=f"threatlens_ai_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
                mime="application/json",
                use_container_width=True
            )

            if st.button(f"🗑️ {t('clear_results')}", use_container_width=True):
                for k in [
                    "last_findings", "last_rule_findings", "last_top_recommendations",
                    "last_attack_timeline"
                ]:
                    st.session_state[k] = []
                st.session_state.last_risk_score = 0
                st.session_state.last_severity = "Clean"
                st.session_state.last_exec_summary = {}
                st.session_state.last_input_name = ""
                st.rerun()

        st.markdown("---")
        st.markdown(f"### ✅ {t('top_3_recommendations')}")
        if top_recommendations:
            for i, recommendation in enumerate(top_recommendations[:3], 1):
                st.markdown(f"**{i}.** {recommendation}")
        else:
            st.info(t("no_recommendations"))

        st.markdown("---")

        # Tabs
        tab1, tab_rec, tab2, tab_mitre, tab3, tab_timeline = st.tabs([
            f"🎯 {t('tab_findings')}",
            f"✅ {t('tab_recommendations')}",
            f"📋 {t('tab_summary')}",
            f"🧭 {t('tab_mitre')}",
            f"🗺️ {t('tab_owasp')}",
            f"⏱️ {t('tab_timeline')}"
        ])

        with tab1:
            if not findings:
                st.success(f"✅ {t('no_threats_detected')}")
            else:
                for i, f in enumerate(findings, 1):
                    finding_card(f, i)

                    # Turkish translation
                    if st.session_state["language"] == "tr" and st.session_state.api_key_valid:
                        with st.expander(f"🇹🇷 {t('turkish_explanation')} — #{i}"):
                            with st.spinner(t("translating")):
                                tr = translate_to_turkish(f, st.session_state.api_key)
                            if tr:
                                st.markdown(f"**{t('simple_explanation')}:** {tr.get('basit_aciklama','')}")
                                st.markdown(f"**{t('what_could_happen')}:** {tr.get('ne_olabilir','')}")
                                st.markdown(f"**{t('business_impact')}:** {tr.get('is_etkisi','')}")
                                steps = tr.get("hemen_yapilacaklar", [])
                                if steps:
                                    st.markdown(f"**{t('what_to_do_now')}:**")
                                    for s in steps:
                                        st.markdown(f"  • {s}")

        with tab_rec:
            if top_recommendations:
                for i, recommendation in enumerate(top_recommendations, 1):
                    st.markdown(f"**{i}.** {recommendation}")
            else:
                st.info(t("no_recommendations"))

        with tab2:
            if exec_summary:
                st.markdown(
                    f'<div class="sentinel-card">'
                    f'<h3 style="font-family:Space Mono;color:#00E5FF;margin-top:0">{t("tab_summary")}</h3>'
                    f'<p style="font-size:1rem;line-height:1.7">{exec_summary.get("summary_paragraph","")}</p>'
                    f'</div>',
                    unsafe_allow_html=True
                )
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"**🚨 {t('top_priority_action')}**")
                    st.error(exec_summary.get("top_priority_action", "N/A"))
                    st.markdown(f"**💼 {t('business_risk')}**")
                    st.warning(exec_summary.get("estimated_business_risk", "N/A"))
                with col2:
                    st.markdown(f"**✅ {t('positive_notes')}**")
                    st.success(exec_summary.get("positive_notes", "N/A"))
                    st.markdown(f"**📋 {t('recommended_next_steps')}**")
                    for i, step in enumerate(exec_summary.get("recommended_next_steps", []), 1):
                        st.markdown(f"{i}. {step}")
            else:
                st.info(t("summary_not_available"))

        with tab_mitre:
            mitre_map = {}
            for f in findings:
                for mapping in f.get("mitre_attack", []) or []:
                    if not isinstance(mapping, dict):
                        continue
                    label = f'{mapping.get("technique_id", "")} {mapping.get("technique", "")}'.strip()
                    tactic = mapping.get("tactic", "Unknown tactic")
                    mitre_map.setdefault(label or "Unknown", {"tactic": tactic, "threats": []})
                    mitre_map[label or "Unknown"]["threats"].append(f.get("threat_type", "Unknown"))

            if mitre_map:
                for label, data in mitre_map.items():
                    with st.expander(f"{label} ({data['tactic']})", expanded=True):
                        for threat in sorted(set(data["threats"])):
                            st.markdown(f"- {threat}")
                        st.caption(f"{t('reference')}: https://attack.mitre.org/")
            else:
                st.info(t("mitre_unavailable"))

        with tab3:
            owasp_map = {}
            for f in findings:
                cat = f.get("owasp_category", t("unknown"))
                mitre = f.get("mitre_attack_summary") or format_mitre_attack(f.get("mitre_attack"))
                owasp_map.setdefault(cat, []).append({
                    "threat": f.get("threat_type", t("unknown")),
                    "mitre": mitre,
                })

            if owasp_map:
                for cat, entries in owasp_map.items():
                    with st.expander(f"📌 {cat}", expanded=True):
                        for entry in entries:
                            st.markdown(f"  ⚔️ {entry['threat']} — MITRE: {entry['mitre']}")
                        st.caption(f"{t('reference')}: https://owasp.org/Top10/")
            else:
                st.info(t("owasp_unavailable"))

        with tab_timeline:
            if attack_timeline:
                timeline_df = pd.DataFrame(attack_timeline)
                st.dataframe(
                    timeline_df[["timestamp", "source_ip", "threat_type", "method", "path", "status"]],
                    use_container_width=True,
                    height=320
                )
                with st.expander(t("timeline_evidence"), expanded=False):
                    for item in attack_timeline[:10]:
                        st.markdown(f'**{item.get("timestamp", "unknown")} - {item.get("threat_type", t("unknown"))}**')
                        st.code(item.get("evidence", ""), language="text")
            else:
                st.info(t("timeline_unavailable"))

# ─── Page: History ────────────────────────────────────────────────────────────

elif page == "history":
    st.markdown(f"# 🕐 {t('analysis_history')}")
    st.markdown("---")

    analyses = get_all_analyses(50)

    if not analyses:
        st.info(t("history_empty"))
    else:
        # Filter controls
        col1, col2 = st.columns([2, 1])
        with col1:
            search = st.text_input(f"🔍 {t('search_by_filename')}", placeholder="e.g. apache, flask...")
        with col2:
            filter_type = st.selectbox(t("filter_by_type"), [t("all"), "log", "code"])

        filtered = [
            a for a in analyses
            if (not search or search.lower() in (a.get("input_filename") or "").lower())
            and (filter_type == t("all") or a.get("analysis_type") == filter_type)
        ]

        st.markdown(f"**{t('records', count=len(filtered))}**")

        for a in filtered:
            sev = a.get("severity_label", "Unknown")
            sev_badge = severity_badge(sev)
            score = a.get("overall_risk_score", 0)
            created = a.get("created_at", "")[:16].replace("T", " ")
            a_type = a.get("analysis_type", "").upper()
            fname = a.get("input_filename", "Unknown")
            n_findings = a.get("total_findings", 0)

            with st.expander(
                f"{sev_badge} {fname} — {t('score')}: {score}/100 — {created}",
                expanded=False
            ):
                col_d, col_act = st.columns([4, 1])
                with col_d:
                    st.markdown(f"**{t('type')}:** {a_type} &nbsp;|&nbsp; **{t('findings')}:** {n_findings} &nbsp;|&nbsp; **{t('language_label')}:** {a.get('language','en').upper()}")
                    detail = get_analysis_detail(a["id"])
                    for finding in detail.get("findings", []):
                        st.markdown(
                            f'<div style="padding:4px 0;border-bottom:1px solid #1E2D40;font-size:0.85rem">'
                            f'<span style="color:#00E5FF">{finding["threat_type"]}</span>'
                            f' — {finding["severity"]} — {finding["owasp_category"]}</div>',
                            unsafe_allow_html=True
                        )
                with col_act:
                    if st.button(f"🗑️ {t('delete')}", key=f"del_{a['id']}"):
                        delete_analysis(a["id"])
                        st.rerun()

                    # Quick report download
                    detail2 = get_analysis_detail(a["id"])
                    analysis_meta = detail2.get("analysis", {})
                    try:
                        stored_summary = json.loads(analysis_meta.get("executive_summary") or "{}")
                    except json.JSONDecodeError:
                        stored_summary = {}
                    report_text = build_text_report(
                        a.get("analysis_type",""),
                        fname, score, sev,
                        detail2.get("findings", []),
                        stored_summary,
                        language=st.session_state["language"],
                        rule_findings=[],
                        attack_timeline=analysis_meta.get("attack_timeline", []),
                        top_recommendations=analysis_meta.get("top_recommendations", [])
                    )
                    st.download_button(
                        f"📄 {t('export')}",
                        data=report_text,
                        file_name=f"threatlens_{a['id']}.txt",
                        key=f"exp_{a['id']}"
                    )

# ─── Page: Reports ────────────────────────────────────────────────────────────

elif page == "reports":
    st.markdown(f"# 📄 {t('report_export')}")
    st.markdown("---")

    if not st.session_state.last_findings and st.session_state.last_risk_score == 0:
        st.info(t("no_active_analysis"))
    else:
        findings = st.session_state.last_findings
        risk_score = st.session_state.last_risk_score
        severity = st.session_state.last_severity
        exec_summary = st.session_state.last_exec_summary
        rule_findings = st.session_state.last_rule_findings
        top_recommendations = st.session_state.last_top_recommendations
        attack_timeline = st.session_state.last_attack_timeline

        st.markdown(f"### 📊 {t('current_analysis_summary')}")
        col1, col2, col3 = st.columns(3)
        col1.metric(t("score"), f"{risk_score}/100")
        col2.metric(t("severity"), severity)
        col3.metric(t("findings"), len(findings))

        st.markdown("---")
        st.markdown(f"### ⬇️ {t('download_report')}")

        report_text = build_text_report(
            st.session_state.last_analysis_type,
            st.session_state.last_input_name,
            risk_score, severity, findings, exec_summary,
            language=st.session_state["language"],
            rule_findings=rule_findings,
            attack_timeline=attack_timeline,
            top_recommendations=top_recommendations
        )

        st.text_area(t("report_preview"), value=report_text[:3000] + "\n...", height=400,
                     label_visibility="collapsed")

        st.download_button(
            label=f"📥 {t('download_full_report')}",
            data=report_text,
            file_name=f"threatlens_ai_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt",
            mime="text/plain",
            use_container_width=True
        )

        st.markdown("---")
        st.markdown(f"### 📋 {t('raw_json_export')}")
        json_export = build_json_export(
            st.session_state.last_analysis_type,
            st.session_state.last_input_name,
            risk_score,
            severity,
            findings,
            exec_summary,
            rule_findings=rule_findings,
            top_recommendations=top_recommendations,
            attack_timeline=attack_timeline,
        )

        st.download_button(
            label=f"📥 {t('download_json')}",
            data=json_export,
            file_name=f"threatlens_ai_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json",
            use_container_width=True
        )
