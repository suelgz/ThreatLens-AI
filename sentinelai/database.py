import sqlite3
import json
from datetime import datetime
from pathlib import Path

DB_PATH = Path(__file__).parent / "sentinelai.db"

def get_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.executescript("""
        CREATE TABLE IF NOT EXISTS analyses (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            created_at TEXT NOT NULL,
            analysis_type TEXT NOT NULL,          -- 'log' or 'code'
            input_filename TEXT,
            input_preview TEXT,
            overall_risk_score INTEGER,
            severity_label TEXT,                  -- Critical / High / Medium / Low / Clean
            total_findings INTEGER DEFAULT 0,
            executive_summary TEXT,
            language TEXT DEFAULT 'en'            -- 'en' or 'tr'
        );

        CREATE TABLE IF NOT EXISTS findings (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            threat_detected INTEGER DEFAULT 1,
            threat_type TEXT,
            severity TEXT,
            confidence REAL,
            evidence TEXT,
            explanation TEXT,
            owasp_category TEXT,
            recommended_fix TEXT,
            business_impact TEXT,
            false_positive_note TEXT,
            pattern_score INTEGER DEFAULT 0,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
        );

        CREATE TABLE IF NOT EXISTS uploaded_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            analysis_id INTEGER NOT NULL,
            filename TEXT,
            file_size INTEGER,
            file_type TEXT,
            uploaded_at TEXT,
            line_count INTEGER DEFAULT 0,
            flagged_line_count INTEGER DEFAULT 0,
            FOREIGN KEY (analysis_id) REFERENCES analyses(id) ON DELETE CASCADE
        );
    """)
    conn.commit()
    conn.close()

def save_analysis(analysis_type, input_filename, input_preview, risk_score,
                  severity_label, findings: list, executive_summary="", language="en"):
    conn = get_connection()
    cursor = conn.cursor()
    now = datetime.now().isoformat()

    cursor.execute("""
        INSERT INTO analyses (created_at, analysis_type, input_filename, input_preview,
                              overall_risk_score, severity_label, total_findings,
                              executive_summary, language)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    """, (now, analysis_type, input_filename, input_preview,
          risk_score, severity_label, len(findings), executive_summary, language))

    analysis_id = cursor.lastrowid

    for f in findings:
        cursor.execute("""
            INSERT INTO findings (analysis_id, threat_detected, threat_type, severity,
                                  confidence, evidence, explanation, owasp_category,
                                  recommended_fix, business_impact, false_positive_note,
                                  pattern_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            analysis_id,
            int(f.get("threat_detected", True)),
            f.get("threat_type", "Unknown"),
            f.get("severity", "Unknown"),
            float(f.get("confidence", 0.5)),
            f.get("evidence", ""),
            f.get("explanation", ""),
            f.get("owasp_category", ""),
            f.get("recommended_fix", ""),
            f.get("business_impact", ""),
            f.get("false_positive_note", ""),
            int(f.get("pattern_score", 0))
        ))

    conn.commit()
    conn.close()
    return analysis_id

def save_uploaded_file(analysis_id, filename, file_size, file_type, line_count=0, flagged_count=0):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO uploaded_files (analysis_id, filename, file_size, file_type,
                                    uploaded_at, line_count, flagged_line_count)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (analysis_id, filename, file_size, file_type,
          datetime.now().isoformat(), line_count, flagged_count))
    conn.commit()
    conn.close()

def get_all_analyses(limit=50):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM analyses ORDER BY created_at DESC LIMIT ?
    """, (limit,))
    rows = [dict(r) for r in cursor.fetchall()]
    conn.close()
    return rows

def get_analysis_detail(analysis_id):
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM analyses WHERE id = ?", (analysis_id,))
    analysis = dict(cursor.fetchone() or {})

    cursor.execute("SELECT * FROM findings WHERE analysis_id = ?", (analysis_id,))
    findings = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT * FROM uploaded_files WHERE analysis_id = ?", (analysis_id,))
    files = [dict(r) for r in cursor.fetchall()]

    conn.close()
    return {"analysis": analysis, "findings": findings, "files": files}

def get_stats():
    conn = get_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT COUNT(*) as total FROM analyses")
    total = cursor.fetchone()["total"]

    cursor.execute("SELECT severity_label, COUNT(*) as cnt FROM analyses GROUP BY severity_label")
    by_severity = {r["severity_label"]: r["cnt"] for r in cursor.fetchall()}

    cursor.execute("SELECT threat_type, COUNT(*) as cnt FROM findings GROUP BY threat_type ORDER BY cnt DESC LIMIT 5")
    top_threats = [dict(r) for r in cursor.fetchall()]

    cursor.execute("SELECT AVG(overall_risk_score) as avg FROM analyses")
    avg_score = cursor.fetchone()["avg"] or 0

    conn.close()
    return {
        "total_analyses": total,
        "by_severity": by_severity,
        "top_threats": top_threats,
        "avg_risk_score": round(avg_score, 1)
    }

def delete_analysis(analysis_id):
    conn = get_connection()
    cursor = conn.cursor()
    cursor.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()

# Initialize on import
init_db()
