import re
import pandas as pd
from io import StringIO

# Apache Combined Log Format pattern
APACHE_PATTERN = re.compile(
    r'(?P<ip>\S+)\s+\S+\s+\S+\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d+)\s+(?P<size>\S+)'
    r'(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

def parse_apache_log(content: str) -> pd.DataFrame:
    rows = []
    for line in content.strip().splitlines():
        line = line.strip()
        if not line:
            continue
        m = APACHE_PATTERN.match(line)
        if m:
            rows.append({
                "ip": m.group("ip"),
                "time": m.group("time"),
                "method": m.group("method"),
                "path": m.group("path"),
                "status": int(m.group("status")),
                "size": m.group("size"),
                "agent": m.group("agent") or "",
                "raw": line
            })
        else:
            rows.append({
                "ip": "", "time": "", "method": "", "path": "",
                "status": 0, "size": "", "agent": "", "raw": line
            })
    return pd.DataFrame(rows) if rows else pd.DataFrame(
        columns=["ip", "time", "method", "path", "status", "size", "agent", "raw"]
    )

def parse_generic_log(content: str) -> pd.DataFrame:
    rows = [{"raw": line.strip()} for line in content.strip().splitlines() if line.strip()]
    return pd.DataFrame(rows)

def detect_log_format(content: str) -> str:
    sample = content[:2000]
    if APACHE_PATTERN.search(sample):
        return "apache"
    return "generic"

def parse_log_file(content: str) -> tuple[pd.DataFrame, str]:
    fmt = detect_log_format(content)
    if fmt == "apache":
        df = parse_apache_log(content)
    else:
        df = parse_generic_log(content)
    return df, fmt

def get_log_stats(df: pd.DataFrame) -> dict:
    stats = {"total_lines": len(df)}
    if "status" in df.columns and df["status"].any():
        stats["status_counts"] = df["status"].value_counts().to_dict()
    if "ip" in df.columns:
        stats["unique_ips"] = df["ip"].nunique()
        stats["top_ips"] = df["ip"].value_counts().head(5).to_dict()
    if "method" in df.columns:
        stats["methods"] = df["method"].value_counts().to_dict()
    return stats
