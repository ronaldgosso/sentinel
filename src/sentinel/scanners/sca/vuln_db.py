import sqlite3
import json
from pathlib import Path
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import httpx

DB_PATH = Path.home() / ".sentinel" / "vuln_cache.db"


def get_db_connection() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Create tables if they don't exist."""
    with get_db_connection() as conn:
        # Check if cache table needs migration (does it have 'ecosystem' column?)
        cursor = conn.execute("PRAGMA table_info(cache)")
        columns = [row["name"] for row in cursor.fetchall()]
        if columns and "ecosystem" not in columns:
            conn.execute("DROP TABLE cache")

        conn.execute("""
            CREATE TABLE IF NOT EXISTS cache (
                package TEXT,
                version TEXT,
                ecosystem TEXT,
                vuln_data TEXT,   -- JSON list of vulnerabilities
                queried_at TIMESTAMP,
                PRIMARY KEY (package, version, ecosystem)
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS nvd_cache (
                cve_id TEXT PRIMARY KEY,
                cvss_score REAL,
                cvss_severity TEXT,
                queried_at TIMESTAMP
            )
        """)
        conn.commit()


def query_osv(package: str, version: str, ecosystem: str = "PyPI") -> Any:
    """Query OSV.dev API for vulnerabilities of a specific package version."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package, "ecosystem": ecosystem},
        "version": version,
    }
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.post(url, json=payload)
            if resp.status_code == 200:
                data = resp.json()
                return data.get("vulns", [])
            else:
                return []
    except Exception:
        return []


def get_cvss_from_nvd(cve_id: str) -> Optional[Dict[str, Any]]:
    """Fetch CVSS details from NVD API (cached)."""
    # Check cache first
    with get_db_connection() as conn:
        row = conn.execute(
            "SELECT cvss_score, cvss_severity FROM nvd_cache WHERE cve_id = ? AND queried_at > ?",
            (cve_id, datetime.now() - timedelta(days=7)),
        ).fetchone()
        if row:
            return {"score": row["cvss_score"], "severity": row["cvss_severity"]}

    # Not cached or expired, fetch from NVD
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        with httpx.Client(timeout=10.0) as client:
            resp = client.get(url)
            if resp.status_code == 200:
                data = resp.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    cve = vulns[0].get("cve", {})
                    metrics = cve.get("metrics", {})
                    cvss_v3 = metrics.get("cvssMetricV31", [])
                    if cvss_v3:
                        cvss_data = cvss_v3[0].get("cvssData", {})
                        score = cvss_data.get("baseScore")
                        severity = cvss_data.get("baseSeverity")
                        # Cache it
                        with get_db_connection() as conn:
                            conn.execute(
                                "INSERT OR REPLACE INTO nvd_cache (cve_id, cvss_score, cvss_severity, queried_at) VALUES (?, ?, ?, ?)",
                                (cve_id, score, severity, datetime.now()),
                            )
                            conn.commit()
                        return {"score": score, "severity": severity}
    except Exception:
        pass
    return None


def get_vulnerabilities(
    package: str, version: str, ecosystem: str = "PyPI", force_refresh: bool = False
) -> Any:
    """Get vulnerabilities for a package version, with caching."""
    if not version:
        return []  # we need a version to query OSV

    # Check cache
    if not force_refresh:
        with get_db_connection() as conn:
            row = conn.execute(
                "SELECT vuln_data, queried_at FROM cache WHERE package = ? AND version = ? AND ecosystem = ?",
                (package, version, ecosystem),
            ).fetchone()
            if row:
                # refresh if older than 24h
                queried_at = datetime.fromisoformat(row["queried_at"])
                if datetime.now() - queried_at < timedelta(hours=24):
                    return json.loads(row["vuln_data"])

    # Query OSV
    vulns = query_osv(package, version, ecosystem)
    # Enrich with CVSS from NVD
    for vuln in vulns:
        cve_id = vuln.get("id")  # e.g., CVE-2023-...
        if cve_id and cve_id.startswith("CVE-"):
            cvss = get_cvss_from_nvd(cve_id)
            if cvss:
                vuln["cvss_score"] = cvss["score"]
                vuln["cvss_severity"] = cvss["severity"]
        # OSV may already have severity, but we'll overwrite with NVD if available

    # Cache
    with get_db_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO cache (package, version, ecosystem, vuln_data, queried_at) VALUES (?, ?, ?, ?, ?)",
            (package, version, ecosystem, json.dumps(vulns), datetime.now().isoformat()),
        )
        conn.commit()

    return vulns
