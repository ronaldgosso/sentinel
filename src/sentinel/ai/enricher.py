import json
import hashlib
import sqlite3
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from .client import AIClient
from .prompts import FINDING_ANALYSIS_PROMPT
from rich.console import Console

console = Console()

CACHE_DB = Path.home() / ".sentinel" / "ai_cache.db"


def get_cache_connection() -> sqlite3.Connection:
    CACHE_DB.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(CACHE_DB))
    conn.row_factory = sqlite3.Row
    return conn


def init_cache() -> None:
    with get_cache_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS ai_cache (
                finding_hash TEXT PRIMARY KEY,
                analysis TEXT,
                analyzed_at TIMESTAMP
            )
        """)
        conn.commit()


def get_finding_hash(finding: Dict[str, Any]) -> str:
    """Generate a hash based on rule_id, location, and code snippet."""
    key = f"{finding.get('id')}:{finding.get('location')}:{finding.get('code', '')}"
    return hashlib.md5(key.encode()).hexdigest()


class AIEnricher:
    def __init__(self, api_key: Optional[str] = None, use_local: bool = False) -> None:
        self.client = AIClient(api_key=api_key, use_local=use_local)
        self.available = self.client.is_available()
        init_cache()
        if not self.available:
            if use_local:
                console.print("[yellow]⚠️ Local Ollama unavailable. Falling back to no AI.[/]")
            else:
                console.print(
                    "[yellow]⚠️ No Mistral API key found. Set MISTRAL_API_KEY or use --ai-api-key.[/]"
                )

    def enrich(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Enrich each finding with AI analysis."""
        if not self.available:
            return findings  # no changes

        enriched = []
        for finding in findings:
            # Check cache first
            f_hash = get_finding_hash(finding)
            cached = self._get_cached(f_hash)
            if cached:
                # Merge cached analysis into finding
                finding.update(cached)
                finding["ai_confirmed"] = True
                enriched.append(finding)
                continue

            # Call AI
            analysis = self._analyze_finding(finding)
            if analysis:
                finding.update(analysis)
                finding["ai_confirmed"] = True
                # Cache the result
                self._cache_result(f_hash, analysis)
            else:
                # Fallback: keep original, mark AI as not confirmed
                finding["ai_confirmed"] = False
                # Optionally add placeholder if AI failed
                if not finding.get("fix"):
                    finding["fix"] = "Review and fix manually."
            enriched.append(finding)

        return enriched

    def _analyze_finding(self, finding: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Call AI with prompt and parse JSON response."""
        # Build prompt
        vuln_type = finding.get("id", "unknown").replace("_", " ").title()
        current_severity = finding.get("severity", "Medium")
        location = finding.get("location", "unknown")
        code = finding.get("code", "N/A")
        cwe = finding.get("cwe", "N/A")
        message = finding.get("message", "")

        prompt = FINDING_ANALYSIS_PROMPT.format(
            vuln_type=vuln_type,
            current_severity=current_severity,
            location=location,
            code=code,
            cwe=cwe,
            message=message,
        )

        response = self.client.complete(prompt)
        if not response:
            return None

        # Parse JSON
        try:
            # Try to extract JSON from the response (may contain markdown)
            # Find first { and last }
            start = response.find("{")
            end = response.rfind("}") + 1
            if start == -1 or end == 0:
                return None
            json_str = response[start:end]
            data = json.loads(json_str)
            # Map fields
            result = {
                "severity": data.get("risk", current_severity),
                "justification": data.get("justification", ""),
                "attack_scenario": data.get("attack_scenario", ""),
                "fix": data.get("hardening_suggestion", finding.get("fix", "")),
                "priority": data.get("priority", "Next Sprint"),
            }
            return result
        except Exception as e:
            console.print(f"[red]AI response parsing failed: {e}[/]")
            console.print(f"[dim]Response: {response[:200]}...[/]")
            return None

    def _get_cached(self, f_hash: str) -> Optional[Dict[str, Any]]:
        """Retrieve cached analysis if fresh (< 7 days)."""
        with get_cache_connection() as conn:
            row = conn.execute(
                "SELECT analysis, analyzed_at FROM ai_cache WHERE finding_hash = ?", (f_hash,)
            ).fetchone()
            if row:
                analyzed_at = datetime.fromisoformat(row["analyzed_at"])
                if datetime.now() - analyzed_at < timedelta(days=7):
                    res: Dict[str, Any] = json.loads(row["analysis"])
                    return res
        return None

    def _cache_result(self, f_hash: str, analysis: Dict[str, Any]) -> None:
        """Cache the analysis result."""
        with get_cache_connection() as conn:
            conn.execute(
                "INSERT OR REPLACE INTO ai_cache (finding_hash, analysis, analyzed_at) VALUES (?, ?, ?)",
                (f_hash, json.dumps(analysis), datetime.now().isoformat()),
            )
            conn.commit()
