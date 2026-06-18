FINDING_ANALYSIS_PROMPT = """
You are a senior security engineer. Analyze the following vulnerability finding and provide a structured response.

Finding:
- Type: {vuln_type}
- Severity (if known): {current_severity}
- Location: {location}
- Code snippet: {code}
- CWE: {cwe}
- Description: {message}

Provide a JSON response with the following fields:
{{
  "risk": "Critical|High|Medium|Low",  // Re-evaluate severity with context
  "justification": "One-sentence justification for the risk level",
  "attack_scenario": "A short paragraph describing how this could be exploited",
  "hardening_suggestion": "Specific code fix or configuration change (with before/if applicable)",
  "priority": "Immediate|Next Sprint|Backlog"
}}

Return ONLY valid JSON, no extra text.
"""
