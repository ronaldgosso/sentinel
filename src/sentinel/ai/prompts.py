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

AUTOFIX_PROMPT = """
You are an expert security engineer and Python developer.
We found a vulnerability in the following code.
Vulnerability: {vuln_type}
Location: {location}
Description: {message}

Here is the code block containing the vulnerability:
```python
{code_context}
```

Please fix the vulnerability. Provide the EXACT original text that needs to be replaced, and the EXACT replacement text.
Return your response as a valid JSON object with the following format:
{{
  "target": "exact string to replace (must match the source code perfectly)",
  "replacement": "the secure code to replace it with"
}}

IMPORTANT:
- Only return the JSON. No markdown formatting, no explanations.
- The `target` string must be an exact substring of the original code block so that `source.replace(target, replacement)` works.
"""
