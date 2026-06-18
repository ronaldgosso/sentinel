import pytest
from sentinel.ai.enricher import AIEnricher, get_finding_hash


def test_finding_hash() -> None:
    f = {"id": "sql_injection", "location": "auth.py:42", "code": "query = f'SELECT...'"}
    h = get_finding_hash(f)
    assert isinstance(h, str)
    assert len(h) == 32


# Mock client for testing
class MockClient:
    def complete(self, prompt: str) -> str:
        return '{"risk": "High", "justification": "test", "attack_scenario": "test", "hardening_suggestion": "fix", "priority": "Immediate"}'


def test_enricher_mock(monkeypatch: pytest.MonkeyPatch) -> None:
    enricher = AIEnricher(use_local=True)
    # Override client with mock
    enricher.client = MockClient()  # type: ignore[assignment]
    enricher.available = True
    findings = [{"id": "test", "severity": "Medium", "location": "x.py", "code": "test"}]
    enriched = enricher.enrich(findings)
    assert enriched[0].get("ai_confirmed") is True
    assert "fix" in enriched[0]
