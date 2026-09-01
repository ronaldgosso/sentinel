import time
from unittest.mock import MagicMock, patch

import pytest

from sentinel.ai.client import DEFAULT_MISTRAL_API_KEY, AIClient
from sentinel.ai.enricher import AIEnricher, get_finding_hash
from sentinel.ai.rate_limiter import RateLimiter


def test_finding_hash() -> None:
    f = {"id": "sql_injection", "location": "auth.py:42", "code": "query = f'SELECT...'"}
    h = get_finding_hash(f)
    assert isinstance(h, str)
    assert len(h) == 64  # SHA256 hex digest length


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


# --- Rate Limiter Tests ---


def test_rate_limiter_pacing() -> None:
    limiter = RateLimiter(requests_per_second=10.0)  # 100ms interval
    assert limiter.is_enabled is True
    assert limiter.min_interval == 0.1

    start = time.time()
    limiter.acquire()
    limiter.acquire()
    elapsed = time.time() - start
    assert elapsed >= 0.08  # Account for slight timer jitter


def test_rate_limiter_disabled() -> None:
    limiter = RateLimiter(requests_per_second=None)
    assert limiter.is_enabled is False
    assert limiter.acquire() == 0.0


def test_rate_limiter_backoff_and_retry_after() -> None:
    limiter = RateLimiter(initial_backoff=1.0, max_backoff=10.0)

    # Test Retry-After header
    delay = limiter.get_backoff_delay(attempt=0, retry_after="5")
    assert delay == 5.0

    # Test exponential backoff
    delay_0 = limiter.get_backoff_delay(attempt=0)
    assert 1.0 <= delay_0 <= 2.0

    delay_1 = limiter.get_backoff_delay(attempt=1)
    assert 2.0 <= delay_1 <= 3.0

    # Max backoff cap
    delay_large = limiter.get_backoff_delay(attempt=10)
    assert delay_large <= 10.0


# --- AIClient Dual-Tier & Key Resolution Tests ---


def test_ai_client_default_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    client = AIClient()
    assert client.api_key == DEFAULT_MISTRAL_API_KEY
    assert client.is_custom_key is False
    assert client.effective_rate_limit == 1.0
    assert client.rate_limiter.is_enabled is True


def test_ai_client_custom_key_env(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MISTRAL_API_KEY", "user-custom-key-123")
    client = AIClient()
    assert client.api_key == "user-custom-key-123"
    assert client.is_custom_key is True
    assert client.effective_rate_limit is None
    assert client.rate_limiter.is_enabled is False


def test_ai_client_custom_key_explicit_arg(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISTRAL_API_KEY", raising=False)
    client = AIClient(api_key="arg-custom-key-456")
    assert client.api_key == "arg-custom-key-456"
    assert client.is_custom_key is True
    assert client.effective_rate_limit is None
    assert client.rate_limiter.is_enabled is False


def test_ai_client_custom_rate_limit_override() -> None:
    client = AIClient(api_key="user-key", rate_limit=5.0)
    assert client.effective_rate_limit == 5.0
    assert client.rate_limiter.is_enabled is True
    assert client.rate_limiter.min_interval == 0.2


# --- AIClient Cloud Completion & Retry Tests ---


def test_ai_client_complete_cloud_success(monkeypatch: pytest.MonkeyPatch) -> None:
    client = AIClient(api_key="test-key")

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"choices": [{"message": {"content": '{"risk": "High"}'}}]}

    with patch("httpx.Client") as mock_httpx:
        instance = mock_httpx.return_value.__enter__.return_value
        instance.post.return_value = mock_resp

        result = client._complete_cloud("Test prompt")
        assert result == '{"risk": "High"}'
        assert instance.post.call_count == 1


def test_ai_client_complete_cloud_retry_on_429(monkeypatch: pytest.MonkeyPatch) -> None:
    client = AIClient(api_key="test-key")
    client.rate_limiter.max_retries = 2
    client.rate_limiter.initial_backoff = 0.01

    mock_429 = MagicMock()
    mock_429.status_code = 429
    mock_429.headers = {"Retry-After": "0.01"}
    mock_429.text = "Too Many Requests"

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.json.return_value = {
        "choices": [{"message": {"content": "Recovered after rate limit"}}]
    }

    with patch("httpx.Client") as mock_httpx, patch("time.sleep"):
        instance = mock_httpx.return_value.__enter__.return_value
        instance.post.side_effect = [mock_429, mock_200]

        result = client._complete_cloud("Test prompt")
        assert result == "Recovered after rate limit"
        assert instance.post.call_count == 2


def test_ai_client_complete_cloud_server_error_retry() -> None:
    client = AIClient(api_key="test-key")
    client.rate_limiter.max_retries = 1
    client.rate_limiter.initial_backoff = 0.01

    mock_503 = MagicMock()
    mock_503.status_code = 503
    mock_503.text = "Service Unavailable"

    mock_200 = MagicMock()
    mock_200.status_code = 200
    mock_200.json.return_value = {"choices": [{"message": {"content": "Recovered from 503"}}]}

    with patch("httpx.Client") as mock_httpx, patch("time.sleep"):
        instance = mock_httpx.return_value.__enter__.return_value
        instance.post.side_effect = [mock_503, mock_200]

        result = client._complete_cloud("Test prompt")
        assert result == "Recovered from 503"
        assert instance.post.call_count == 2
