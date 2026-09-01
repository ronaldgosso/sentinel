import os
import time

import httpx
from rich.console import Console

from ..utils.config import load_config
from .rate_limiter import RateLimiter

console = Console()

DEFAULT_MISTRAL_API_KEY = "tGBWwpZqi2CZUns8r0Y7ANAEEYypNtx5"


class AIClient:
    """Client for interacting with Mistral (local Ollama or cloud API)."""

    def __init__(
        self,
        api_key: str | None = None,
        use_local: bool = False,
        rate_limit: float | None = None,
        model: str | None = None,
    ) -> None:
        cfg = load_config()
        configured_key = cfg.get("mistral_api_key")

        if api_key:
            self.api_key: str | None = api_key
            self.is_custom_key = True
        elif os.getenv("MISTRAL_API_KEY"):
            self.api_key = os.getenv("MISTRAL_API_KEY")
            self.is_custom_key = True
        elif configured_key:
            self.api_key = str(configured_key)
            self.is_custom_key = True
        else:
            self.api_key = DEFAULT_MISTRAL_API_KEY
            self.is_custom_key = False

        self.use_local = use_local
        self.local_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = model or os.getenv("MISTRAL_MODEL", "mistral:7b-instruct")
        self.cloud_model = (
            model
            or os.getenv("MISTRAL_CLOUD_MODEL")
            or os.getenv("MISTRAL_MODEL")
            or cfg.get("ai_cloud_model")
            or "mistral-small-latest"
        )
        self.timeout = 30.0

        # Determine rate limiting:
        # If rate_limit is explicitly passed, use it.
        # Otherwise: if using default key, default to 1.0 req/s. If custom key, unrestricted (None).
        if rate_limit is not None:
            self.effective_rate_limit: float | None = rate_limit
        elif not self.is_custom_key:
            env_limit = os.getenv("MISTRAL_RATE_LIMIT")
            self.effective_rate_limit = float(env_limit) if env_limit else 1.0
        else:
            self.effective_rate_limit = None

        self.rate_limiter = RateLimiter(requests_per_second=self.effective_rate_limit)

    def is_available(self) -> bool:
        """Check if AI is available (either local or cloud)."""
        if self.use_local:
            return self._check_local()
        else:
            return bool(self.api_key)

    def _check_local(self) -> bool:
        """Check if Ollama is running and model is available."""
        try:
            with httpx.Client(timeout=2.0) as client:
                resp = client.get(f"{self.local_url}/api/tags")
                if resp.status_code == 200:
                    models = resp.json().get("models", [])
                    for m in models:
                        if self.model in m.get("name", ""):
                            return True
                    console.print(
                        f"[yellow]⚠️ Model '{self.model}' not found in Ollama. Please pull it: ollama pull {self.model}[/]"
                    )
                    return False
                return False
        except Exception:  # noqa: BLE001
            return False

    def complete(self, prompt: str) -> str | None:
        """Send a prompt to AI and return the response text."""
        if self.use_local:
            return self._complete_local(prompt)
        else:
            return self._complete_cloud(prompt)

    def _complete_local(self, prompt: str) -> str | None:
        """Call Ollama API."""
        url = f"{self.local_url}/api/generate"
        payload = {
            "model": self.model,
            "prompt": prompt,
            "stream": False,
        }
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload)
                if resp.status_code == 200:
                    data = resp.json()
                    return str(data.get("response", "")).strip()
                else:
                    console.print(f"[red]Ollama error: {resp.text}[/]")
                    return None
        except Exception as e:  # noqa: BLE001
            console.print(f"[red]Ollama request failed: {e}[/]")
            return None

    def _complete_cloud(self, prompt: str) -> str | None:
        """Call Mistral AI API with rate limiting and exponential backoff retry."""
        if not self.api_key:
            console.print("[red]MISTRAL_API_KEY not set. Provide it via env or --ai-api-key.[/]")
            return None

        url = "https://api.mistral.ai/v1/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }
        payload = {
            "model": self.cloud_model,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.2,
        }

        for attempt in range(self.rate_limiter.max_retries + 1):
            self.rate_limiter.acquire()
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, json=payload, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        return str(data["choices"][0]["message"]["content"]).strip()
                    elif resp.status_code == 429:
                        if attempt < self.rate_limiter.max_retries:
                            retry_after = resp.headers.get("Retry-After")
                            delay = self.rate_limiter.get_backoff_delay(attempt, retry_after)
                            console.print(
                                f"[yellow]⏳ Rate limit reached. Retrying in {delay:.1f}s (attempt {attempt + 1}/{self.rate_limiter.max_retries})...[/]"
                            )
                            time.sleep(delay)
                            continue
                        else:
                            console.print(
                                f"[red]Mistral API rate limit exceeded after {self.rate_limiter.max_retries} retries.[/]"
                            )
                            return None
                    elif resp.status_code in (500, 502, 503, 504):
                        if attempt < self.rate_limiter.max_retries:
                            delay = self.rate_limiter.get_backoff_delay(attempt)
                            console.print(
                                f"[yellow]⚠️ Mistral server error ({resp.status_code}). Retrying in {delay:.1f}s...[/]"
                            )
                            time.sleep(delay)
                            continue
                        else:
                            console.print(
                                f"[red]Mistral server error {resp.status_code}: {resp.text}[/]"
                            )
                            return None
                    else:
                        console.print(
                            f"[red]Mistral API error ({resp.status_code}): {resp.text}[/]"
                        )
                        return None
            except httpx.RequestError as e:
                if attempt < self.rate_limiter.max_retries:
                    delay = self.rate_limiter.get_backoff_delay(attempt)
                    console.print(
                        f"[yellow]⚠️ Mistral request error: {e}. Retrying in {delay:.1f}s...[/]"
                    )
                    time.sleep(delay)
                    continue
                else:
                    console.print(f"[red]Mistral request failed after retries: {e}[/]")
                    return None
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]Mistral request unexpected error: {e}[/]")
                return None

        return None
