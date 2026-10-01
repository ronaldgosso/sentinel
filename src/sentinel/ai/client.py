from __future__ import annotations

import os
import time
from typing import Any

import httpx
from rich.console import Console

from ..utils.config import load_config
from .rate_limiter import RateLimiter

console = Console()

VENDOR_CONFIGS: dict[str, dict[str, Any]] = {
    "mistral": {
        "display_name": "Mistral AI",
        "env_key": "MISTRAL_API_KEY",
        "config_key": "mistral_api_key",
        "default_model": "mistral-small-latest",
        "endpoint": "https://api.mistral.ai/v1/chat/completions",
        "protocol": "openai",
        "models": [
            "mistral-small-latest",
            "codestral-latest",
            "mistral-large-latest",
            "open-mixtral-8x7b",
        ],
    },
    "openai": {
        "display_name": "OpenAI",
        "env_key": "OPENAI_API_KEY",
        "config_key": "openai_api_key",
        "default_model": "gpt-4o-mini",
        "endpoint": "https://api.openai.com/v1/chat/completions",
        "protocol": "openai",
        "models": ["gpt-4o-mini", "gpt-4o", "gpt-3.5-turbo", "o1-mini"],
    },
    "anthropic": {
        "display_name": "Anthropic",
        "env_key": "ANTHROPIC_API_KEY",
        "config_key": "anthropic_api_key",
        "default_model": "claude-3-5-haiku-20241022",
        "endpoint": "https://api.anthropic.com/v1/messages",
        "protocol": "anthropic",
        "models": [
            "claude-3-5-haiku-20241022",
            "claude-3-5-sonnet-20241022",
            "claude-3-opus-20240229",
        ],
    },
    "gemini": {
        "display_name": "Google Gemini",
        "env_key": "GEMINI_API_KEY",
        "config_key": "gemini_api_key",
        "default_model": "gemini-1.5-flash",
        "endpoint": "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent",
        "protocol": "gemini",
        "models": ["gemini-1.5-flash", "gemini-1.5-pro", "gemini-2.0-flash"],
    },
    "groq": {
        "display_name": "Groq",
        "env_key": "GROQ_API_KEY",
        "config_key": "groq_api_key",
        "default_model": "llama-3.3-70b-versatile",
        "endpoint": "https://api.groq.com/openai/v1/chat/completions",
        "protocol": "openai",
        "models": ["llama-3.3-70b-versatile", "llama-3.1-8b-instant", "mixtral-8x7b-32768"],
    },
    "ollama": {
        "display_name": "Ollama (Local)",
        "env_key": None,
        "config_key": None,
        "default_model": "mistral:7b-instruct",
        "endpoint": "http://localhost:11434/api/generate",
        "protocol": "ollama",
        "models": ["mistral:7b-instruct", "codellama", "llama3", "deepseek-coder"],
    },
}


class AIClient:
    """Client for interacting with multiple AI providers (Mistral, OpenAI, Anthropic, Gemini, Groq, Ollama)."""

    def __init__(
        self,
        api_key: str | None = None,
        vendor: str | None = None,
        use_local: bool = False,
        rate_limit: float | None = None,
        model: str | None = None,
    ) -> None:
        cfg = load_config()

        # Resolve vendor
        resolved_vendor = (vendor or "").lower().strip()
        if use_local or resolved_vendor in ("local", "ollama"):
            self.vendor = "ollama"
            self.use_local = True
        elif resolved_vendor in VENDOR_CONFIGS:
            self.vendor = resolved_vendor
            self.use_local = False
        elif os.getenv("AI_VENDOR"):
            self.vendor = os.getenv("AI_VENDOR", "").lower().strip()
            self.use_local = self.vendor == "ollama"
        elif cfg.get("ai_vendor"):
            self.vendor = str(cfg.get("ai_vendor")).lower().strip()
            self.use_local = self.vendor == "ollama"
        else:
            self.vendor = "mistral"
            self.use_local = False

        self.vendor_info = VENDOR_CONFIGS.get(self.vendor, VENDOR_CONFIGS["mistral"])
        self.vendor_name: str = self.vendor_info["display_name"]

        # Resolve API Key
        env_key = self.vendor_info.get("env_key")
        config_key = self.vendor_info.get("config_key")
        configured_key = cfg.get(config_key) if config_key else None

        if api_key:
            self.api_key: str | None = api_key
            self.is_custom_key = True
        elif env_key and os.getenv(env_key):
            self.api_key = os.getenv(env_key)
            self.is_custom_key = True
        elif configured_key:
            self.api_key = str(configured_key)
            self.is_custom_key = True
        else:
            self.api_key = None
            self.is_custom_key = False

        self.local_url = os.getenv("OLLAMA_URL", "http://localhost:11434")

        # Resolve Model
        vendor_env_model = f"{self.vendor.upper()}_MODEL"
        self.model: str = (
            model
            or os.getenv("AI_MODEL")
            or os.getenv(vendor_env_model)
            or (os.getenv("MISTRAL_MODEL") if self.vendor == "mistral" else None)
            or (cfg.get(f"{self.vendor}_model"))
            or (cfg.get("ai_cloud_model") if self.vendor == "mistral" else None)
            or self.vendor_info["default_model"]
        )
        self.cloud_model = self.model
        self.timeout = 30.0

        # Determine rate limiting:
        if rate_limit is not None:
            self.effective_rate_limit: float | None = rate_limit
        elif os.getenv("MISTRAL_RATE_LIMIT") and self.vendor == "mistral":
            try:
                self.effective_rate_limit = float(os.getenv("MISTRAL_RATE_LIMIT", ""))
            except ValueError:
                self.effective_rate_limit = None
        elif os.getenv("AI_RATE_LIMIT"):
            try:
                self.effective_rate_limit = float(os.getenv("AI_RATE_LIMIT", ""))
            except ValueError:
                self.effective_rate_limit = None
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
        """Call AI provider API with rate limiting and exponential backoff retry."""
        if not self.api_key:
            env_hint = self.vendor_info.get("env_key") or "API key"
            console.print(
                f"[red]{self.vendor_name} API key not set. Provide it via --ai-api-key or {env_hint}.[/]"
            )
            return None

        protocol = self.vendor_info.get("protocol", "openai")
        if protocol == "openai":
            url = str(self.vendor_info["endpoint"])
            headers = {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
            payload: dict[str, Any] = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "temperature": 0.2,
            }
        elif protocol == "anthropic":
            url = str(self.vendor_info["endpoint"])
            headers = {
                "x-api-key": str(self.api_key),
                "anthropic-version": "2023-06-01",
                "Content-Type": "application/json",
            }
            payload = {
                "model": self.model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": 2048,
                "temperature": 0.2,
            }
        elif protocol == "gemini":
            base_url = str(self.vendor_info["endpoint"]).format(model=self.model)
            url = f"{base_url}?key={self.api_key}"
            headers = {
                "Content-Type": "application/json",
            }
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.2,
                },
            }
        else:
            console.print(
                f"[red]Unsupported protocol '{protocol}' for vendor {self.vendor_name}.[/]"
            )
            return None

        for attempt in range(self.rate_limiter.max_retries + 1):
            self.rate_limiter.acquire()
            try:
                with httpx.Client(timeout=self.timeout) as client:
                    resp = client.post(url, json=payload, headers=headers)
                    if resp.status_code == 200:
                        data = resp.json()
                        if protocol == "openai":
                            return str(data["choices"][0]["message"]["content"]).strip()
                        elif protocol == "anthropic":
                            return str(data["content"][0]["text"]).strip()
                        elif protocol == "gemini":
                            return str(
                                data["candidates"][0]["content"]["parts"][0]["text"]
                            ).strip()
                        return None
                    elif resp.status_code == 401:
                        console.print(
                            f"[red]❌ {self.vendor_name} authentication failed (401): Invalid API key.[/]"
                        )
                        return None
                    elif resp.status_code == 429:
                        if attempt < self.rate_limiter.max_retries:
                            retry_after = resp.headers.get("Retry-After")
                            delay = self.rate_limiter.get_backoff_delay(attempt, retry_after)
                            console.print(
                                f"[yellow]⏳ {self.vendor_name} rate limit reached. Retrying in {delay:.1f}s (attempt {attempt + 1}/{self.rate_limiter.max_retries})...[/]"
                            )
                            time.sleep(delay)
                            continue
                        else:
                            console.print(
                                f"[red]{self.vendor_name} rate limit exceeded after {self.rate_limiter.max_retries} retries.[/]"
                            )
                            return None
                    elif resp.status_code in (500, 502, 503, 504):
                        if attempt < self.rate_limiter.max_retries:
                            delay = self.rate_limiter.get_backoff_delay(attempt)
                            console.print(
                                f"[yellow]⚠️ {self.vendor_name} server error ({resp.status_code}). Retrying in {delay:.1f}s...[/]"
                            )
                            time.sleep(delay)
                            continue
                        else:
                            console.print(
                                f"[red]{self.vendor_name} server error {resp.status_code}: {resp.text}[/]"
                            )
                            return None
                    else:
                        console.print(
                            f"[red]{self.vendor_name} API error ({resp.status_code}): {resp.text}[/]"
                        )
                        return None
            except httpx.RequestError as e:
                if attempt < self.rate_limiter.max_retries:
                    delay = self.rate_limiter.get_backoff_delay(attempt)
                    console.print(
                        f"[yellow]⚠️ {self.vendor_name} request error: {e}. Retrying in {delay:.1f}s...[/]"
                    )
                    time.sleep(delay)
                    continue
                else:
                    console.print(f"[red]{self.vendor_name} request failed after retries: {e}[/]")
                    return None
            except Exception as e:  # noqa: BLE001
                console.print(f"[red]{self.vendor_name} unexpected error: {e}[/]")
                return None

        return None
