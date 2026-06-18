import os
from typing import Optional
import httpx
from rich.console import Console

console = Console()


class AIClient:
    """Client for interacting with Mistral (local Ollama or cloud API)."""

    def __init__(self, api_key: Optional[str] = None, use_local: bool = False) -> None:
        self.api_key = api_key or os.getenv("MISTRAL_API_KEY")
        self.use_local = use_local
        self.local_url = os.getenv("OLLAMA_URL", "http://localhost:11434")
        self.model = os.getenv("MISTRAL_MODEL", "mistral:7b-instruct")
        self.cloud_model = "mistral-tiny"  # or mistral-small, etc.
        self.timeout = 30.0

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
        except Exception:
            return False

    def complete(self, prompt: str) -> Optional[str]:
        """Send a prompt to AI and return the response text."""
        if self.use_local:
            return self._complete_local(prompt)
        else:
            return self._complete_cloud(prompt)

    def _complete_local(self, prompt: str) -> Optional[str]:
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
        except Exception as e:
            console.print(f"[red]Ollama request failed: {e}[/]")
            return None

    def _complete_cloud(self, prompt: str) -> Optional[str]:
        """Call Mistral AI API."""
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
        try:
            with httpx.Client(timeout=self.timeout) as client:
                resp = client.post(url, json=payload, headers=headers)
                if resp.status_code == 200:
                    data = resp.json()
                    return str(data["choices"][0]["message"]["content"]).strip()
                else:
                    console.print(f"[red]Mistral API error: {resp.text}[/]")
                    return None
        except Exception as e:
            console.print(f"[red]Mistral request failed: {e}[/]")
            return None
