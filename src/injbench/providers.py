"""Minimal OpenAI-compatible chat client (stdlib only) for free-tier providers."""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class Model:
    key: str          # short id used in results
    provider: str
    name: str         # provider's model id
    min_interval: float  # seconds between calls, to stay under free-tier limits


PROVIDERS = {
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai/chat/completions", "GEMINI_API_KEY"),
    "groq": ("https://api.groq.com/openai/v1/chat/completions", "GROQ_API_KEY"),
    "mistral": ("https://api.mistral.ai/v1/chat/completions", "MISTRAL_API_KEY"),
}

MODELS = (
    Model("gemini-flash", "gemini", "gemini-flash-latest", 6.5),
    Model("gemini-flash-lite", "gemini", "gemini-flash-lite-latest", 4.5),
    Model("gpt-oss-120b", "groq", "openai/gpt-oss-120b", 2.5),
    Model("gpt-oss-20b", "groq", "openai/gpt-oss-20b", 2.5),
    Model("qwen3.8-27b", "groq", "qwen/qwen3.8-27b", 2.5),
    Model("mistral-small", "mistral", "mistral-small-latest", 1.5),
)


def load_env(path: Path = Path(".env")) -> None:
    if not path.exists():
        return
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        os.environ.setdefault(k.strip(), v.strip())


def available(models=MODELS) -> list[Model]:
    return [m for m in models if os.environ.get(PROVIDERS[m.provider][1])]


class RateLimited(Exception):
    pass


_last_call: dict[str, float] = {}


def chat(model: Model, messages: list[dict], temperature: float = 0.2, retries: int = 5) -> str:
    url, env = PROVIDERS[model.provider]
    body = {
        "model": model.name,
        "messages": messages,
        "temperature": temperature,
        "response_format": {"type": "json_object"},
    }
    data = json.dumps(body).encode("utf-8")
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {os.environ[env]}",
        # Groq's edge rejects the default Python-urllib agent with Cloudflare error 1010
        "User-Agent": "injbench/0.1 (+https://github.com/nekodu/nis2-pipeline-prompt-injection)",
    }
    for attempt in range(retries):
        wait = model.min_interval - (time.monotonic() - _last_call.get(model.key, 0.0))
        if wait > 0:
            time.sleep(wait)
        _last_call[model.key] = time.monotonic()
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=60) as resp:
                payload = json.loads(resp.read().decode("utf-8"))
            return payload["choices"][0]["message"]["content"] or ""
        except urllib.error.HTTPError as e:
            # 429 and transient 5xx get a back-off; anything else is a real error
            if e.code == 429 or e.code >= 500:
                time.sleep(min(60, 5 * 2**attempt))
                continue
            body_text = e.read().decode("utf-8", "replace")
            # Groq's JSON mode rejects invalid output with a 400; that is a result
            # (the model broke the format), not a client error, so score it.
            if e.code == 400 and "json_validate_failed" in body_text:
                try:
                    return json.loads(body_text)["error"].get("failed_generation") or ""
                except (json.JSONDecodeError, KeyError):
                    return ""
            raise RuntimeError(f"{model.key}: HTTP {e.code}: {body_text[:300]}") from None
        except (urllib.error.URLError, TimeoutError):
            time.sleep(5 * (attempt + 1))
    raise RateLimited(f"{model.key}: gave up after {retries} attempts")
