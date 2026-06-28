"""Meta Prompt-Guard-2 classifier, served via Groq.

The model returns a single float in [0, 1] — the probability that the input is a
prompt-injection / jailbreak attempt. We wrap it with retries and a clean error
type so the Shield can fall back to heuristics if the network is down.
"""
from __future__ import annotations

import os
import time

import requests

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:  # pragma: no cover
    pass

GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
GUARD_MODEL = os.getenv("SHIELD_GUARD_MODEL", "meta-llama/llama-prompt-guard-2-86m")


class ClassifierError(RuntimeError):
    pass


def _api_key() -> str:
    key = os.getenv("GROQ_API_KEY", "")
    if not key:
        raise RuntimeError("GROQ_API_KEY is not set. Copy .env.example to .env and add your key.")
    return key


def classify(text: str, *, max_retries: int = 2) -> float:
    """Return injection probability in [0, 1]."""
    url = f"{GROQ_BASE_URL}/chat/completions"
    payload = {"model": GUARD_MODEL, "messages": [{"role": "user", "content": text}]}
    headers = {"Authorization": f"Bearer {_api_key()}", "Content-Type": "application/json"}

    last_err: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=30)
            if resp.status_code in (429, 500, 502, 503):
                raise ClassifierError(f"transient {resp.status_code}")
            resp.raise_for_status()
            content = resp.json()["choices"][0]["message"]["content"]
            return _parse_score(content)
        except (requests.RequestException, ClassifierError, KeyError, ValueError) as exc:
            last_err = exc
            if attempt < max_retries:
                time.sleep(1.5**attempt)
    raise ClassifierError(f"Prompt-Guard classification failed: {last_err}")


def _parse_score(content: str) -> float:
    try:
        score = float(str(content).strip())
    except ValueError as exc:
        raise ClassifierError(f"Unexpected classifier output: {content!r}") from exc
    return max(0.0, min(1.0, score))
