"""FastAPI service: an inspection endpoint AND a protective LLM gateway.

    uvicorn promptshield.api:app --reload

POST /inspect       — score text, return verdict (no LLM call downstream)
POST /guard/chat    — gateway: inspect the latest user turn; if safe, forward to
                      Groq chat and return the answer; if blocked, refuse.
"""
from __future__ import annotations

import os

import requests
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from . import __version__
from .shield import Shield, Verdict

app = FastAPI(
    title="promptshield",
    version=__version__,
    description="Layered prompt-injection defense (Prompt-Guard-2 + heuristics) and a protective LLM gateway.",
)

shield = Shield()
GROQ_BASE_URL = os.getenv("GROQ_BASE_URL", "https://api.groq.com/openai/v1")
DOWNSTREAM_MODEL = os.getenv("SHIELD_DOWNSTREAM_MODEL", "llama-3.3-70b-versatile")


class InspectIn(BaseModel):
    text: str = Field(..., min_length=1)
    use_classifier: bool = True


class InspectOut(BaseModel):
    verdict: str
    risk: float
    classifier_score: float | None
    heuristic_score: float
    heuristic_hits: list[str]
    notes: list[str]


class Msg(BaseModel):
    role: str
    content: str


class GuardChatIn(BaseModel):
    messages: list[Msg] = Field(..., min_length=1)


@app.get("/healthz")
def healthz() -> dict:
    return {"status": "ok"}


def _inspect(text: str, use_classifier: bool) -> InspectOut:
    s = Shield(use_classifier=use_classifier)
    r = s.inspect(text)
    return InspectOut(
        verdict=r.verdict.value,
        risk=r.risk,
        classifier_score=r.classifier_score,
        heuristic_score=r.heuristic_score,
        heuristic_hits=[h.rule for h in r.heuristic_hits],
        notes=r.notes,
    )


@app.post("/inspect", response_model=InspectOut)
def inspect(body: InspectIn) -> InspectOut:
    return _inspect(body.text, body.use_classifier)


@app.post("/guard/chat")
def guard_chat(body: GuardChatIn) -> dict:
    """Inspect the most recent user message; forward to the LLM only if safe."""
    last_user = next((m for m in reversed(body.messages) if m.role == "user"), None)
    if last_user is None:
        raise HTTPException(status_code=400, detail="No user message to inspect.")

    result = shield.inspect(last_user.content)
    if result.verdict is Verdict.BLOCK:
        return {
            "blocked": True,
            "risk": result.risk,
            "reason": "Prompt-injection attempt detected.",
            "matched_rules": [h.rule for h in result.heuristic_hits],
        }

    key = os.getenv("GROQ_API_KEY", "")
    if not key:
        raise HTTPException(status_code=500, detail="GROQ_API_KEY not configured.")

    resp = requests.post(
        f"{GROQ_BASE_URL}/chat/completions",
        headers={"Authorization": f"Bearer {key}", "Content-Type": "application/json"},
        json={
            "model": DOWNSTREAM_MODEL,
            "messages": [m.model_dump() for m in body.messages],
            "temperature": 0.5,
            "max_tokens": 512,
        },
        timeout=60,
    )
    if not resp.ok:
        raise HTTPException(status_code=502, detail=f"Downstream LLM error: {resp.status_code}")

    answer = resp.json()["choices"][0]["message"]["content"]
    return {"blocked": False, "risk": result.risk, "verdict": result.verdict.value, "answer": answer}
