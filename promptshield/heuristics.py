"""Fast, local, zero-cost heuristics for known injection / jailbreak patterns.

These run before (and independently of) the ML classifier. They give explainable
hits ("matched: ignore previous instructions") and catch obvious attacks even if
the network/classifier is unavailable. Each rule has a weight; the heuristic
score is the saturated sum of matched weights.
"""
from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class HeuristicHit:
    rule: str
    weight: float
    snippet: str


# (name, weight, compiled regex). Weights are tuned so a single strong signal
# (e.g. "ignore previous instructions") is already alarming on its own.
_RULES: list[tuple[str, float, re.Pattern]] = [
    (
        "ignore_previous_instructions",
        0.9,
        re.compile(r"\bignore\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|prompts?|messages?|context)", re.I),
    ),
    (
        "disregard_instructions",
        0.85,
        re.compile(r"\b(?:disregard|forget|override|bypass)\s+(?:all\s+)?(?:your\s+)?(?:previous\s+)?(?:instructions?|rules?|guidelines?|system\s+prompt)", re.I),
    ),
    (
        "reveal_system_prompt",
        0.8,
        re.compile(r"\b(?:reveal|show|print|repeat|output|leak|tell\s+me)\b.{0,30}\b(?:system\s+prompt|your\s+instructions?|initial\s+prompt|the\s+prompt\s+above)", re.I),
    ),
    (
        "role_override",
        0.7,
        re.compile(r"\byou\s+are\s+now\b|\bfrom\s+now\s+on\s+you\b|\bact\s+as\s+(?:if\s+you\s+are\s+)?(?:a\s+)?(?:dan|jailbroken|unrestricted|developer\s+mode)", re.I),
    ),
    (
        "dan_jailbreak",
        0.85,
        re.compile(r"\b(?:do\s+anything\s+now|DAN\s+mode|developer\s+mode\s+enabled|jailbreak)\b", re.I),
    ),
    (
        "fake_system_tag",
        0.75,
        re.compile(r"</?(?:system|assistant|user)>|\[(?:system|INST|/INST)\]|<\|im_start\|>", re.I),
    ),
    (
        "no_restrictions",
        0.6,
        re.compile(r"\b(?:without\s+(?:any\s+)?restrictions?|no\s+(?:longer\s+)?(?:bound|restricted|limited)|ignore\s+(?:your\s+)?(?:safety|guidelines?|policy|policies))", re.I),
    ),
    (
        "encoded_payload",
        0.4,
        re.compile(r"\b(?:base64|rot13|decode\s+the\s+following|reverse\s+this\s+string)\b", re.I),
    ),
    (
        "exfiltration",
        0.5,
        re.compile(r"\b(?:send|post|exfiltrate|forward)\b.{0,40}\b(?:to\s+https?://|api\s+key|secret|password|token)", re.I),
    ),
]


def scan_heuristics(text: str) -> tuple[float, list[HeuristicHit]]:
    """Return (score in [0,1], hits)."""
    hits: list[HeuristicHit] = []
    total = 0.0
    for name, weight, pattern in _RULES:
        m = pattern.search(text)
        if m:
            hits.append(HeuristicHit(rule=name, weight=weight, snippet=_clip(m.group(0))))
            total += weight
    # Saturate so multiple medium signals can't exceed a single strong one's ceiling.
    score = 1.0 - (1.0 - min(total, 1.0)) if total <= 1.0 else 1.0
    score = min(total, 1.0)
    return score, hits


def _clip(s: str, n: int = 60) -> str:
    s = " ".join(s.split())
    return s if len(s) <= n else s[:n] + "…"
