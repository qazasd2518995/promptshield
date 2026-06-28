"""Shield — fuse the ML classifier and local heuristics into a verdict.

Risk = max(classifier_score, heuristic_score). We take the max (rather than an
average) on purpose: either a strong ML signal OR an unambiguous known-attack
pattern should be enough to block. The classifier is optional — if it errors,
the Shield degrades to heuristics-only and says so in `result.notes`.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum

from . import classifier
from .heuristics import HeuristicHit, scan_heuristics


class Verdict(str, Enum):
    ALLOW = "allow"
    FLAG = "flag"
    BLOCK = "block"


@dataclass
class ShieldResult:
    text: str
    verdict: Verdict
    risk: float
    classifier_score: float | None
    heuristic_score: float
    heuristic_hits: list[HeuristicHit] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def blocked(self) -> bool:
        return self.verdict is Verdict.BLOCK


class Shield:
    def __init__(
        self,
        *,
        block_threshold: float | None = None,
        flag_threshold: float | None = None,
        use_classifier: bool = True,
    ) -> None:
        self.block_threshold = (
            block_threshold
            if block_threshold is not None
            else float(os.getenv("SHIELD_BLOCK_THRESHOLD", "0.8"))
        )
        self.flag_threshold = (
            flag_threshold
            if flag_threshold is not None
            else float(os.getenv("SHIELD_FLAG_THRESHOLD", "0.4"))
        )
        self.use_classifier = use_classifier

    def inspect(self, text: str) -> ShieldResult:
        notes: list[str] = []
        heur_score, hits = scan_heuristics(text)

        clf_score: float | None = None
        if self.use_classifier:
            try:
                clf_score = classifier.classify(text)
            except (classifier.ClassifierError, RuntimeError) as exc:
                notes.append(f"classifier unavailable, heuristics-only ({exc})")

        risk = max(heur_score, clf_score or 0.0)
        verdict = self._verdict(risk)
        return ShieldResult(
            text=text,
            verdict=verdict,
            risk=round(risk, 4),
            classifier_score=None if clf_score is None else round(clf_score, 4),
            heuristic_score=round(heur_score, 4),
            heuristic_hits=hits,
            notes=notes,
        )

    def _verdict(self, risk: float) -> Verdict:
        if risk >= self.block_threshold:
            return Verdict.BLOCK
        if risk >= self.flag_threshold:
            return Verdict.FLAG
        return Verdict.ALLOW
