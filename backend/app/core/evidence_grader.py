"""Deterministic Evidence Grader for false-positive classification.

Replaces AI-based FP adjudication with rule-based grading.  The grader
assigns each finding a grade (A–D) with a corresponding FP *ceiling*.
The AI may still output a ``false_positive_probability`` but it can only
*lower* the ceiling, never raise it.

Grades
------
A – Active verification with strong proof markers  → ceiling 0.05
B – Structural / observable (the finding IS the proof) → ceiling 0.10
B+ – Verified by detector with decent confidence   → ceiling 0.15
C – Heuristic with partial evidence                 → ceiling 0.40
D – Weak / ambiguous evidence                       → ceiling 0.75
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from app.models.vulnerability import Vulnerability

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Grade result
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EvidenceGrade:
    """Immutable grading result for a single finding."""

    grade: str          # "A", "B", "B+", "C", or "D"
    fp_ceiling: float   # Maximum false-positive probability the AI may assign
    reason: str         # Human-readable explanation of why this grade was given


# ---------------------------------------------------------------------------
# Vocabulary sets
# ---------------------------------------------------------------------------

# Vulnerability types whose *existence* is confirmed by observation alone.
# These never require an exploit payload — the absence of a header, the use
# of HTTP GET for credentials, or the reachability of an admin panel IS the
# vulnerability.  Matching is case-insensitive substring.
_STRUCTURAL_VULN_KEYWORDS: tuple[str, ...] = (
    # Security-header absence
    "missing security header",
    "weak content security policy",
    "missing cache-control",
    # Information disclosure from headers
    "information disclosure in header",
    "server banner",
    # Transport / TLS issues
    "insecure transport",
    "weak tls",
    "ssl configuration",
    # Credential exposure in URL
    "credentials transmitted via http get",
    "credential / token exposed",
    "sensitive data in url",
    "sensitive credential",
    "password in get",
    "credentials via get",
    # Cookie attribute issues
    "insecure session cookie",
    "cookie without secure flag",
    "cookie attribute",
    # Admin / sensitive path reachability
    "admin / privileged endpoint",
    "admin endpoint",
    "privileged endpoint",
    "well-known admin",
    "sensitive path",
    "admin panel",
    "phpmyadmin",
    "sensitive file exposure",
    # CSRF structural absence (no hidden token field)
    "authentication form may lack csrf",
    "authentication form lacks csrf",
    # Mixed content
    "mixed content",
    # Authentication endpoint served over HTTP
    "authentication endpoint served over plaintext",
)

# Detection methods that constitute strong active verification.
_STRONG_ACTIVE_METHODS: frozenset[str] = frozenset({
    "time_based",
    "boolean_differential",
    "union_based",
    "error_based",
    "canary_verified",
    "context_breakout",
    "token_bypass",
    "command_output",
    "file_retrieval",
    "path_traversal_file_read",
    "stream_decoding_oracle",
    "remote_include_error_oracle",
})

# Evidence-blob keywords that signal strong active proof.
_STRONG_EVIDENCE_KEYWORDS: tuple[str, ...] = (
    "root:x:0",
    "uid=",
    "gid=",
    "pdoexception",
    "you have an error in your sql syntax",
    "sqlstate",
    "boot loader",
    "[extensions]",
    "<script>alert",
    "canary_verified",
    "time_delta",
)


# ---------------------------------------------------------------------------
# Grader
# ---------------------------------------------------------------------------

class EvidenceGrader:
    """Deterministic false-positive grading based on evidence markers.

    Usage::

        grader = EvidenceGrader()
        grade = grader.grade(vulnerability)
        # grade.fp_ceiling is the max FP probability the AI may assign
    """

    def grade(self, vuln: Vulnerability) -> EvidenceGrade:
        """Assign an evidence grade to *vuln*.

        Evaluation order (first match wins):
        1. Grade A – verified + high confidence + strong active marker
        2. Grade B – structural/observable vuln type
        3. Grade B+ – verified + moderate confidence
        4. Grade C – heuristic with partial evidence
        5. Grade D – everything else
        """
        vuln_lower = (vuln.vuln_type or "").lower()
        method = (vuln.evidence.detection_method or "").lower()
        confidence = vuln.evidence.confidence_score
        verified = vuln.evidence.verified

        # --- Grade A: strong active verification ---
        has_strong_method = method in _STRONG_ACTIVE_METHODS
        has_strong_evidence = self._has_strong_evidence_keywords(vuln)

        if verified and confidence >= 85.0 and (has_strong_method or has_strong_evidence):
            return EvidenceGrade(
                grade="A",
                fp_ceiling=0.05,
                reason=(
                    f"Active verification confirmed: method={method}, "
                    f"confidence={confidence:.0f}, verified=True"
                ),
            )

        # --- Grade B: structural / observable ---
        if self._is_structural(vuln_lower):
            return EvidenceGrade(
                grade="B",
                fp_ceiling=0.10,
                reason=(
                    f"Structural/observable finding: '{vuln.vuln_type}' — "
                    f"the observation itself is the proof"
                ),
            )

        # --- Grade B+: verified with decent confidence ---
        if verified and confidence >= 70.0:
            return EvidenceGrade(
                grade="B+",
                fp_ceiling=0.15,
                reason=(
                    f"Detector-verified with confidence={confidence:.0f}, "
                    f"method={method}"
                ),
            )

        # --- Grade A (late catch): strong method even at moderate confidence ---
        if verified and has_strong_method:
            return EvidenceGrade(
                grade="A",
                fp_ceiling=0.05,
                reason=(
                    f"Strong active method '{method}' with verified=True "
                    f"(confidence={confidence:.0f})"
                ),
            )

        # --- Grade C: Verified but low confidence ---
        if verified:
            return EvidenceGrade(
                grade="C",
                fp_ceiling=0.40,
                reason=(
                    f"Verified finding but low confidence: "
                    f"confidence={confidence:.0f}, method={method}"
                ),
            )

        # --- Grade D: weak / ambiguous ---
        return EvidenceGrade(
            grade="D",
            fp_ceiling=1.00,
            reason=(
                f"Weak/ambiguous evidence: confidence={confidence:.0f}, "
                f"verified={verified}, method={method}"
            ),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_structural(vuln_lower: str) -> bool:
        """Return True if the vuln type matches a structural/observable class."""
        return any(keyword in vuln_lower for keyword in _STRUCTURAL_VULN_KEYWORDS)

    @staticmethod
    def _has_strong_evidence_keywords(vuln: Vulnerability) -> bool:
        """Check if the evidence blob contains strong proof markers."""
        blob_parts = [
            vuln.evidence.payload or "",
            vuln.evidence.response_snippet or "",
        ]
        if vuln.evidence.detection_evidence:
            import json
            blob_parts.append(json.dumps(vuln.evidence.detection_evidence))

        blob = " ".join(blob_parts).lower()
        return any(kw in blob for kw in _STRONG_EVIDENCE_KEYWORDS)
