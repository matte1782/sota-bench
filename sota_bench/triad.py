"""IMPACT-TRIAD gate and CIA-concession linter for finding triage.

This module is STDLIB-ONLY. It encodes two pure, deterministic checks the
project uses to keep finding drafts honest:

* :func:`triad_gate` — the project's **L31 rule**. A finding only clears the
  gate when *all three* impact axes hold: it crosses a lower trust boundary,
  it leaks a sensitive artifact, and it has a practical consequence. If any
  axis is false the finding is not rejected outright but flagged
  ``informative`` (a real observation that does not rise to a reportable
  impact), and the failing axes are named.

* :func:`cia_concession_lint` — catches the self-contradiction where a draft
  *claims* real impact (disclosure, RCE, takeover, write, escalation, ...)
  while *conceding* the corresponding CIA axis to ``None`` — either via an
  explicit ``Confidentiality: None`` style phrasing or via a CVSS vector that
  scores the axis ``C:N`` / ``I:N`` / ``A:N``. Such a draft is internally
  inconsistent and hard-FAILs the lint.

No LLM-as-judge: every decision here is a deterministic string/keyword check.
"""

from __future__ import annotations

import re
from typing import Final

__all__ = [
    "TRIAD_AXES",
    "triad_gate",
    "cia_concession_lint",
]

# --- IMPACT-TRIAD gate -------------------------------------------------------

#: Human-readable names of the three impact axes, in evaluation order.
TRIAD_AXES: Final[tuple[str, str, str]] = (
    "crosses_lower_trust_boundary",
    "leaks_sensitive_artifact",
    "has_practical_consequence",
)


def triad_gate(
    crosses_lower_trust_boundary: bool,
    leaks_sensitive_artifact: bool,
    has_practical_consequence: bool,
) -> dict[str, object]:
    """Apply the L31 IMPACT-TRIAD gate to a finding.

    A finding PASSES only if all three axes are true. Otherwise it is treated
    as *informative*: a real observation that does not, on its own, rise to a
    reportable impact. The failing axes are named in ``reasons``.

    Args:
        crosses_lower_trust_boundary: True if the issue lets a lower-trust
            principal reach something it should not.
        leaks_sensitive_artifact: True if a sensitive artifact (secret, token,
            private data, internal state) is exposed.
        has_practical_consequence: True if there is a concrete, demonstrable
            consequence (not merely a theoretical one).

    Returns:
        A mapping with:
            * ``passes`` (bool): True iff all three axes are true.
            * ``reasons`` (list[str]): one message per failing axis when not
              passing; empty when passing.
            * ``informative`` (bool): present and True only when ``passes`` is
              False, marking the finding as informative-but-not-reportable.
    """
    axis_values = (
        crosses_lower_trust_boundary,
        leaks_sensitive_artifact,
        has_practical_consequence,
    )

    reasons: list[str] = [
        f"axis not satisfied: {name}" for name, value in zip(TRIAD_AXES, axis_values) if not value
    ]

    if not reasons:
        return {"passes": True, "reasons": []}

    return {"passes": False, "reasons": reasons, "informative": True}


# --- CIA-concession linter ---------------------------------------------------

#: Keywords whose presence in a draft asserts a real, concrete impact. Each
#: maps to the CIA axis it primarily implicates.
_IMPACT_KEYWORDS: Final[dict[str, str]] = {
    "disclosure": "C",
    "exfiltration": "C",
    "leak": "C",
    "read access": "C",
    "rce": "I",
    "remote code execution": "I",
    "takeover": "I",
    "account takeover": "I",
    "write": "I",
    "tampering": "I",
    "escalation": "I",
    "privilege escalation": "I",
}

#: Map each CIA axis letter to a readable name for messages.
_AXIS_NAME: Final[dict[str, str]] = {
    "C": "Confidentiality",
    "I": "Integrity",
    "A": "Availability",
}

#: Match a CVSS base metric like ``C:N`` / ``I:N`` / ``A:N`` (axis conceded).
_VECTOR_NONE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b([CIA]):N\b",
)

#: Match explicit prose concessions like "Confidentiality: None".
_PROSE_NONE_RE: Final[re.Pattern[str]] = re.compile(
    r"\b(Confidentiality|Integrity|Availability)\s*:\s*None\b",
    re.IGNORECASE,
)


def _conceded_axes(text: str, cvss_vector: str | None) -> set[str]:
    """Return the set of CIA axis letters conceded to None.

    Concessions are detected from the CVSS vector (``C:N``/``I:N``/``A:N``)
    and from explicit prose (``Confidentiality: None`` etc.).
    """
    conceded: set[str] = set()

    if cvss_vector:
        for match in _VECTOR_NONE_RE.finditer(cvss_vector):
            conceded.add(match.group(1).upper())

    for match in _PROSE_NONE_RE.finditer(text):
        conceded.add(match.group(1)[0].upper())

    return conceded


def _claimed_axes(text: str) -> dict[str, list[str]]:
    """Return, per CIA axis letter, the impact keywords claimed in ``text``.

    Matching is case-insensitive and whole-word where the keyword is a single
    token; multi-word keywords are matched as substrings on word boundaries.
    """
    lowered = text.lower()
    claimed: dict[str, list[str]] = {}
    for keyword, axis in _IMPACT_KEYWORDS.items():
        pattern = re.compile(r"\b" + re.escape(keyword) + r"\b")
        if pattern.search(lowered):
            claimed.setdefault(axis, []).append(keyword)
    return claimed


def cia_concession_lint(text: str, cvss_vector: str | None = None) -> dict[str, object]:
    """Flag drafts that claim impact while conceding the matching CIA axis.

    A draft hard-FAILs when it asserts a concrete impact on a CIA axis (via an
    impact keyword) yet concedes that same axis to ``None`` — either through
    the CVSS vector (``C:N``/``I:N``/``A:N``) or explicit prose
    (``Confidentiality: None`` etc.). This catches the common
    self-contradiction of, e.g., describing "information disclosure" under a
    ``C:N`` vector.

    Args:
        text: The draft text to lint.
        cvss_vector: Optional CVSS vector string used to detect conceded axes.

    Returns:
        A mapping with:
            * ``passes`` (bool): False iff a contradiction was found.
            * ``reasons`` (list[str]): one message per contradicting axis.
    """
    claimed = _claimed_axes(text)
    conceded = _conceded_axes(text, cvss_vector)

    reasons: list[str] = []
    for axis in sorted(claimed.keys() & conceded):
        keywords = ", ".join(sorted(claimed[axis]))
        name = _AXIS_NAME[axis]
        reasons.append(f"draft claims {name} impact ({keywords}) but concedes {axis}:N (None)")

    return {"passes": not reasons, "reasons": reasons}
