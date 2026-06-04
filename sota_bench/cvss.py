"""CVSS v3.1 Base score computation (STDLIB-ONLY).

Implements the official Common Vulnerability Scoring System v3.1 *Base* metric
group: vector-string parsing, the Base score formula (Impact Sub-Score,
scope-aware Impact, Exploitability, scope-aware combination, and the v3.1
integer roundup), severity banding, and a ``check_claimed`` helper that
recomputes a vector's score and flags a mismatch against a claimed value.

The arithmetic follows the CVSS v3.1 Specification Document (FIRST.org),
Section 7.1 (Base Metrics Equations) and the v3.1 ``Roundup`` definition in
Appendix A, which is *integer-based* (not naive ``round``/``ceil`` on floats)
to avoid binary floating-point edge cases. No third-party imports.
"""

from __future__ import annotations

import math
from typing import Final

__all__ = [
    "BASE_METRICS",
    "METRIC_VALUES",
    "parse_vector",
    "base_score",
    "severity_band",
    "check_claimed",
]

#: The required Base metric abbreviations, in canonical vector order.
BASE_METRICS: Final[tuple[str, ...]] = ("AV", "AC", "PR", "UI", "S", "C", "I", "A")

#: Numeric weights for every Base metric value. Privileges Required (``PR``)
#: is scope-dependent: when Scope is Changed, ``L`` and ``H`` take higher
#: weights, so it is resolved separately in :func:`base_score`.
METRIC_VALUES: Final[dict[str, dict[str, float]]] = {
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR": {"N": 0.85, "L": 0.62, "H": 0.27},  # scope-unchanged weights
    "UI": {"N": 0.85, "R": 0.62},
    "S": {"U": 0.0, "C": 0.0},  # scope is structural, not a weight
    "C": {"H": 0.56, "L": 0.22, "N": 0.0},
    "I": {"H": 0.56, "L": 0.22, "N": 0.0},
    "A": {"H": 0.56, "L": 0.22, "N": 0.0},
}

#: Privileges Required weights when Scope is Changed.
_PR_CHANGED: Final[dict[str, float]] = {"N": 0.85, "L": 0.68, "H": 0.5}

#: Canonical vector prefix for CVSS v3.1.
_PREFIX: Final[str] = "CVSS:3.1"


def parse_vector(v: str) -> dict[str, str]:
    """Parse a CVSS v3.1 vector string into its Base metric values.

    Accepts an optional ``CVSS:3.1`` prefix. Only the eight Base metrics are
    returned; any temporal/environmental metrics present are ignored. The
    result maps each of ``AV/AC/PR/UI/S/C/I/A`` to its single-letter value.

    Args:
        v: A vector string, e.g. ``"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"``.

    Returns:
        A dict with exactly the eight Base metric abbreviations as keys.

    Raises:
        ValueError: If the string is empty, a token is malformed, a metric is
            duplicated, a Base metric is missing, or a value is not allowed.
    """
    if not isinstance(v, str) or not v.strip():
        raise ValueError("vector must be a non-empty string")

    tokens = [t for t in v.strip().split("/") if t != ""]
    if not tokens:
        raise ValueError("vector contains no metric tokens")

    # Drop an optional version prefix (CVSS:3.1 / CVSS:3.0).
    if tokens and tokens[0].upper().startswith("CVSS:"):
        version = tokens[0].split(":", 1)[1]
        if version not in ("3.1", "3.0"):
            raise ValueError(f"unsupported CVSS version prefix {tokens[0]!r}")
        tokens = tokens[1:]

    parsed: dict[str, str] = {}
    for tok in tokens:
        if ":" not in tok:
            raise ValueError(f"malformed metric token {tok!r} (expected 'KEY:VAL')")
        key, _, val = tok.partition(":")
        key, val = key.upper(), val.upper()
        if key not in METRIC_VALUES and key not in BASE_METRICS:
            # Unknown / temporal / environmental metric: ignore non-Base keys.
            continue
        if key in parsed:
            raise ValueError(f"duplicate metric {key!r} in vector")
        allowed = METRIC_VALUES[key]
        if val not in allowed:
            choices = ", ".join(sorted(allowed))
            raise ValueError(f"metric {key!r} has invalid value {val!r} (allowed: {choices})")
        parsed[key] = val

    missing = [m for m in BASE_METRICS if m not in parsed]
    if missing:
        raise ValueError(f"missing required Base metric(s): {', '.join(missing)}")

    return {m: parsed[m] for m in BASE_METRICS}


def _roundup(value: float) -> float:
    """Return the v3.1 integer-based roundup of ``value`` to one decimal.

    Per the CVSS v3.1 specification (Appendix A), the standard floating-point
    ``round``/``ceil`` are unsafe near boundaries; the reference algorithm
    works in integer hundredths::

        int_input = round(value * 100000)
        if int_input % 10000 == 0:
            return int_input / 100000.0
        return (floor(int_input / 10000) + 1) / 10.0

    Args:
        value: The non-rounded score component.

    Returns:
        ``value`` rounded *up* to the nearest 0.1.
    """
    int_input = int(round(value * 100000))
    if int_input % 10000 == 0:
        return int_input / 100000.0
    return (math.floor(int_input / 10000) + 1) / 10.0


def base_score(metrics: dict[str, str]) -> float:
    """Compute the CVSS v3.1 Base score from parsed metric values.

    Args:
        metrics: A mapping of the eight Base metrics to their letter values,
            as returned by :func:`parse_vector`.

    Returns:
        The Base score in ``[0.0, 10.0]``, rounded up to one decimal.

    Raises:
        ValueError: If a required metric is absent or has an invalid value.
    """
    for m in BASE_METRICS:
        if m not in metrics:
            raise ValueError(f"missing required Base metric {m!r}")

    scope_changed = metrics["S"] == "C"

    # Privileges Required uses scope-dependent weights.
    pr_val = metrics["PR"]
    pr_table = _PR_CHANGED if scope_changed else METRIC_VALUES["PR"]
    if pr_val not in pr_table:
        raise ValueError(f"metric 'PR' has invalid value {pr_val!r}")
    pr = pr_table[pr_val]

    av = METRIC_VALUES["AV"][metrics["AV"]]
    ac = METRIC_VALUES["AC"][metrics["AC"]]
    ui = METRIC_VALUES["UI"][metrics["UI"]]
    c = METRIC_VALUES["C"][metrics["C"]]
    i = METRIC_VALUES["I"][metrics["I"]]
    a = METRIC_VALUES["A"][metrics["A"]]

    # Impact Sub-Score (ISS).
    iss = 1.0 - ((1.0 - c) * (1.0 - i) * (1.0 - a))

    # Scope-aware Impact.
    if scope_changed:
        impact = 7.52 * (iss - 0.029) - 3.25 * ((iss - 0.02) ** 15)
    else:
        impact = 6.42 * iss

    # Exploitability.
    exploitability = 8.22 * av * ac * pr * ui

    if impact <= 0.0:
        return 0.0

    if scope_changed:
        raw = min(1.08 * (impact + exploitability), 10.0)
    else:
        raw = min(impact + exploitability, 10.0)

    return _roundup(raw)


def severity_band(score: float) -> str:
    """Map a numeric Base score to its CVSS v3.1 qualitative severity band.

    Bands (per the v3.1 spec): ``0.0`` → ``"none"``; ``0.1-3.9`` → ``"low"``;
    ``4.0-6.9`` → ``"medium"``; ``7.0-8.9`` → ``"high"``; ``9.0-10.0`` →
    ``"critical"``.

    Args:
        score: A CVSS Base score in ``[0.0, 10.0]``.

    Returns:
        One of ``"none"``, ``"low"``, ``"medium"``, ``"high"``, ``"critical"``.

    Raises:
        ValueError: If ``score`` is outside ``[0.0, 10.0]``.
    """
    if score < 0.0 or score > 10.0:
        raise ValueError(f"score must be in [0.0, 10.0], got {score!r}")
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


def check_claimed(vector: str, claimed: float) -> dict[str, object]:
    """Recompute a vector's Base score and flag a mismatch with ``claimed``.

    Parses ``vector``, recomputes the canonical Base score and band, and
    compares the computed score to ``claimed``. A mismatch is any absolute
    difference greater than ``0.05`` (half the score granularity), which
    catches arithmetic slips while tolerating display rounding.

    Args:
        vector: A CVSS v3.1 vector string.
        claimed: The score asserted by the reporter.

    Returns:
        A dict with keys: ``vector`` (str), ``claimed`` (float), ``computed``
        (float), ``computed_band`` (str), ``delta`` (float, rounded), and
        ``mismatch`` (bool).

    Raises:
        ValueError: If ``vector`` cannot be parsed.
    """
    metrics = parse_vector(vector)
    computed = base_score(metrics)
    delta = abs(computed - claimed)
    return {
        "vector": vector,
        "claimed": float(claimed),
        "computed": computed,
        "computed_band": severity_band(computed),
        "delta": round(delta, 2),
        "mismatch": delta > 0.05,
    }
