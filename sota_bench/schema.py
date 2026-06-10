"""Core data model for the sota_bench benchmark.

This module is STDLIB-ONLY. It defines the immutable :class:`BenchEntry`
record (one labeled benchmark item), a :class:`Prediction` record (one model
output to be scored), and pure validation/loading helpers.

A ``BenchEntry`` is the ground-truth unit of the benchmark: a specific finding
at a (repo, commit_sha, file, line) location, labeled with its true security
disposition, the OWASP/CWE taxonomy, the runtime-gating ``fp_killer`` that
resolves it either way, and the expected CVSS severity band/vector. Validation
is strict and fails closed with a precise, line-aware message so dataset
authoring errors surface immediately.
"""

from __future__ import annotations

import datetime
import json
from dataclasses import dataclass, fields
from typing import Any, Final

__all__ = [
    "VERTICALS",
    "GROUND_TRUTH_VALUES",
    "CVSS_BANDS",
    "PREDICTED_LABELS",
    "BenchEntry",
    "Prediction",
    "validate_entry",
    "load_dataset",
]

# --- Controlled vocabularies -------------------------------------------------

#: Allowed values for :attr:`BenchEntry.vertical`.
VERTICALS: Final[frozenset[str]] = frozenset({"authz", "decode"})

#: Allowed values for :attr:`BenchEntry.ground_truth`.
GROUND_TRUTH_VALUES: Final[frozenset[str]] = frozenset({"vuln", "secure", "oos", "wontfix"})

#: Allowed values for :attr:`BenchEntry.expected_cvss_band` and
#: :attr:`Prediction.predicted_cvss_band`.
CVSS_BANDS: Final[frozenset[str]] = frozenset({"none", "low", "medium", "high", "critical"})

#: Allowed values for :attr:`Prediction.predicted_label`. Predictions collapse
#: ground truth to a binary decision: a finding is either flagged (``"vuln"``)
#: or cleared (``"secure"``).
PREDICTED_LABELS: Final[frozenset[str]] = frozenset({"vuln", "secure"})


# --- Records -----------------------------------------------------------------


@dataclass(frozen=True)
class BenchEntry:
    """One labeled benchmark item.

    Each field is required and carries ground truth for scoring. ``variant``
    distinguishes near-duplicate cases (e.g. a vuln and its patched twin) that
    share a code location, which is what makes the ``fp_killer`` the decisive
    signal. Optional fields are typed ``... | None`` and must be present as
    explicit ``null`` in the source JSONL.
    """

    finding_id: str
    vertical: str  # one of VERTICALS
    repo: str
    commit_sha: str
    file: str
    line: int
    ground_truth: str  # one of GROUND_TRUTH_VALUES
    variant: str
    owasp_labels: list[str]  # e.g. ["API1:2023", "API5:2023"]
    cwe: list[str]  # e.g. ["CWE-862"]
    fp_killer: str  # the runtime-gating check that resolves it
    expected_cvss_band: str  # one of CVSS_BANDS
    expected_cvss_vector: str | None
    realized_outcome: str
    public_url: str | None
    notes: str

    # --- Provenance (optional; absent in the source defaults to None) ----------
    # These are append-only-corpus metadata. They are OPTIONAL so legacy rows
    # validate unchanged; a missing key is None ("unsourced"), NEVER a guessed
    # value. ``evidence_date`` is the ISO date (YYYY-MM-DD) of the EARLIEST public
    # artifact for this finding (the fix commit / patch PR, which predates the
    # CVE/advisory), used by the contamination gate. ``added_in_corpus_version``
    # records the slice that introduced the row. ``supersedes`` names the
    # finding_id this row corrects (corrections are new rows, never in-place edits).
    evidence_date: str | None = None
    added_in_corpus_version: str | None = None
    supersedes: str | None = None

    # --- Embargo / live-verification metadata (optional) -----------------------
    # The last live-checked disclosure state of a finding, so a vuln row carries
    # its own do-not-publish guard. ADVISORY ONLY: per the embargo gate the
    # authoritative signal is always a FRESH live ``state`` check, NEVER these
    # stored strings (the ``embargo`` note text says exactly this). Optional +
    # default None so secure rows and legacy rows validate unchanged.
    verified_state: str | None = None  # last live-checked state, e.g. "triage"/"published"
    verified_public: bool | None = None  # confirmed present in the global advisory DB?
    verified_at: str | None = None  # ISO date (YYYY-MM-DD) of that live check
    embargo: str | None = None  # human-readable embargo guard note

    # --- Scoring-exclusion marker (optional) -----------------------------------
    # ``excluded_from_scoring=True`` marks a row that is a PUBLIC DEMO / CALIBRATION
    # item: it ships WITH its answer key (``ground_truth`` + ``fp_killer``) as a
    # worked illustration and is PERMANENTLY non-scoreable (its labels are public
    # and its evidence_date predates current model cutoffs, so it can never serve
    # as a held-out test). This is a SCORING-correctness / documentation flag, NOT
    # a security control: the do-not-leak guard is the publication firewall
    # (a structural path-allowlist), which never trusts a per-row self-flag.
    # Optional + default None so legacy rows validate unchanged.
    excluded_from_scoring: bool | None = None


@dataclass(frozen=True)
class Prediction:
    """One model output to be scored against a :class:`BenchEntry`."""

    finding_id: str
    predicted_label: str  # one of PREDICTED_LABELS
    predicted_cvss_score: float | None
    predicted_cvss_band: str | None


# --- Validation --------------------------------------------------------------


def _require_str(d: dict[str, Any], key: str) -> str:
    """Return ``d[key]`` as a non-bool ``str`` or raise ``ValueError``."""
    if key not in d:
        raise ValueError(f"missing required field {key!r}")
    value = d[key]
    if not isinstance(value, str):
        raise ValueError(f"field {key!r} must be a string, got {type(value).__name__}")
    return value


def _require_str_list(d: dict[str, Any], key: str) -> list[str]:
    """Return ``d[key]`` as a ``list[str]`` or raise ``ValueError``."""
    if key not in d:
        raise ValueError(f"missing required field {key!r}")
    value = d[key]
    if not isinstance(value, list):
        raise ValueError(f"field {key!r} must be a list of strings, got {type(value).__name__}")
    for i, item in enumerate(value):
        if not isinstance(item, str):
            raise ValueError(f"field {key}[{i}] must be a string, got {type(item).__name__}")
    return list(value)


def _require_enum(d: dict[str, Any], key: str, allowed: frozenset[str]) -> str:
    """Return ``d[key]`` if it is a string in ``allowed`` else raise."""
    value = _require_str(d, key)
    if value not in allowed:
        choices = ", ".join(sorted(allowed))
        raise ValueError(f"field {key!r} must be one of {{{choices}}}, got {value!r}")
    return value


def _require_int(d: dict[str, Any], key: str) -> int:
    """Return ``d[key]`` as an ``int`` (rejecting ``bool``) or raise."""
    if key not in d:
        raise ValueError(f"missing required field {key!r}")
    value = d[key]
    # bool is a subclass of int; reject it explicitly.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"field {key!r} must be an integer, got {type(value).__name__}")
    return value


def _require_str_or_none(d: dict[str, Any], key: str) -> str | None:
    """Return ``d[key]`` as ``str`` or ``None`` (key must be present)."""
    if key not in d:
        raise ValueError(f"missing required field {key!r}")
    value = d[key]
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"field {key!r} must be a string or null, got {type(value).__name__}")
    return value


def _optional_str_or_none(d: dict[str, Any], key: str) -> str | None:
    """Return ``d[key]`` as ``str`` or ``None``; a MISSING key also yields ``None``.

    Unlike :func:`_require_str_or_none`, the key may be absent (it defaults to
    ``None``), which is what makes the provenance fields optional so legacy rows
    validate unchanged.
    """
    if key not in d:
        return None
    return _require_str_or_none(d, key)


def _optional_bool(d: dict[str, Any], key: str) -> bool | None:
    """Return ``d[key]`` as a ``bool`` or ``None``; a MISSING key also yields ``None``.

    Used for optional verification flags so legacy rows (which lack the key)
    validate unchanged. A present value must be a real ``bool``; anything else
    fails closed.
    """
    if key not in d:
        return None
    value = d[key]
    if value is None:
        return None
    if not isinstance(value, bool):
        raise ValueError(f"field {key!r} must be a boolean or null, got {type(value).__name__}")
    return value


def _optional_iso_date(d: dict[str, Any], key: str) -> str | None:
    """Return ``d[key]`` as a validated ``YYYY-MM-DD`` string, or ``None``.

    A missing key or explicit null yields ``None`` (unsourced). When present, the
    value must parse as an ISO calendar date; an unparseable date fails closed so
    a garbage date can never enter the provenance record.

    Raises:
        ValueError: If present but not a string, or not a valid ISO date.
    """
    value = _optional_str_or_none(d, key)
    if value is None:
        return None
    try:
        datetime.date.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"field {key!r} must be an ISO date (YYYY-MM-DD), got {value!r}") from exc
    return value


def validate_entry(d: dict[str, Any]) -> BenchEntry:
    """Validate a raw mapping and build a :class:`BenchEntry`.

    Raises :class:`ValueError` with a precise message on any unknown field,
    missing field, wrong type, or out-of-enum value.

    Args:
        d: A mapping of field name to value (e.g. one parsed JSONL object).

    Returns:
        The validated, frozen :class:`BenchEntry`.

    Raises:
        ValueError: If ``d`` is not a mapping, contains unknown keys, omits a
            required field, has a value of the wrong type, or violates an enum.
    """
    if not isinstance(d, dict):
        raise ValueError(f"entry must be a JSON object, got {type(d).__name__}")

    allowed_keys = {f.name for f in fields(BenchEntry)}
    unknown = set(d) - allowed_keys
    if unknown:
        names = ", ".join(repr(k) for k in sorted(unknown))
        raise ValueError(f"unknown field(s): {names}")

    return BenchEntry(
        finding_id=_require_str(d, "finding_id"),
        vertical=_require_enum(d, "vertical", VERTICALS),
        repo=_require_str(d, "repo"),
        commit_sha=_require_str(d, "commit_sha"),
        file=_require_str(d, "file"),
        line=_require_int(d, "line"),
        ground_truth=_require_enum(d, "ground_truth", GROUND_TRUTH_VALUES),
        variant=_require_str(d, "variant"),
        owasp_labels=_require_str_list(d, "owasp_labels"),
        cwe=_require_str_list(d, "cwe"),
        fp_killer=_require_str(d, "fp_killer"),
        expected_cvss_band=_require_enum(d, "expected_cvss_band", CVSS_BANDS),
        expected_cvss_vector=_require_str_or_none(d, "expected_cvss_vector"),
        realized_outcome=_require_str(d, "realized_outcome"),
        public_url=_require_str_or_none(d, "public_url"),
        notes=_require_str(d, "notes"),
        evidence_date=_optional_iso_date(d, "evidence_date"),
        added_in_corpus_version=_optional_str_or_none(d, "added_in_corpus_version"),
        supersedes=_optional_str_or_none(d, "supersedes"),
        verified_state=_optional_str_or_none(d, "verified_state"),
        verified_public=_optional_bool(d, "verified_public"),
        verified_at=_optional_iso_date(d, "verified_at"),
        embargo=_optional_str_or_none(d, "embargo"),
        excluded_from_scoring=_optional_bool(d, "excluded_from_scoring"),
    )


def load_dataset(path: str) -> list[BenchEntry]:
    """Load and validate a JSONL dataset of :class:`BenchEntry` records.

    Blank lines (after stripping) are skipped. Every non-blank line is parsed
    as JSON and validated. The 1-based file line number is included in any
    error message so the offending row is easy to find.

    Args:
        path: Filesystem path to a UTF-8 JSONL file.

    Returns:
        The validated entries in file order.

    Raises:
        ValueError: If any line is not valid JSON or fails validation; the
            message names the 1-based line number.
    """
    entries: list[BenchEntry] = []
    with open(path, encoding="utf-8") as fh:
        for lineno, raw in enumerate(fh, start=1):
            if not raw.strip():
                continue
            try:
                obj = json.loads(raw)
            except json.JSONDecodeError as exc:
                raise ValueError(f"line {lineno}: invalid JSON: {exc}") from exc
            try:
                entries.append(validate_entry(obj))
            except ValueError as exc:
                raise ValueError(f"line {lineno}: {exc}") from exc
    return entries
