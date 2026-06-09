"""Tests for the provenance layer: schema fields, contamination gate, append-only.

Covers:
* the optional ``evidence_date`` / ``added_in_corpus_version`` / ``supersedes``
  fields on :class:`BenchEntry` (parsed when present, ``None`` when absent,
  fail-closed on a garbage date);
* :func:`filter_by_evidence_cutoff` -- post-cutoff eligible, on/before-cutoff
  excluded, unsourced excluded (fail-safe);
* :func:`assert_append_only` -- subset clean, removal/mutation are violations, a
  superseding correction is a clean addition;
* a real-``authz_v1`` integration check (self is append-only-clean; with no
  evidence dates sourced yet, the gate excludes all rows as unsourced).

Dual-runnable: works under pytest and as a plain script.
"""

from __future__ import annotations

import datetime
import os
import sys

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.provenance import (  # noqa: E402
    assert_append_only,
    filter_by_evidence_cutoff,
)
from sota_bench.schema import BenchEntry, load_dataset, validate_entry  # noqa: E402

_DATASET_PATH = os.path.join(_PKG_ROOT, "datasets", "authz_v1.jsonl")


# --- fixtures ---------------------------------------------------------------


def _raw(finding_id: str, **overrides: object) -> dict[str, object]:
    """A valid raw entry mapping; overrides patch individual fields."""
    base: dict[str, object] = {
        "finding_id": finding_id,
        "vertical": "authz",
        "repo": "example/agent-app",
        "commit_sha": "deadbeefcafe",
        "file": "src/tools/admin.py",
        "line": 42,
        "ground_truth": "vuln",
        "variant": "baseline",
        "owasp_labels": ["API1:2023"],
        "cwe": ["CWE-862"],
        "fp_killer": "no require_role() before dispatch",
        "expected_cvss_band": "high",
        "expected_cvss_vector": None,
        "realized_outcome": "GHSA assigned",
        "public_url": None,
        "notes": "provenance test fixture",
    }
    base.update(overrides)
    return base


def _entry(finding_id: str, **overrides: object) -> BenchEntry:
    """Build a validated BenchEntry for provenance tests."""
    return validate_entry(_raw(finding_id, **overrides))


# --- schema: optional provenance fields -------------------------------------


def test_provenance_fields_absent_default_to_none() -> None:
    """A row without the provenance keys validates with all three as None."""
    entry = _entry("authz-0001")
    assert entry.evidence_date is None
    assert entry.added_in_corpus_version is None
    assert entry.supersedes is None


def test_provenance_fields_present_are_parsed() -> None:
    """Present provenance fields are carried through verbatim."""
    entry = _entry(
        "authz-0001",
        evidence_date="2026-03-13",
        added_in_corpus_version="authz_v1",
        supersedes="authz-0000",
    )
    assert entry.evidence_date == "2026-03-13"
    assert entry.added_in_corpus_version == "authz_v1"
    assert entry.supersedes == "authz-0000"


def test_evidence_date_explicit_null_is_none() -> None:
    """An explicit JSON null for evidence_date is accepted as None."""
    assert _entry("authz-0001", evidence_date=None).evidence_date is None


def test_evidence_date_garbage_is_rejected() -> None:
    """A non-ISO evidence_date fails closed with a clear message."""
    for bad in ("2026-13-99", "not-a-date", "03/13/2026"):
        try:
            _entry("authz-0001", evidence_date=bad)
        except ValueError as exc:
            assert "ISO date" in str(exc)
            continue
        raise AssertionError(f"expected ValueError for evidence_date={bad!r}")


def test_evidence_date_wrong_type_is_rejected() -> None:
    """A non-string, non-null evidence_date is rejected."""
    try:
        _entry("authz-0001", evidence_date=20260313)
    except ValueError:
        return
    raise AssertionError("expected ValueError for a non-string evidence_date")


# --- contamination gate -----------------------------------------------------


def test_cutoff_keeps_only_post_cutoff_rows() -> None:
    """Only findings dated strictly after the cutoff are eligible."""
    dataset = [
        _entry("after", evidence_date="2026-02-01"),
        _entry("on", evidence_date="2026-01-01"),
        _entry("before", evidence_date="2025-12-01"),
    ]
    report = filter_by_evidence_cutoff(dataset, "2026-01-01")
    assert report.eligible_ids == ("after",)
    assert set(report.excluded_pre_cutoff) == {"on", "before"}
    assert report.excluded_unsourced == ()
    assert report.n_eligible == 1
    assert report.n_excluded == 2


def test_cutoff_excludes_unsourced_failsafe() -> None:
    """A row with no evidence_date is excluded as unsourced, never kept."""
    dataset = [
        _entry("dated", evidence_date="2026-06-01"),
        _entry("undated"),  # evidence_date is None
    ]
    report = filter_by_evidence_cutoff(dataset, "2026-01-01")
    assert report.eligible_ids == ("dated",)
    assert report.excluded_unsourced == ("undated",)


def test_cutoff_accepts_date_object() -> None:
    """The cutoff may be passed as a datetime.date as well as a string."""
    dataset = [_entry("after", evidence_date="2026-02-01")]
    report = filter_by_evidence_cutoff(dataset, datetime.date(2026, 1, 1))
    assert report.eligible_ids == ("after",)


# --- append-only check ------------------------------------------------------


def test_append_only_clean_superset() -> None:
    """Adding a row while leaving the rest unchanged is append-only-clean."""
    v1 = [_entry("a"), _entry("b")]
    v2 = [_entry("a"), _entry("b"), _entry("c")]
    report = assert_append_only(v1, v2)
    assert report.ok is True
    assert report.added == ("c",)
    assert report.violations == ()


def test_append_only_removal_is_violation() -> None:
    """Dropping a row from the next version is a violation."""
    v1 = [_entry("a"), _entry("b")]
    v2 = [_entry("a")]
    report = assert_append_only(v1, v2)
    assert report.ok is False
    assert report.removed == ("b",)


def test_append_only_mutation_is_violation() -> None:
    """Editing an existing row in place is a violation."""
    v1 = [_entry("a", line=42)]
    v2 = [_entry("a", line=7)]  # same id, changed field
    report = assert_append_only(v1, v2)
    assert report.ok is False
    assert report.mutated == ("a",)


def test_append_only_supersede_is_clean_addition() -> None:
    """A correction as a NEW superseding row (original untouched) is clean."""
    v1 = [_entry("a", line=42)]
    v2 = [
        _entry("a", line=42),  # original unchanged
        _entry("a-fix", line=7, supersedes="a"),  # correction is a new row
    ]
    report = assert_append_only(v1, v2)
    assert report.ok is True
    assert report.added == ("a-fix",)


def test_append_only_raise_on_violation() -> None:
    """raise_on_violation surfaces a ValueError on a non-append-only change."""
    v1 = [_entry("a")]
    v2 = [_entry("b")]  # 'a' removed, 'b' added
    try:
        assert_append_only(v1, v2, raise_on_violation=True)
    except ValueError:
        return
    raise AssertionError("expected ValueError on append-only violation")


def test_append_only_duplicate_id_raises() -> None:
    """A duplicate finding_id within a version is rejected."""
    dup = [_entry("a"), _entry("a")]
    try:
        assert_append_only(dup, dup)
    except ValueError:
        return
    raise AssertionError("expected ValueError on duplicate finding_id")


# --- real-dataset integration -----------------------------------------------


def test_real_authz_v1_is_self_append_only() -> None:
    """The shipped corpus is trivially append-only against itself."""
    entries = load_dataset(_DATASET_PATH)
    report = assert_append_only(entries, entries)
    assert report.ok is True
    assert report.added == ()


def test_real_authz_v1_all_unsourced_under_gate() -> None:
    """With no evidence dates sourced yet, the gate excludes the whole corpus.

    This is the honest no-op: a dateless corpus yields zero eligible rows under
    any cutoff (fail-safe), making the missing provenance explicit rather than
    silently scoring potentially-contaminated rows.
    """
    entries = load_dataset(_DATASET_PATH)
    report = filter_by_evidence_cutoff(entries, "2020-01-01")
    assert report.n_eligible == 0
    assert len(report.excluded_unsourced) == len(entries)


# --- dual-run harness -------------------------------------------------------


def _run_all() -> int:
    """Run every test_* function; print PASS/FAIL; return process exit code."""
    tests = [
        (name, obj)
        for name, obj in sorted(globals().items())
        if name.startswith("test_") and callable(obj)
    ]
    failures = 0
    for name, fn in tests:
        try:
            fn()
        except Exception as exc:  # noqa: BLE001 - test harness reports all
            failures += 1
            print(f"FAIL: {name}: {type(exc).__name__}: {exc}")
        else:
            print(f"PASS: {name}")
    print(f"\n{len(tests) - failures}/{len(tests)} passed")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(_run_all())
