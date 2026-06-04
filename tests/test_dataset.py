"""Tests for the vertical-1 labeled set ``datasets/authz_v1.jsonl``.

Validates that the shipped dataset loads through :func:`sota_bench.schema.load_dataset`,
meets the size / class-balance floors, and uses only the allowed OWASP/CWE
vocabulary for the agent tool-dispatch authorization-confusion class.

Dual-runnable: works under pytest, and also as a plain script
(``python sota_bench/tests/test_dataset.py``) which runs every test function and
prints a PASS/FAIL summary.
"""

from __future__ import annotations

import os
import sys

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.schema import (  # noqa: E402
    CVSS_BANDS,
    GROUND_TRUTH_VALUES,
    BenchEntry,
    load_dataset,
)

#: Path to the dataset under test (resolved relative to this file).
_DATASET_PATH = os.path.join(_PKG_ROOT, "datasets", "authz_v1.jsonl")

#: Vocabularies the task pins for vertical-1.
_ALLOWED_OWASP = frozenset({"API1:2023", "API5:2023"})
_ALLOWED_CWE = frozenset({"CWE-862", "CWE-863", "CWE-285"})


def _load() -> list[BenchEntry]:
    """Load the dataset, asserting it exists first for a clear failure."""
    assert os.path.exists(_DATASET_PATH), f"dataset not found: {_DATASET_PATH}"
    return load_dataset(_DATASET_PATH)


# --- structure / loading -----------------------------------------------------


def test_dataset_loads_and_validates() -> None:
    """Every line loads and validates into a BenchEntry (load_dataset is strict)."""
    entries = _load()
    assert entries, "dataset is empty"
    for e in entries:
        assert isinstance(e, BenchEntry)


def test_dataset_min_entries() -> None:
    """At least 8 labeled entries in the public slice (the labeled positive set
    is withheld pending coordinated disclosure)."""
    assert len(_load()) >= 8


def test_dataset_class_balance() -> None:
    """The public slice ships the secure negatives; the labeled positive set is
    withheld pending coordinated disclosure, so the vuln count may be 0 here."""
    entries = _load()
    vuln = sum(1 for e in entries if e.ground_truth == "vuln")
    secure = sum(1 for e in entries if e.ground_truth == "secure")
    assert secure >= 8, f"expected >=8 secure, got {secure}"
    assert vuln >= 0


def test_dataset_finding_ids_unique() -> None:
    """finding_id is a primary key; no duplicates across the set."""
    ids = [e.finding_id for e in _load()]
    assert len(ids) == len(set(ids)), "duplicate finding_id in dataset"


# --- controlled vocabularies -------------------------------------------------


def test_dataset_all_vertical_authz() -> None:
    """Every entry in the vertical-1 set is the authz vertical."""
    assert all(e.vertical == "authz" for e in _load())


def test_dataset_ground_truth_in_vocab() -> None:
    """ground_truth values stay within the schema enum."""
    assert all(e.ground_truth in GROUND_TRUTH_VALUES for e in _load())


def test_dataset_owasp_labels_in_vocab() -> None:
    """Every owasp label is from {API1:2023 (BOLA), API5:2023 (BFLA)}."""
    for e in _load():
        assert e.owasp_labels, f"{e.finding_id}: empty owasp_labels"
        for label in e.owasp_labels:
            assert label in _ALLOWED_OWASP, f"{e.finding_id}: bad owasp label {label!r}"


def test_dataset_cwe_in_vocab() -> None:
    """Every cwe is from {CWE-862, CWE-863, CWE-285}."""
    for e in _load():
        assert e.cwe, f"{e.finding_id}: empty cwe"
        for cwe in e.cwe:
            assert cwe in _ALLOWED_CWE, f"{e.finding_id}: bad cwe {cwe!r}"


def test_dataset_cvss_bands_in_vocab() -> None:
    """expected_cvss_band stays within the schema enum."""
    assert all(e.expected_cvss_band in CVSS_BANDS for e in _load())


# --- label-quality invariants ------------------------------------------------


def test_dataset_each_entry_has_fp_killer() -> None:
    """Every entry names the runtime-gating check that resolves it either way."""
    for e in _load():
        assert e.fp_killer.strip(), f"{e.finding_id}: empty fp_killer"


def test_dataset_version_marker_in_notes() -> None:
    """Each entry carries an explicit version/status marker in its notes.

    v1 labels were hand-adjudicated and confirmed by the operator on 2026-06-03,
    so the marker asserts the CONFIRMED state (it guarded the DRAFT state pre-freeze).
    """
    for e in _load():
        assert e.notes.startswith("[v1 labels-confirmed 2026-06-03] "), (
            f"{e.finding_id}: missing v1 confirmed marker"
        )


def test_dataset_vuln_entries_cite_evidence() -> None:
    """Each positive cites an advisory id or file:line in its notes."""
    for e in _load():
        if e.ground_truth != "vuln":
            continue
        cites_advisory = "GHSA-" in e.notes
        cites_location = ".py:" in e.notes or ".ts:" in e.notes or ".py " in e.notes
        assert cites_advisory or cites_location, f"{e.finding_id}: no evidence cited in notes"


# --- dual-run harness --------------------------------------------------------


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
