"""Tests for sota_bench.schema: validate_entry and load_dataset.

Dual-runnable: works under pytest, and also as a plain script
(``python sota_bench/tests/test_schema.py``) which runs every test function
and prints a PASS/FAIL summary.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile
from typing import Any

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.schema import (  # noqa: E402
    BenchEntry,
    Prediction,
    load_dataset,
    validate_entry,
)


def _good_entry_dict() -> dict[str, Any]:
    """Return a fully-valid raw entry mapping."""
    return {
        "finding_id": "authz-0001",
        "vertical": "authz",
        "repo": "example/agent-app",
        "commit_sha": "deadbeefcafe",
        "file": "src/tools/admin.py",
        "line": 42,
        "ground_truth": "vuln",
        "variant": "baseline",
        "owasp_labels": ["API1:2023", "API5:2023"],
        "cwe": ["CWE-862"],
        "fp_killer": "no require_role() before the dispatch on the tool path",
        "expected_cvss_band": "high",
        "expected_cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "realized_outcome": "GHSA assigned",
        "public_url": "https://github.com/advisories/GHSA-xxxx",
        "notes": "REST path checks role; tool path does not.",
    }


def _assert_raises_value_error(fn: Any, *, contains: str | None = None) -> None:
    """Assert that ``fn()`` raises ValueError (optionally with a substring)."""
    try:
        fn()
    except ValueError as exc:
        if contains is not None:
            assert contains in str(exc), (
                f"expected substring {contains!r} in error, got {str(exc)!r}"
            )
        return
    raise AssertionError("expected ValueError, none raised")


# --- validate_entry: happy path ---------------------------------------------


def test_validate_entry_good() -> None:
    """A complete, well-typed mapping validates into a BenchEntry."""
    entry = validate_entry(_good_entry_dict())
    assert isinstance(entry, BenchEntry)
    assert entry.finding_id == "authz-0001"
    assert entry.vertical == "authz"
    assert entry.line == 42
    assert entry.owasp_labels == ["API1:2023", "API5:2023"]
    assert entry.cwe == ["CWE-862"]
    assert entry.expected_cvss_band == "high"


def test_validate_entry_nullable_fields_accept_none() -> None:
    """expected_cvss_vector and public_url accept explicit null."""
    d = _good_entry_dict()
    d["expected_cvss_vector"] = None
    d["public_url"] = None
    entry = validate_entry(d)
    assert entry.expected_cvss_vector is None
    assert entry.public_url is None


def test_validate_entry_is_frozen() -> None:
    """BenchEntry is immutable (frozen dataclass)."""
    entry = validate_entry(_good_entry_dict())
    try:
        entry.line = 7  # type: ignore[misc]
    except Exception:
        return
    raise AssertionError("expected BenchEntry to be frozen/immutable")


# --- validate_entry: failure modes ------------------------------------------


def test_validate_entry_not_a_dict() -> None:
    """A non-mapping input raises ValueError."""
    _assert_raises_value_error(lambda: validate_entry([]), contains="JSON object")  # type: ignore[arg-type]


def test_validate_entry_missing_field() -> None:
    """A missing required field raises ValueError naming the field."""
    d = _good_entry_dict()
    del d["repo"]
    _assert_raises_value_error(lambda: validate_entry(d), contains="repo")


def test_validate_entry_unknown_field() -> None:
    """An unknown field raises ValueError naming it."""
    d = _good_entry_dict()
    d["surprise"] = "boom"
    _assert_raises_value_error(lambda: validate_entry(d), contains="surprise")


def test_validate_entry_bad_vertical_enum() -> None:
    """An out-of-enum vertical raises ValueError."""
    d = _good_entry_dict()
    d["vertical"] = "networking"
    _assert_raises_value_error(lambda: validate_entry(d), contains="vertical")


def test_validate_entry_bad_ground_truth_enum() -> None:
    """An out-of-enum ground_truth raises ValueError."""
    d = _good_entry_dict()
    d["ground_truth"] = "maybe"
    _assert_raises_value_error(lambda: validate_entry(d), contains="ground_truth")


def test_validate_entry_bad_cvss_band_enum() -> None:
    """An out-of-enum expected_cvss_band raises ValueError."""
    d = _good_entry_dict()
    d["expected_cvss_band"] = "extreme"
    _assert_raises_value_error(lambda: validate_entry(d), contains="expected_cvss_band")


def test_validate_entry_wrong_type_line() -> None:
    """A non-int line raises ValueError."""
    d = _good_entry_dict()
    d["line"] = "42"
    _assert_raises_value_error(lambda: validate_entry(d), contains="line")


def test_validate_entry_bool_line_rejected() -> None:
    """A bool line is rejected (bool is a subclass of int)."""
    d = _good_entry_dict()
    d["line"] = True
    _assert_raises_value_error(lambda: validate_entry(d), contains="line")


def test_validate_entry_wrong_type_owasp_labels() -> None:
    """A non-list owasp_labels raises ValueError."""
    d = _good_entry_dict()
    d["owasp_labels"] = "API1:2023"
    _assert_raises_value_error(lambda: validate_entry(d), contains="owasp_labels")


def test_validate_entry_owasp_labels_non_str_item() -> None:
    """A non-string item inside owasp_labels raises ValueError with index."""
    d = _good_entry_dict()
    d["owasp_labels"] = ["API1:2023", 5]
    _assert_raises_value_error(lambda: validate_entry(d), contains="owasp_labels[1]")


def test_validate_entry_wrong_type_string_field() -> None:
    """A non-string repo raises ValueError."""
    d = _good_entry_dict()
    d["repo"] = 123
    _assert_raises_value_error(lambda: validate_entry(d), contains="repo")


def test_validate_entry_nullable_wrong_type() -> None:
    """A non-string, non-null public_url raises ValueError."""
    d = _good_entry_dict()
    d["public_url"] = 123
    _assert_raises_value_error(lambda: validate_entry(d), contains="public_url")


# --- Prediction -------------------------------------------------------------


def test_prediction_construction() -> None:
    """Prediction is constructible and holds its fields."""
    pred = Prediction(
        finding_id="authz-0001",
        predicted_label="vuln",
        predicted_cvss_score=7.3,
        predicted_cvss_band="high",
    )
    assert pred.finding_id == "authz-0001"
    assert pred.predicted_label == "vuln"
    assert pred.predicted_cvss_score == 7.3
    assert pred.predicted_cvss_band == "high"


# --- load_dataset -----------------------------------------------------------


def _write_jsonl(lines: list[str]) -> str:
    """Write lines to a temp .jsonl file and return its path."""
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return path


def test_load_dataset_good() -> None:
    """A valid JSONL file (with a blank line) loads all entries in order."""
    a = _good_entry_dict()
    b = _good_entry_dict()
    b["finding_id"] = "authz-0002"
    b["ground_truth"] = "secure"
    b["variant"] = "patched"
    path = _write_jsonl([json.dumps(a), "", json.dumps(b)])
    try:
        entries = load_dataset(path)
    finally:
        os.remove(path)
    assert len(entries) == 2
    assert entries[0].finding_id == "authz-0001"
    assert entries[1].finding_id == "authz-0002"
    assert entries[1].ground_truth == "secure"


def test_load_dataset_invalid_json_reports_line() -> None:
    """Malformed JSON raises ValueError naming the 1-based line number."""
    path = _write_jsonl([json.dumps(_good_entry_dict()), "{not json"])
    try:
        _assert_raises_value_error(lambda: load_dataset(path), contains="line 2")
    finally:
        os.remove(path)


def test_load_dataset_validation_error_reports_line() -> None:
    """A bad entry raises ValueError naming the 1-based line number."""
    bad = _good_entry_dict()
    bad["vertical"] = "networking"
    path = _write_jsonl([json.dumps(_good_entry_dict()), json.dumps(bad)])
    try:
        _assert_raises_value_error(lambda: load_dataset(path), contains="line 2")
    finally:
        os.remove(path)


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
