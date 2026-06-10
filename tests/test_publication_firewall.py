"""Red-team tests for the publication firewall (the s22 A4 security control).

These prove the firewall FAILS CLOSED: a planted answer key outside the explicit
allowlist must be caught, a per-row self-flag must not bypass it, and the real
public tree must pass. Deliberately adversarial: the tests try to sneak a leak
past the gate.

Dual-runnable: works under pytest and as a plain script.
"""

from __future__ import annotations

import json
import os
import sys
import tempfile

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

from sota_bench.publication_firewall import (  # noqa: E402
    PUBLICATION_ALLOWLIST,
    scan_tree,
)

# A realistic answer-key bench row (vuln positive). This is the exact shape an
# embargoed finding would have, used here only as a planted leak in a temp tree.
_VULN_ROW = {
    "finding_id": "planted-embargoed-leak",
    "vertical": "decode",
    "repo": "example/secret",
    "commit_sha": "deadbeef",
    "file": "src/x.sol",
    "line": 7,
    "ground_truth": "vuln",
    "variant": "planted",
    "owasp_labels": [],
    "cwe": ["CWE-682"],
    "fp_killer": "the decisive answer key that must never leak",
    "expected_cvss_band": "high",
    "expected_cvss_vector": None,
    "realized_outcome": "embargoed",
    "public_url": None,
    "notes": "planted",
}


def _write(root: str, relpath: str, content: str) -> None:
    """Write ``content`` to ``root/relpath``, creating parent dirs."""
    path = os.path.join(root, relpath.replace("/", os.sep))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(content)


# --- the real public tree must pass -----------------------------------------


def test_real_public_tree_passes() -> None:
    """The actual mirror tree (allowlisted files only) passes the firewall."""
    report = scan_tree(_PKG_ROOT)
    assert report.ok, f"real tree unexpectedly flagged: {report.violations}"


def test_allowlist_concrete_entries_exist() -> None:
    """Each non-glob allowlist entry resolves to a real file (anti-rot)."""
    for pattern in PUBLICATION_ALLOWLIST:
        if any(ch in pattern for ch in "*?["):
            continue  # glob entry, may legitimately match nothing yet
        assert os.path.isfile(os.path.join(_PKG_ROOT, pattern)), (
            f"allowlist points at a missing file: {pattern}"
        )


# --- red-team: a planted leak must FAIL --------------------------------------


def test_planted_vuln_fp_killer_in_seeds_fails() -> None:
    """An embargoed answer key planted under seeds/ outside the allowlist fails."""
    with tempfile.TemporaryDirectory() as root:
        _write(root, "seeds/evil/leak.jsonl", json.dumps(_VULN_ROW) + "\n")
        report = scan_tree(root)
    assert not report.ok
    assert any("seeds/evil/leak.jsonl" in v for v in report.violations)


def test_planted_slice_in_datasets_fails() -> None:
    """A scored .jsonl slice planted under datasets/ outside the allowlist fails."""
    with tempfile.TemporaryDirectory() as root:
        _write(root, "datasets/secret_v1.jsonl", json.dumps(_VULN_ROW) + "\n")
        report = scan_tree(root)
    assert not report.ok
    assert any("datasets/secret_v1.jsonl" in v for v in report.violations)


def test_self_flag_excluded_from_scoring_does_NOT_bypass() -> None:
    """A per-row excluded_from_scoring self-flag must NOT let a leak through.

    The firewall is a path-allowlist, so author-controlled row data can never
    grant publication. This is the core flaw-hunt requirement.
    """
    row = dict(_VULN_ROW, excluded_from_scoring=True)
    with tempfile.TemporaryDirectory() as root:
        _write(root, "seeds/sneaky/leak.jsonl", json.dumps(row) + "\n")
        report = scan_tree(root)
    assert not report.ok
    assert any("seeds/sneaky/leak.jsonl" in v for v in report.violations)


def test_ground_truth_row_without_fp_killer_still_fails() -> None:
    """A labeled bench row with fp_killer stripped still fails (structural check)."""
    row = {k: v for k, v in _VULN_ROW.items() if k != "fp_killer"}
    with tempfile.TemporaryDirectory() as root:
        _write(root, "datasets/labels_only.jsonl", json.dumps(row) + "\n")
        report = scan_tree(root)
    assert not report.ok
    assert any("labels_only.jsonl" in v for v in report.violations)


def test_unparseable_jsonl_under_scan_dir_fails_closed() -> None:
    """A garbage .jsonl under a scanned dir is a violation, never a silent pass."""
    with tempfile.TemporaryDirectory() as root:
        _write(root, "seeds/x/bad.jsonl", "{not valid json at all\n")
        report = scan_tree(root)
    assert not report.ok
    assert any("bad.jsonl" in v for v in report.violations)


# --- legitimate content must PASS -------------------------------------------


def test_allowlisted_demo_path_passes() -> None:
    """A PROPERLY-MARKED demo vuln under the explicit seeds/**/demo/ allowlist passes.

    The path allowlist permits the file, and the scoreable-vuln guard is satisfied
    because the demo positive carries excluded_from_scoring=true (an already-public
    answer key shown as a demonstration, not a scored row).
    """
    demo_row = dict(_VULN_ROW, excluded_from_scoring=True)
    with tempfile.TemporaryDirectory() as root:
        _write(root, "seeds/newclass/demo/demo.jsonl", json.dumps(demo_row) + "\n")
        report = scan_tree(root)
    assert report.ok, f"allowlisted demo path flagged: {report.violations}"


def test_result_json_without_fp_killer_passes() -> None:
    """A measurement/result .json (ground_truth outcome, no fp_killer) is not an answer key."""
    result = {"finding_id": "x", "ground_truth": "vuln", "naive": "vuln", "method": "vuln"}
    with tempfile.TemporaryDirectory() as root:
        _write(root, "seeds/x/run_2026.json", json.dumps(result) + "\n")
        report = scan_tree(root)
    assert report.ok, f"benign result json flagged: {report.violations}"


# --- in-allowlist scoreable-vuln guard (the dev-full-vs-public-subset hole) ---


def test_scoreable_vuln_in_allowlisted_path_fails() -> None:
    """A plain vuln row pushed to an allowlisted path (the full dev slice over the
    public secure-only slice) is caught even though the path is allowlisted."""
    with tempfile.TemporaryDirectory() as root:
        # datasets/authz_v1.jsonl is allowlisted, but the public version is
        # secure-only; a vuln row here is the full-dev-slice leak.
        _write(root, "datasets/authz_v1.jsonl", json.dumps(_VULN_ROW) + "\n")
        report = scan_tree(root)
    assert not report.ok
    assert any("scoreable vuln" in v for v in report.violations)


def test_demo_vuln_with_excluded_flag_in_allowlisted_path_passes() -> None:
    """A vuln row marked excluded_from_scoring in an allowlisted demo file passes."""
    demo_row = dict(_VULN_ROW, excluded_from_scoring=True)
    with tempfile.TemporaryDirectory() as root:
        _write(root, "seeds/decode_v1/decode_v1.jsonl", json.dumps(demo_row) + "\n")
        report = scan_tree(root)
    assert report.ok, f"marked demo vuln flagged: {report.violations}"


def test_secure_row_in_allowlisted_path_passes() -> None:
    """Secure negatives in an allowlisted file are always fine."""
    secure_row = dict(_VULN_ROW, ground_truth="secure")
    with tempfile.TemporaryDirectory() as root:
        _write(root, "datasets/authz_v1.jsonl", json.dumps(secure_row) + "\n")
        report = scan_tree(root)
    assert report.ok, f"secure row flagged: {report.violations}"


# --- dual-run harness -------------------------------------------------------


def _run_all() -> int:
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
