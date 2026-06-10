"""Tests for the L5 pre-registration: PROTOCOL.md and the SLICES.md registry.

These guard the pre-registration from silent drift: the protocol must declare
format version 2 and pre-register the primary metric and the admission bar, and
every shipped dataset slice must be registered in SLICES.md before it can be
scored (the register-before-run rule). They are deliberately light string and
structural checks -- the salience guard is a discipline, and this is its CI.

Dual-runnable: works under pytest and as a plain script.
"""

from __future__ import annotations

import glob
import os
import sys

# Make the package importable when run as a plain script from anywhere.
_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _PKG_ROOT not in sys.path:
    sys.path.insert(0, _PKG_ROOT)

_PROTOCOL_PATH = os.path.join(_PKG_ROOT, "PROTOCOL.md")
_SLICES_PATH = os.path.join(_PKG_ROOT, "SLICES.md")
_DATASETS_DIR = os.path.join(_PKG_ROOT, "datasets")


def _read(path: str) -> str:
    assert os.path.exists(path), f"missing required file: {path}"
    with open(path, encoding="utf-8") as fh:
        return fh.read()


# --- PROTOCOL.md ------------------------------------------------------------


def test_protocol_declares_format_version_3() -> None:
    """The protocol header marks itself format version 3 (additive bump over v2)."""
    text = _read(_PROTOCOL_PATH)
    assert "Format version:** 3" in text
    # The format-version-2 amendments are retained as the historical record (no retcon).
    assert "format version 2 (L1" in text


def test_protocol_v3_carveout_present_and_additive() -> None:
    """The v3 public-demo carve-out exists as an amendment and retains v2 text."""
    text = _read(_PROTOCOL_PATH)
    assert "format version 3 (L7" in text
    # Re-scopes, does not rewrite: the original private-corpus section is still here.
    assert "## The corpus is PRIVATE and dated" in text
    assert "non-scored public by design" in text


def test_protocol_pre_registers_primary_metric() -> None:
    """The signed-recall primary metric is pre-registered, not chosen post-hoc."""
    text = _read(_PROTOCOL_PATH)
    assert "Primary metric (pre-registered): the signed delta on RECALL" in text


def test_protocol_pre_registers_admission_bar() -> None:
    """The naive-weakness admission bar is pre-registered at recall < 0.5."""
    text = _read(_PROTOCOL_PATH)
    assert "naive recall < 0.5" in text


def test_protocol_mandates_underpowered_label() -> None:
    """The UNDERPOWERED rule is pre-registered as mandatory."""
    text = _read(_PROTOCOL_PATH)
    assert "UNDERPOWERED is mandatory" in text


# --- SLICES.md registry -----------------------------------------------------


def test_slices_registry_exists_and_nonempty() -> None:
    """The slice registry exists and has content."""
    assert _read(_SLICES_PATH).strip(), "SLICES.md is empty"


def test_every_shipped_slice_is_registered() -> None:
    """Every datasets/*.jsonl slice is named in SLICES.md (register-before-run).

    A shipped slice that is missing from the registry fails here -- you cannot
    score a slice you did not pre-register.
    """
    registry = _read(_SLICES_PATH)
    slice_files = sorted(glob.glob(os.path.join(_DATASETS_DIR, "*.jsonl")))
    assert slice_files, "no dataset slices found to check"
    missing = [os.path.basename(p) for p in slice_files if os.path.basename(p) not in registry]
    assert not missing, f"slices not registered in SLICES.md: {missing}"


def test_registry_publishes_all_rule_present() -> None:
    """The publish-all-slices salience rule is stated in the registry."""
    text = _read(_SLICES_PATH)
    assert "never a chosen subset" in text


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
