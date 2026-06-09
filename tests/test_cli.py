"""Tests for the ``python -m sota_bench`` CLI.

The CLI exists so a reviewer can *run* the three honesty locks (the published
loss, the comparability gate, the admission floor) on a fresh clone rather than
trust a recording. These tests assert each subcommand runs and prints the real,
load-bearing output, so the asciinema recording on the site can never drift from
what the package actually does.
"""

from __future__ import annotations

import json
from dataclasses import asdict

from sota_bench.__main__ import build_parser, main
from sota_bench.schema import BenchEntry


def test_baseline_prints_the_honest_loss(capsys) -> None:
    assert main(["baseline"]) == 0
    out = capsys.readouterr().out
    assert "0.833" in out  # naive recall
    assert "0.667" in out  # method recall
    assert "-0.167" in out  # signed delta
    assert "the method LOST" in out


def test_delta_gate_refuses_incomparable_runs(capsys) -> None:
    assert main(["delta"]) == 0
    out = capsys.readouterr().out
    # the exact message raised by loop.delta_vs_baseline
    assert "corpus mismatch" in out
    assert "dataset_hash boundary" in out


def test_admit_rejects_underpowered_slice(capsys) -> None:
    assert main(["admit", "decode_v1", "--n", "3"]) == 0
    out = capsys.readouterr().out
    assert "REJECTED" in out
    assert "MIN_SLICE_N=10" in out
    assert "decode_v1" in out


def test_admit_defaults_to_an_underpowered_seed(capsys) -> None:
    assert main(["admit"]) == 0
    out = capsys.readouterr().out
    assert "decode_v1" in out
    assert "REJECTED" in out


def _entry(finding_id: str, ground_truth: str) -> BenchEntry:
    return BenchEntry(
        finding_id=finding_id,
        vertical="authz",
        repo="ex/app",
        commit_sha="0000000",
        file="x.py",
        line=1,
        ground_truth=ground_truth,
        variant="v",
        owasp_labels=[],
        cwe=["CWE-862"],
        fp_killer="runtime sibling-guard oracle",
        expected_cvss_band="high",
        expected_cvss_vector=None,
        realized_outcome="example",
        public_url=None,
        notes="test fixture",
    )


def test_score_runs_on_files(tmp_path, capsys) -> None:
    dataset_path = tmp_path / "dataset.jsonl"
    preds_path = tmp_path / "preds.jsonl"
    entries = [_entry("v1", "vuln"), _entry("s1", "secure")]
    dataset_path.write_text(
        "\n".join(json.dumps(asdict(e)) for e in entries) + "\n", encoding="utf-8"
    )
    preds = [
        {"finding_id": "v1", "predicted_label": "vuln"},
        {"finding_id": "s1", "predicted_label": "secure"},
    ]
    preds_path.write_text("\n".join(json.dumps(p) for p in preds) + "\n", encoding="utf-8")

    assert main(["score", str(dataset_path), str(preds_path)]) == 0
    out = capsys.readouterr().out
    assert "recall" in out


def test_parser_requires_a_subcommand() -> None:
    parser = build_parser()
    try:
        parser.parse_args([])
    except SystemExit as exc:
        assert exc.code != 0
    else:  # pragma: no cover - argparse must exit on a missing required subcommand
        raise AssertionError("expected SystemExit when no subcommand is given")
