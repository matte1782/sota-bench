"""Command-line entry point for sota_bench: ``python -m sota_bench``.

Every subcommand here is reproducible on a fresh clone. The core is STDLIB-ONLY:
no network, no API key, and no private corpus is required. The commands exist to
let a reviewer *run* the three honesty locks the benchmark is built around,
rather than take a screenshot's word for them:

    python -m sota_bench baseline          # the pinned, published authz baseline (the method LOST)
    python -m sota_bench delta             # the comparability gate refusing an incomparable diff
    python -m sota_bench admit decode_v1   # the admission floor rejecting an underpowered slice
    python -m sota_bench score DATA PREDS  # score any labeled dataset against a predictions file

``baseline`` prints the published *aggregate* result only: the positive corpus is
withheld pending coordinated disclosure, so this echoes the pinned numbers from
``PROTOCOL.md`` (the loss, not a win, is the headline) rather than re-scoring data
that is not shipped. ``delta`` and ``admit`` exercise live code paths and print
the *real* messages those functions raise, so the output cannot drift from the
library. ``score`` runs the deterministic scorer over any caller-supplied files.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence

from sota_bench.admission import MIN_SLICE_N, assess_slice_admission
from sota_bench.loop import DeltaResult, delta_vs_baseline
from sota_bench.schema import Prediction, load_dataset
from sota_bench.scorer import score

#: The pinned, PUBLISHED authz_v1 baseline (aggregate metrics only). These are the
#: same numbers documented in ``PROTOCOL.md``; the positive corpus that produced
#: them is withheld pending coordinated disclosure, so this command reports the
#: published result, it does not re-score private data.
_PINNED_AUTHZ: dict[str, dict[str, float]] = {
    "naive": {"recall": 0.833, "precision": 1.000, "youden_j": 0.833},
    "method": {"recall": 0.667, "precision": 0.800, "youden_j": 0.567},
    "delta": {"recall": -0.167, "youden_j": -0.267},
}


def cmd_baseline(_args: argparse.Namespace) -> int:
    """Print the pinned, published authz_v1 baseline (the honest loss)."""
    naive, method, delta = _PINNED_AUTHZ["naive"], _PINNED_AUTHZ["method"], _PINNED_AUTHZ["delta"]
    print("sota_bench | pinned authz_v1 baseline | 16 items | 2026-06-03")
    print(
        f"  naive    recall {naive['recall']:.3f}   "
        f"precision {naive['precision']:.3f}   Youden J {naive['youden_j']:.3f}"
    )
    print(
        f"  method   recall {method['recall']:.3f}   "
        f"precision {method['precision']:.3f}   Youden J {method['youden_j']:.3f}"
    )
    print(
        f"  signed delta   recall {delta['recall']:+.3f}   "
        f"Youden J {delta['youden_j']:+.3f}   :: the method LOST; published as-is."
    )
    print("  note: aggregate metrics only; the positive corpus is withheld pending")
    print("        coordinated disclosure. the loss, not a win, is the headline (PROTOCOL.md).")
    return 0


def cmd_delta(_args: argparse.Namespace) -> int:
    """Demonstrate the comparability gate refusing two runs scored on different corpora."""
    common = {"recall": 0.0}
    new = DeltaResult(
        model_label="release-N",
        dataset_fingerprint="release-N corpus",
        naive_metrics=common,
        method_metrics=common,
        delta=common,
        dataset_hash="sha256:9f2c4e",
        scorer_version="sha256:scorer-v2",
    )
    baseline = DeltaResult(
        model_label="pinned-baseline",
        dataset_fingerprint="pinned corpus",
        naive_metrics=common,
        method_metrics=common,
        delta=common,
        dataset_hash="sha256:1a7e0b",
        scorer_version="sha256:scorer-v2",
    )
    print("sota_bench | comparability gate")
    print("  comparing release-N against the pinned baseline ...")
    try:
        delta_vs_baseline(new, baseline)
    except ValueError as exc:
        for i, line in enumerate(str(exc).split("; ")):
            print(("  ValueError: " if i == 0 else "    ") + line)
        print("  >> the benchmark refuses to compare what it cannot honestly compare.")
        return 0
    print("  (no mismatch raised; this should not happen in the demo)")
    return 1


def cmd_admit(args: argparse.Namespace) -> int:
    """Run the admission floor on an underpowered candidate slice."""
    report = assess_slice_admission({"recall": 1.0 / 3.0}, sample_n=args.n)
    print("sota_bench | slice-admission gate")
    print(f"  candidate: {args.name}    naive recall 0.333    n={args.n}")
    status = "ADMITTED" if report.admitted else "REJECTED"
    print(f"  {status}: (MIN_SLICE_N={MIN_SLICE_N})")
    for reason in report.reasons:
        for i, line in enumerate(reason.split(" (")):
            print(("    - " if i == 0 else "      (") + line)
    print("  >> suggestive, not a calibrated rate. growing toward n>=10.")
    return 0 if report.admitted == args.expect_admit else 1


def _load_predictions(path: str) -> list[Prediction]:
    """Load a predictions JSONL (one ``{finding_id, predicted_label, ...}`` per line)."""
    preds: list[Prediction] = []
    with open(path, encoding="utf-8") as fh:
        for raw in fh:
            raw = raw.strip()
            if not raw:
                continue
            obj = json.loads(raw)
            preds.append(
                Prediction(
                    finding_id=str(obj["finding_id"]),
                    predicted_label=str(obj["predicted_label"]),
                    predicted_cvss_score=obj.get("predicted_cvss_score"),
                    predicted_cvss_band=obj.get("predicted_cvss_band"),
                )
            )
    return preds


def cmd_score(args: argparse.Namespace) -> int:
    """Score a predictions file against a labeled dataset (the deterministic scorer)."""
    dataset = load_dataset(args.dataset)
    predictions = _load_predictions(args.predictions)
    result = score(dataset, predictions)
    print(f"sota_bench | score | {len(dataset)} entries, {len(predictions)} predictions")
    for key, value in result.to_metrics_dict().items():
        print(f"  {key}: {value:.4g}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Construct the argument parser with one subcommand per honesty lock."""
    parser = argparse.ArgumentParser(
        prog="python -m sota_bench",
        description="sota_bench: an open, model-agnostic benchmark for the "
        "validation/calibration layer. Every subcommand runs on a fresh clone.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser(
        "baseline", help="print the pinned, published authz baseline (the method lost)"
    ).set_defaults(func=cmd_baseline)

    sub.add_parser(
        "delta", help="show the comparability gate refusing an incomparable diff"
    ).set_defaults(func=cmd_delta)

    p_admit = sub.add_parser("admit", help="run the admission floor on a candidate slice")
    p_admit.add_argument("name", nargs="?", default="decode_v1", help="candidate slice name")
    p_admit.add_argument("--n", type=int, default=3, help="number of scored items (sample_n)")
    p_admit.add_argument("--expect-admit", action="store_true", help=argparse.SUPPRESS)
    p_admit.set_defaults(func=cmd_admit)

    p_score = sub.add_parser("score", help="score a predictions file against a labeled dataset")
    p_score.add_argument("dataset", help="path to a dataset JSONL")
    p_score.add_argument("predictions", help="path to a predictions JSONL")
    p_score.set_defaults(func=cmd_score)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse ``argv`` and dispatch to the selected subcommand."""
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
