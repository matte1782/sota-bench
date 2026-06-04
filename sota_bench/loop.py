"""The sota_bench SOTA-validation DELTA loop.

This module is STDLIB-ONLY. It implements the pre-registered measurement
protocol documented in ``PROTOCOL.md``:

1. **Pin a baseline.** A *naive single-frontier-call* adapter is run over the
   private dated corpus and its metrics are frozen to disk (:func:`pin_baseline`).
2. **Re-run each release.** On every new frontier model, run both the naive
   adapter and the full *method* scaffold over the same corpus and compute the
   **signed delta** (method minus naive) for each metric (:func:`run_delta`).
3. **Publish the signed delta.** Compare the new run against the pinned baseline
   (:func:`delta_vs_baseline`) so improvement claims are always *method-minus-naive*
   and *release-over-release*, never a single absolute number.

The loop is model-agnostic: it depends only on the :class:`~sota_bench.adapters.ModelAdapter`
seam and on caller-supplied pure functions (``predict_fn``, ``scorer_fn``). It
contains NO LLM-as-judge: scoring is whatever deterministic function the caller
passes, and this module only does the arithmetic of differencing metric maps.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Final

from sota_bench.adapters import ModelAdapter
from sota_bench.schema import BenchEntry, Prediction

__all__ = [
    "FORMAT_VERSION",
    "PredictFn",
    "ScorerFn",
    "DeltaResult",
    "run_pass",
    "run_delta",
    "signed_delta",
    "pin_baseline",
    "load_baseline",
    "delta_vs_baseline",
]

#: On-disk format version for pinned baselines. Bump on incompatible changes.
FORMAT_VERSION: Final[int] = 1

#: A function turning one model's raw text output (for one entry) into a
#: :class:`~sota_bench.schema.Prediction`. Kept caller-supplied so the loop is
#: agnostic to prompt format and parsing.
PredictFn = Callable[[BenchEntry, str], Prediction]

#: A pure, deterministic scorer mapping (dataset, predictions) to a flat dict of
#: named metric -> float. NO LLM-as-judge: this is plain arithmetic over labels.
ScorerFn = Callable[[Sequence[BenchEntry], Sequence[Prediction]], dict[str, float]]


@dataclass(frozen=True)
class DeltaResult:
    """The signed outcome of one delta run on one model release.

    ``delta`` is, key-for-key, ``method_metrics`` minus ``naive_metrics``. A
    positive value means the method scaffold beat the naive single call on that
    metric for this release; negative means it regressed.
    """

    model_label: str
    dataset_fingerprint: str
    naive_metrics: dict[str, float]
    method_metrics: dict[str, float]
    delta: dict[str, float]
    format_version: int = field(default=FORMAT_VERSION)


def run_pass(
    dataset: Sequence[BenchEntry],
    adapter: ModelAdapter,
    predict_fn: PredictFn,
    *,
    prompt_fn: Callable[[BenchEntry], str] | None = None,
) -> list[Prediction]:
    """Run one adapter over a dataset and parse its outputs into predictions.

    For each entry the prompt is built (``prompt_fn`` if given, else the entry's
    ``fp_killer`` text, which is the decisive runtime-gating question), passed to
    ``adapter.run``, and the raw text handed to ``predict_fn`` to become a
    :class:`~sota_bench.schema.Prediction`.

    Args:
        dataset: The benchmark entries, in order.
        adapter: The model under test (naive baseline or method scaffold).
        predict_fn: Turns ``(entry, raw_text)`` into a ``Prediction``.
        prompt_fn: Optional builder of the prompt string from an entry. Defaults
            to using ``entry.fp_killer`` so a bare :class:`StubAdapter` mapping
            can be keyed on the decisive check.

    Returns:
        One ``Prediction`` per entry, in dataset order.
    """
    build = prompt_fn if prompt_fn is not None else (lambda e: e.fp_killer)
    predictions: list[Prediction] = []
    for entry in dataset:
        raw = adapter.run(build(entry))
        predictions.append(predict_fn(entry, raw))
    return predictions


def signed_delta(
    method_metrics: dict[str, float], naive_metrics: dict[str, float]
) -> dict[str, float]:
    """Return ``method_metrics`` minus ``naive_metrics``, key for key.

    Both maps must share exactly the same keys; a mismatch raises ``ValueError``
    so a silently-renamed metric can never produce a misaligned delta.

    Raises:
        ValueError: If the two metric maps do not have identical key sets.
    """
    if method_metrics.keys() != naive_metrics.keys():
        only_method = sorted(method_metrics.keys() - naive_metrics.keys())
        only_naive = sorted(naive_metrics.keys() - method_metrics.keys())
        raise ValueError(
            f"metric key sets differ: only in method={only_method}, only in naive={only_naive}"
        )
    return {k: method_metrics[k] - naive_metrics[k] for k in method_metrics}


def run_delta(
    dataset: Sequence[BenchEntry],
    naive_adapter: ModelAdapter,
    method_adapter: ModelAdapter,
    predict_fn: PredictFn,
    scorer_fn: ScorerFn,
    *,
    model_label: str = "unspecified",
    dataset_fingerprint: str = "",
    prompt_fn: Callable[[BenchEntry], str] | None = None,
) -> DeltaResult:
    """Run both adapters over the dataset and compute the signed method-vs-naive delta.

    This is the core measurement: the same dataset, scored by the same
    deterministic ``scorer_fn``, run once with the naive single-call adapter and
    once with the method scaffold. The returned :class:`DeltaResult` carries both
    metric maps and their signed difference (method minus naive).

    Args:
        dataset: The benchmark entries.
        naive_adapter: The pinned single-frontier-call baseline.
        method_adapter: The full method scaffold under evaluation.
        predict_fn: Turns model text into predictions (used for both adapters).
        scorer_fn: Pure deterministic scorer; same function for both passes.
        model_label: Human-readable name of the frontier release being measured.
        dataset_fingerprint: Opaque identifier of the (private) corpus version.
        prompt_fn: Optional prompt builder (see :func:`run_pass`).

    Returns:
        A :class:`DeltaResult` with ``naive_metrics``, ``method_metrics`` and the
        signed ``delta``.
    """
    naive_preds = run_pass(dataset, naive_adapter, predict_fn, prompt_fn=prompt_fn)
    method_preds = run_pass(dataset, method_adapter, predict_fn, prompt_fn=prompt_fn)

    naive_metrics = scorer_fn(dataset, naive_preds)
    method_metrics = scorer_fn(dataset, method_preds)

    return DeltaResult(
        model_label=model_label,
        dataset_fingerprint=dataset_fingerprint,
        naive_metrics=naive_metrics,
        method_metrics=method_metrics,
        delta=signed_delta(method_metrics, naive_metrics),
    )


def pin_baseline(result: DeltaResult, path: str) -> None:
    """Freeze a :class:`DeltaResult` to disk as the pinned baseline.

    The baseline is the reference point all future releases are differenced
    against. Written as pretty UTF-8 JSON so it can be diffed and reviewed.

    Args:
        result: The result to pin (typically the first/naive-defining run).
        path: Destination JSON file path.
    """
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(asdict(result), fh, indent=2, sort_keys=True)
        fh.write("\n")


def load_baseline(path: str) -> DeltaResult:
    """Load a pinned baseline written by :func:`pin_baseline`.

    Args:
        path: Path to the JSON file.

    Returns:
        The reconstructed :class:`DeltaResult`.

    Raises:
        ValueError: If the file is missing required keys or has a future,
            unsupported ``format_version``.
    """
    with open(path, encoding="utf-8") as fh:
        obj = json.load(fh)

    if not isinstance(obj, dict):
        raise ValueError(f"baseline must be a JSON object, got {type(obj).__name__}")

    version = obj.get("format_version", FORMAT_VERSION)
    if not isinstance(version, int) or version > FORMAT_VERSION:
        raise ValueError(
            f"unsupported baseline format_version {version!r} (this build supports "
            f"<= {FORMAT_VERSION})"
        )

    required = {"model_label", "dataset_fingerprint", "naive_metrics", "method_metrics", "delta"}
    missing = required - obj.keys()
    if missing:
        names = ", ".join(repr(k) for k in sorted(missing))
        raise ValueError(f"baseline missing field(s): {names}")

    return DeltaResult(
        model_label=str(obj["model_label"]),
        dataset_fingerprint=str(obj["dataset_fingerprint"]),
        naive_metrics={str(k): float(v) for k, v in obj["naive_metrics"].items()},
        method_metrics={str(k): float(v) for k, v in obj["method_metrics"].items()},
        delta={str(k): float(v) for k, v in obj["delta"].items()},
        format_version=version,
    )


def delta_vs_baseline(new_result: DeltaResult, baseline: DeltaResult) -> dict[str, float]:
    """Return the release-over-release movement of the signed delta.

    This answers the pre-registered question: *as the frontier improves, does the
    method's edge over a naive single call grow, hold, or shrink?* The value is,
    key for key, ``new_result.delta`` minus ``baseline.delta``, the change in the
    signed method-minus-naive gap from the pinned baseline to the new release.

    Args:
        new_result: The freshly measured release.
        baseline: The pinned reference loaded via :func:`load_baseline`.

    Returns:
        A metric -> float map of the change in signed delta.

    Raises:
        ValueError: If the two deltas do not share identical metric keys.
    """
    return signed_delta(new_result.delta, baseline.delta)
