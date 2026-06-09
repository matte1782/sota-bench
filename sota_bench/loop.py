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

Comparability is content-addressed. Every run records a ``dataset_hash``
(SHA-256 over the exact scored corpus) and a ``scorer_version``;
:func:`delta_vs_baseline` refuses to difference two runs unless both match, and
:func:`pin_baseline` is write-once by default. A grown or relabeled corpus, or a
changed scorer, therefore can never be silently differenced against an old pin:
growth happens by minting a NEW fingerprinted pin, never by mutating an old one.
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Callable, Sequence
from dataclasses import asdict, dataclass, field
from typing import Final

from sota_bench.adapters import ModelAdapter
from sota_bench.schema import BenchEntry, Prediction
from sota_bench.stats import paired_significance, significance_to_dict

__all__ = [
    "FORMAT_VERSION",
    "SCORER_VERSION_UNSET",
    "DATASET_HASH_UNHASHED",
    "PredictFn",
    "ScorerFn",
    "DeltaResult",
    "fingerprint_dataset",
    "scorer_source_version",
    "run_pass",
    "run_delta",
    "signed_delta",
    "pin_baseline",
    "load_baseline",
    "delta_vs_baseline",
]

#: On-disk format version for pinned baselines. Bump on incompatible changes.
#: v2 added the content-addressed ``dataset_hash`` and ``scorer_version`` fields.
FORMAT_VERSION: Final[int] = 2

#: Sentinel ``scorer_version`` for a run that did not declare one. Such a result
#: is non-publishable: the pre-registration layer (PROTOCOL.md) requires a real,
#: content-addressed scorer version before a delta may be published.
SCORER_VERSION_UNSET: Final[str] = "unset"

#: Sentinel ``dataset_hash`` filled when loading a legacy baseline that predates
#: content-addressing. A legacy baseline must be re-pinned before its delta can
#: be compared under the binding gate.
DATASET_HASH_UNHASHED: Final[str] = "legacy-unhashed"

#: A function turning one model's raw text output (for one entry) into a
#: :class:`~sota_bench.schema.Prediction`. Kept caller-supplied so the loop is
#: agnostic to prompt format and parsing.
PredictFn = Callable[[BenchEntry, str], Prediction]

#: A pure, deterministic scorer mapping (dataset, predictions) to a flat dict of
#: named metric -> float. NO LLM-as-judge: this is plain arithmetic over labels.
ScorerFn = Callable[[Sequence[BenchEntry], Sequence[Prediction]], dict[str, float]]


def fingerprint_dataset(dataset: Sequence[BenchEntry]) -> str:
    """Return a content-addressed fingerprint of the exact scored corpus.

    The fingerprint is a SHA-256 over the canonical JSON of every entry, sorted
    so the value depends only on the *set of rows and their content*, never on
    row order or dict key order. Any added, removed, or edited field in any row
    changes the digest; a pure reordering does not. This is the comparability
    key: :func:`delta_vs_baseline` only differences two runs whose
    ``dataset_hash`` are byte-identical, so a quietly grown or relabeled corpus
    can never be silently compared against an old pinned baseline.

    Args:
        dataset: The benchmark entries actually scored in this run.

    Returns:
        A string of the form ``"sha256:<hexdigest>"``.
    """
    rows = [
        json.dumps(asdict(entry), sort_keys=True, ensure_ascii=False, separators=(",", ":"))
        for entry in dataset
    ]
    rows.sort()
    digest = hashlib.sha256("\n".join(rows).encode("utf-8")).hexdigest()
    return f"sha256:{digest}"


def scorer_source_version(*paths: str) -> str:
    """Return a content-addressed version tag for the scorer's source code.

    Hashes the raw bytes of the given source files (typically ``scorer.py`` and
    ``cvss.py``) in the order supplied, with a domain separator between files, so
    the tag changes whenever the scoring logic changes. The canonical caller
    passes this as ``scorer_version`` to :func:`run_delta`; the comparability gate
    then refuses to difference two runs scored by different scorer versions.

    Args:
        *paths: Filesystem paths to the scorer source files, in a stable order.

    Returns:
        A string of the form ``"sha256:<hexdigest>"``.

    Raises:
        ValueError: If no paths are given.
    """
    if not paths:
        raise ValueError("scorer_source_version requires at least one source path")
    h = hashlib.sha256()
    for path in paths:
        with open(path, "rb") as fh:
            h.update(fh.read())
        h.update(b"\x00")  # domain separator so concatenation is unambiguous
    return f"sha256:{h.hexdigest()}"


@dataclass(frozen=True)
class DeltaResult:
    """The signed outcome of one delta run on one model release.

    ``delta`` is, key-for-key, ``method_metrics`` minus ``naive_metrics``. A
    positive value means the method scaffold beat the naive single call on that
    metric for this release; negative means it regressed.

    ``dataset_hash`` (SHA-256 of the exact scored corpus) and ``scorer_version``
    are the *comparability key*: a published delta is only valid between two runs
    whose ``dataset_hash`` and ``scorer_version`` both match. ``dataset_fingerprint``
    is a separate human-readable label only; it is never used by the binding gate.

    ``significance`` is the flattened paired-significance verdict (McNemar exact +
    power gate, see :mod:`sota_bench.stats`): it records whether the
    method-vs-naive comparison is powered enough to claim anything on this corpus,
    so a point delta is never silently read as a real effect.
    """

    model_label: str
    dataset_fingerprint: str
    naive_metrics: dict[str, float]
    method_metrics: dict[str, float]
    delta: dict[str, float]
    dataset_hash: str = ""
    scorer_version: str = SCORER_VERSION_UNSET
    significance: dict[str, float] | None = None
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
    scorer_version: str = SCORER_VERSION_UNSET,
    prompt_fn: Callable[[BenchEntry], str] | None = None,
) -> DeltaResult:
    """Run both adapters over the dataset and compute the signed method-vs-naive delta.

    This is the core measurement: the same dataset, scored by the same
    deterministic ``scorer_fn``, run once with the naive single-call adapter and
    once with the method scaffold. The returned :class:`DeltaResult` carries both
    metric maps and their signed difference (method minus naive).

    The corpus is content-addressed here: ``dataset_hash`` is computed from the
    actual ``dataset`` via :func:`fingerprint_dataset` and cannot be supplied by
    the caller, so it always reflects exactly what was scored. ``scorer_version``
    is carried through unchanged; together they form the comparability key the
    binding gate in :func:`delta_vs_baseline` enforces.

    Args:
        dataset: The benchmark entries.
        naive_adapter: The pinned single-frontier-call baseline.
        method_adapter: The full method scaffold under evaluation.
        predict_fn: Turns model text into predictions (used for both adapters).
        scorer_fn: Pure deterministic scorer; same function for both passes.
        model_label: Human-readable name of the frontier release being measured.
        dataset_fingerprint: Human-readable corpus label only (NOT the
            comparability key); the gate uses the computed ``dataset_hash``.
        scorer_version: Caller-declared, content-addressed version of the scorer
            (see :func:`scorer_source_version`). Left as ``SCORER_VERSION_UNSET``
            it marks the result non-publishable.
        prompt_fn: Optional prompt builder (see :func:`run_pass`).

    Returns:
        A :class:`DeltaResult` with ``naive_metrics``, ``method_metrics``, the
        signed ``delta``, the computed ``dataset_hash``, ``scorer_version`` and the
        paired ``significance`` verdict.
    """
    naive_preds = run_pass(dataset, naive_adapter, predict_fn, prompt_fn=prompt_fn)
    method_preds = run_pass(dataset, method_adapter, predict_fn, prompt_fn=prompt_fn)

    naive_metrics = scorer_fn(dataset, naive_preds)
    method_metrics = scorer_fn(dataset, method_preds)

    # Paired honesty: McNemar exact + power gate over the SAME predictions, so a
    # point delta is always accompanied by whether it is even claimable here.
    significance = significance_to_dict(paired_significance(dataset, naive_preds, method_preds))

    return DeltaResult(
        model_label=model_label,
        dataset_fingerprint=dataset_fingerprint,
        naive_metrics=naive_metrics,
        method_metrics=method_metrics,
        delta=signed_delta(method_metrics, naive_metrics),
        dataset_hash=fingerprint_dataset(dataset),
        scorer_version=scorer_version,
        significance=significance,
    )


def pin_baseline(result: DeltaResult, path: str, *, overwrite: bool = False) -> None:
    """Freeze a :class:`DeltaResult` to disk as the pinned baseline.

    The baseline is the reference point all future releases are differenced
    against. Written as pretty UTF-8 JSON so it can be diffed and reviewed.

    A pinned baseline is **write-once by default**: if ``path`` already holds a
    non-empty file, this refuses to clobber it and raises ``FileExistsError``.
    Re-pinning a changed reference must be a deliberate, auditable act, so it
    requires ``overwrite=True``. An empty placeholder file (e.g. one created by
    ``tempfile.mkstemp``) is not a baseline and is written normally.

    Args:
        result: The result to pin (typically the first/naive-defining run).
        path: Destination JSON file path.
        overwrite: When True, replace an existing non-empty baseline. Defaults to
            False so freezing is a property of storage, not operator memory.

    Raises:
        FileExistsError: If ``path`` already holds a non-empty baseline and
            ``overwrite`` is False.
    """
    if not overwrite and os.path.exists(path) and os.path.getsize(path) > 0:
        raise FileExistsError(
            f"refusing to overwrite existing baseline at {path!r}; pass overwrite=True to re-pin"
        )
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

    Note:
        A legacy (v1) baseline that predates content-addressing has no
        ``dataset_hash`` or ``scorer_version``; those load as the
        ``DATASET_HASH_UNHASHED`` / ``SCORER_VERSION_UNSET`` sentinels, which the
        binding gate treats as non-comparable until the baseline is re-pinned.
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

    sig_raw = obj.get("significance")
    significance = (
        {str(k): float(v) for k, v in sig_raw.items()} if isinstance(sig_raw, dict) else None
    )

    return DeltaResult(
        model_label=str(obj["model_label"]),
        dataset_fingerprint=str(obj["dataset_fingerprint"]),
        naive_metrics={str(k): float(v) for k, v in obj["naive_metrics"].items()},
        method_metrics={str(k): float(v) for k, v in obj["method_metrics"].items()},
        delta={str(k): float(v) for k, v in obj["delta"].items()},
        dataset_hash=str(obj.get("dataset_hash", DATASET_HASH_UNHASHED)),
        scorer_version=str(obj.get("scorer_version", SCORER_VERSION_UNSET)),
        significance=significance,
        format_version=version,
    )


def delta_vs_baseline(new_result: DeltaResult, baseline: DeltaResult) -> dict[str, float]:
    """Return the release-over-release movement of the signed delta.

    This answers the pre-registered question: *as the frontier improves, does the
    method's edge over a naive single call grow, hold, or shrink?* The value is,
    key for key, ``new_result.delta`` minus ``baseline.delta`` — the change in the
    signed method-minus-naive gap from the pinned baseline to the new release.

    **Comparability binding (the wall).** A release-over-release delta is only
    meaningful against a byte-identical reference, so this refuses to difference
    two runs unless their ``dataset_hash`` *and* ``scorer_version`` both match. A
    grown or relabeled corpus changes ``dataset_hash``; a changed scorer changes
    ``scorer_version`` — either way the gate raises rather than silently emitting
    an uninterpretable number. Growth is therefore forced down the only safe
    path: mint a NEW fingerprinted pin and start a new series, never re-difference
    an old one.

    Args:
        new_result: The freshly measured release.
        baseline: The pinned reference loaded via :func:`load_baseline`.

    Returns:
        A metric -> float map of the change in signed delta.

    Raises:
        ValueError: If the corpus (``dataset_hash``) or scorer (``scorer_version``)
            differ between the two runs, or if the two deltas do not share
            identical metric keys.
    """
    if new_result.dataset_hash != baseline.dataset_hash:
        raise ValueError(
            "corpus mismatch: cannot difference across a dataset_hash boundary "
            f"(new={new_result.dataset_hash!r} != baseline={baseline.dataset_hash!r}); "
            "a delta is only valid against a baseline pinned on the byte-identical corpus"
        )
    if new_result.scorer_version != baseline.scorer_version:
        raise ValueError(
            "scorer mismatch: cannot difference across a scorer_version boundary "
            f"(new={new_result.scorer_version!r} != baseline={baseline.scorer_version!r}); "
            "re-pin the baseline under the current scorer before comparing"
        )
    return signed_delta(new_result.delta, baseline.delta)
