"""sota_bench: an open, model-agnostic benchmark for agent tool-dispatch
authorization-confusion vulnerability detection and severity calibration.

The public API is re-exported here so downstream code can import directly from
the top-level package, e.g.::

    from sota_bench import BenchEntry, load_dataset, validate_entry

The core is STDLIB-ONLY. The model-seam adapters live in the
``sota_bench.adapters`` subpackage: the stdlib-only ``ModelAdapter`` /
``StubAdapter`` in ``sota_bench/adapters/base.py``, and an OPTIONAL UK-AISI
Inspect AI packaging in ``sota_bench/adapters/inspect_eval.py`` that requires
the ``inspect`` extra (``pip install "sota_bench[inspect]"``) and imports
``inspect_ai`` lazily so the core import never depends on it.
"""

from __future__ import annotations

from sota_bench.schema import (
    CVSS_BANDS,
    GROUND_TRUTH_VALUES,
    PREDICTED_LABELS,
    VERTICALS,
    BenchEntry,
    Prediction,
    load_dataset,
    validate_entry,
)

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

__version__ = "0.1.0"
