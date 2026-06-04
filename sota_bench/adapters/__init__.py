"""Model adapters for the sota_bench SOTA-validation loop.

This subpackage holds every ``ModelAdapter`` the benchmark knows about. It is
split so the core stays STDLIB-ONLY while optional integrations live behind a
lazy import:

- :mod:`sota_bench.adapters.base` (always importable, stdlib-only) defines the
  :class:`ModelAdapter` seam, the deterministic offline :class:`StubAdapter`,
  and the lazily-imported reference factory :func:`make_openai_adapter`. These
  three names are re-exported here so existing imports such as
  ``from sota_bench.adapters import ModelAdapter, StubAdapter`` keep working.
- :mod:`sota_bench.adapters.inspect_eval` (OPTIONAL) is a thin reference
  wrapper that packages the benchmark as a UK-AISI Inspect AI eval. It imports
  ``inspect_ai`` lazily *inside* its functions and is deliberately NOT imported
  here, so ``import sota_bench.adapters`` never requires the optional
  ``inspect`` extra. Import it explicitly when you want it::

      from sota_bench.adapters.inspect_eval import authz_v1_task

The optional ``inspect_ai`` dependency stays in
``[project.optional-dependencies] inspect`` (``pip install sota_bench[inspect]``)
and is never a core runtime dependency.
"""

from __future__ import annotations

from sota_bench.adapters.base import (
    ModelAdapter,
    StubAdapter,
    make_openai_adapter,
)

__all__ = [
    "ModelAdapter",
    "StubAdapter",
    "make_openai_adapter",
]
