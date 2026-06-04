"""OPTIONAL UK-AISI Inspect AI packaging for the ``authz_v1`` benchmark.

This module is a thin, best-effort REFERENCE scaffold that exposes the
sota_bench dataset as an `Inspect AI <https://inspect.aisi.org.uk/>`_ ``Task``.
It is **not** part of the stdlib-only core and is **never** imported by it:

- ``inspect_ai`` is imported **lazily, inside the functions** that need it, and
  a clear :class:`ImportError` with an install hint is raised when it is absent.
  Importing this module (``import sota_bench.adapters.inspect_eval``) therefore
  never requires the optional dependency, only *calling* the builders does.
- ``inspect_ai`` stays in ``[project.optional-dependencies] inspect`` and is
  installed with ``pip install "sota_bench[inspect]"``. It is NOT a core dep.

What it does
------------
:func:`authz_v1_task` maps each :class:`~sota_bench.schema.BenchEntry` to an
Inspect ``Sample``:

- ``input``, a code-audit prompt that references the finding's
  ``repo@commit_sha`` and ``file:line`` location plus the decisive
  ``fp_killer`` gating check, and asks for a ``vuln`` / ``secure`` verdict.
- ``target``, the entry's ``ground_truth`` (so the model's verdict is graded
  against the labeled disposition).
- ``metadata``, the full entry, carried through so the scorer can recover the
  numeric/band labels needed for our calibration metrics.

The scorer (:func:`authz_scorer`) is a **non-LLM** grader: it parses a binary
``vuln``/``secure`` verdict out of the model completion, builds a single
:class:`~sota_bench.schema.Prediction`, and delegates to the deterministic
:func:`sota_bench.scorer.score`. There is **no LLM-as-judge** anywhere in the
grading path, exactly as in the core loop.

API-stability note
------------------
The Inspect AI surface (``Task``/``Sample``/``@scorer``/``Score``) evolves. To
keep the *core* import unbreakable this file only touches that surface inside
lazily-imported functions, and resolves the ``correct``/``incorrect`` ``Score``
values defensively. If a future Inspect release renames something, fix it here;
the rest of sota_bench is unaffected.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from sota_bench.schema import BenchEntry, Prediction

if TYPE_CHECKING:  # pragma: no cover - typing only; never imported at runtime here
    from inspect_ai import Task
    from inspect_ai.dataset import Sample
    from inspect_ai.scorer import Scorer

__all__ = [
    "INSTALL_HINT",
    "build_audit_prompt",
    "require_inspect_ai",
    "entry_to_sample",
    "authz_scorer",
    "authz_v1_task",
]

#: Shown in the :class:`ImportError` raised when ``inspect_ai`` is missing.
INSTALL_HINT = (
    "The Inspect AI integration requires the optional 'inspect_ai' package. "
    'Install it with:  pip install "sota_bench[inspect]"  '
    "(or:  pip install inspect_ai). It is intentionally NOT a core dependency."
)


def require_inspect_ai() -> Any:
    """Import and return the ``inspect_ai`` module, or raise a helpful error.

    The import is performed here (not at module top level) so that importing
    :mod:`sota_bench.adapters.inspect_eval`, and, transitively, the core
    package, never requires the optional dependency.

    Returns:
        The imported ``inspect_ai`` module object.

    Raises:
        ImportError: If ``inspect_ai`` is not installed, with an install hint.
    """
    try:
        import inspect_ai  # noqa: F401  (optional, lazily imported by design)
    except ImportError as exc:  # pragma: no cover - exercised only without the extra
        raise ImportError(INSTALL_HINT) from exc
    return inspect_ai


# --- Prompt construction (pure, stdlib-only) ---------------------------------


def build_audit_prompt(entry: BenchEntry) -> str:
    """Build the code-audit prompt for one :class:`BenchEntry`.

    The prompt pins the model to the exact ``repo@sha`` and ``file:line``
    location, surfaces the OWASP/CWE taxonomy, states the decisive runtime-gating
    check (``fp_killer``) in neutral terms, and asks for a one-word
    ``vuln``/``secure`` verdict plus a CVSS band. It is deliberately
    label-free (it never reveals ``ground_truth`` or ``expected_cvss_band``).

    This function is pure and stdlib-only so it can be unit-tested without
    installing ``inspect_ai``.
    """
    owasp = ", ".join(entry.owasp_labels) if entry.owasp_labels else "(none listed)"
    cwe = ", ".join(entry.cwe) if entry.cwe else "(none listed)"
    return (
        "You are auditing a single code location for an agent tool-dispatch "
        "authorization-confusion vulnerability.\n\n"
        f"Repository: {entry.repo}@{entry.commit_sha}\n"
        f"Location:   {entry.file}:{entry.line}\n"
        f"Taxonomy:   OWASP {owasp}; {cwe}\n\n"
        "Decisive gating consideration (the single fact that resolves the case "
        "either way):\n"
        f"  {entry.fp_killer}\n\n"
        "Decide whether the code at this location is exploitable as described, "
        "or whether the gating check makes it safe.\n"
        "Answer on the FIRST line with exactly one of: 'vuln' or 'secure'.\n"
        "On the SECOND line give a CVSS v3.1 severity band, one of: "
        "none, low, medium, high, critical."
    )


def _parse_verdict(completion: str) -> tuple[str, str | None]:
    """Parse ``(predicted_label, predicted_band)`` from a model completion.

    Best-effort and forgiving: the label is ``"vuln"`` if the first non-empty
    line contains "vuln" (else ``"secure"``); the band is the first recognized
    CVSS band keyword found anywhere, or ``None``.
    """
    text = completion.strip().lower()
    lines = [ln.strip() for ln in text.splitlines() if ln.strip()]
    first = lines[0] if lines else ""
    label = "vuln" if "vuln" in first else "secure"

    band: str | None = None
    for candidate in ("critical", "high", "medium", "low", "none"):
        if candidate in text:
            band = candidate
            break
    return label, band


# --- Inspect integration (lazy; touches inspect_ai only inside functions) ----


def entry_to_sample(entry: BenchEntry) -> Sample:
    """Convert one :class:`BenchEntry` to an Inspect ``Sample``.

    ``input`` is the audit prompt, ``target`` is the ground-truth disposition,
    ``id`` is the stable ``finding_id``, and the full entry is carried in
    ``metadata`` so the scorer can recover calibration labels.

    Raises:
        ImportError: If ``inspect_ai`` is not installed (see :data:`INSTALL_HINT`).
    """
    require_inspect_ai()
    from inspect_ai.dataset import Sample

    return Sample(
        input=build_audit_prompt(entry),
        target=entry.ground_truth,
        id=entry.finding_id,
        metadata={
            "finding_id": entry.finding_id,
            "vertical": entry.vertical,
            "expected_cvss_band": entry.expected_cvss_band,
            "ground_truth": entry.ground_truth,
            "variant": entry.variant,
        },
    )


def authz_scorer() -> Scorer:
    """Build a non-LLM Inspect scorer that wraps :func:`sota_bench.scorer.score`.

    The returned scorer parses a binary verdict (and optional band) from the
    model completion, constructs a single :class:`~sota_bench.schema.Prediction`,
    and runs it through the deterministic core scorer for that one sample. The
    per-sample :class:`Score` is ``correct`` iff the detection decision matches
    the labeled ground truth (``vuln`` flagged / ``secure`` cleared); entries
    whose ground truth is ``oos``/``wontfix`` are scored ``noscore`` because the
    core detection metrics exclude them.

    No model is used to judge: grading is pure arithmetic over labels, identical
    in spirit to the core loop's ``scorer_fn``.

    Raises:
        ImportError: If ``inspect_ai`` is not installed (see :data:`INSTALL_HINT`).
    """
    require_inspect_ai()
    from inspect_ai.scorer import Score, accuracy, scorer, stderr

    # Resolve the canonical correct/incorrect Score values defensively across
    # Inspect versions; fall back to the documented "C"/"I" literals.
    try:
        from inspect_ai.scorer import CORRECT, INCORRECT  # type: ignore
    except Exception:  # pragma: no cover - depends on installed inspect_ai version
        CORRECT, INCORRECT = "C", "I"
    try:
        from inspect_ai.scorer import NOANSWER  # type: ignore
    except Exception:  # pragma: no cover - depends on installed inspect_ai version
        NOANSWER = "N"

    # Import the core (non-LLM) scorer lazily too, to keep this module's import
    # graph minimal; it is stdlib-only and always available.
    from sota_bench import scorer as core_scorer

    @scorer(metrics=[accuracy(), stderr()])
    def _authz_scorer() -> Any:
        async def score(state: Any, target: Any) -> Any:
            completion = state.output.completion if state.output else ""
            label, band = _parse_verdict(completion)

            # ``target`` is an Inspect Target; ``.text`` is the ground-truth string.
            ground_truth = getattr(target, "text", str(target)).strip()
            finding_id = str(getattr(state, "sample_id", "") or "")

            # oos / wontfix are excluded from detection scoring upstream.
            if ground_truth not in ("vuln", "secure"):
                return Score(
                    value=NOANSWER,
                    answer=label,
                    explanation=(
                        f"ground_truth={ground_truth!r} is excluded from detection "
                        "metrics; not scored."
                    ),
                )

            entry = BenchEntry(
                finding_id=finding_id,
                vertical="authz",
                repo="",
                commit_sha="",
                file="",
                line=0,
                ground_truth=ground_truth,
                variant="",
                owasp_labels=[],
                cwe=[],
                fp_killer="",
                expected_cvss_band="none",
                expected_cvss_vector=None,
                realized_outcome="",
                public_url=None,
                notes="",
            )
            prediction = Prediction(
                finding_id=finding_id,
                predicted_label=label,
                predicted_cvss_score=None,
                predicted_cvss_band=band,
            )
            result = core_scorer.score([entry], [prediction])
            correct = (result.tp + result.tn) == 1
            return Score(
                value=CORRECT if correct else INCORRECT,
                answer=label,
                explanation=(
                    f"non-LLM grade via sota_bench.scorer: "
                    f"tp={result.tp} fp={result.fp} tn={result.tn} fn={result.fn}; "
                    f"predicted={label!r} band={band!r} vs ground_truth={ground_truth!r}"
                ),
                metadata={"predicted_band": band},
            )

        return score

    return _authz_scorer()


def authz_v1_task(dataset_path: str = "datasets/authz_v1.jsonl") -> Task:
    """Build an Inspect ``Task`` for the ``authz_v1`` benchmark slice.

    Loads and validates the JSONL dataset with the stdlib-only core loader,
    converts every :class:`BenchEntry` to a ``Sample``, and wires the non-LLM
    :func:`authz_scorer`. A plain ``generate()`` solver is used so the model
    under evaluation simply produces the verdict.

    Args:
        dataset_path: Path to the ``authz_v1`` JSONL file (default matches the
            repo layout). Loaded via :func:`sota_bench.schema.load_dataset`.

    Returns:
        An Inspect ``Task`` ready to pass to ``inspect eval`` / ``eval()``.

    Raises:
        ImportError: If ``inspect_ai`` is not installed (see :data:`INSTALL_HINT`).
        ValueError: If the dataset fails core validation.
    """
    require_inspect_ai()
    from inspect_ai import Task
    from inspect_ai.dataset import MemoryDataset
    from inspect_ai.solver import generate

    from sota_bench.schema import load_dataset

    entries = load_dataset(dataset_path)
    samples = [entry_to_sample(e) for e in entries]

    return Task(
        dataset=MemoryDataset(samples),
        solver=generate(),
        scorer=authz_scorer(),
    )
