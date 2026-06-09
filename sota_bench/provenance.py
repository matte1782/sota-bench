"""Append-only corpus provenance and contamination gating for sota_bench.

This module is STDLIB-ONLY and contains NO LLM-as-judge. It provides the two
structural controls of the provenance layer:

* :func:`filter_by_evidence_cutoff` -- the contamination gate. A benchmark that
  is re-run on each new frontier model must not score a finding the model may
  have trained on. Following the contamination-resistant / "scroll through time"
  design (LiveCodeBench and the LLM-vulnerability-detection benchmarks), only
  findings whose earliest public artifact (``evidence_date``) postdates the
  model's training cutoff are eligible. A row with no ``evidence_date`` is
  UNSOURCED and excluded (fail-safe): absence of a date is never read as safe.

* :func:`assert_append_only` -- the immutability / superset check. A frozen
  corpus version grows only by ADDING rows: every earlier finding_id must still
  be present (no removal) and unchanged (no in-place mutation). A correction is a
  NEW row carrying ``supersedes``, never an edit of the original, so any mutated
  shared row is a violation.
"""

from __future__ import annotations

import datetime
from collections.abc import Sequence
from dataclasses import dataclass

from sota_bench.schema import BenchEntry

__all__ = [
    "ContaminationReport",
    "AppendOnlyReport",
    "filter_by_evidence_cutoff",
    "assert_append_only",
]


def _as_date(value: datetime.date | str) -> datetime.date:
    """Coerce a ``date`` or ``YYYY-MM-DD`` string to a ``datetime.date``."""
    if isinstance(value, datetime.date):
        return value
    return datetime.date.fromisoformat(value)


def _index(entries: Sequence[BenchEntry], *, side: str) -> dict[str, BenchEntry]:
    """Index entries by ``finding_id``; raise on a duplicate (scorer parity)."""
    by_id: dict[str, BenchEntry] = {}
    for entry in entries:
        if entry.finding_id in by_id:
            raise ValueError(f"duplicate finding_id in {side} corpus: {entry.finding_id!r}")
        by_id[entry.finding_id] = entry
    return by_id


@dataclass(frozen=True)
class ContaminationReport:
    """The outcome of a contamination-cutoff filter over a dataset."""

    eligible: tuple[BenchEntry, ...]  # rows safe to score against the cutoff
    excluded_unsourced: tuple[str, ...]  # finding_ids with no evidence_date
    excluded_pre_cutoff: tuple[str, ...]  # finding_ids dated on/before the cutoff
    model_training_cutoff: datetime.date

    @property
    def n_eligible(self) -> int:
        """Number of rows eligible to score under the cutoff."""
        return len(self.eligible)

    @property
    def n_excluded(self) -> int:
        """Total rows excluded (unsourced plus pre-cutoff)."""
        return len(self.excluded_unsourced) + len(self.excluded_pre_cutoff)

    @property
    def eligible_ids(self) -> tuple[str, ...]:
        """The finding_ids of the eligible rows, in dataset order."""
        return tuple(e.finding_id for e in self.eligible)


def filter_by_evidence_cutoff(
    dataset: Sequence[BenchEntry], model_training_cutoff: datetime.date | str
) -> ContaminationReport:
    """Keep only findings that became public strictly after the model's cutoff.

    A finding whose ``evidence_date`` is on or before ``model_training_cutoff``
    may be in the model's training data and is excluded (``excluded_pre_cutoff``).
    A finding with no ``evidence_date`` is unsourced and excluded (fail-safe,
    ``excluded_unsourced``) -- a missing date is never treated as safe.

    Args:
        dataset: The benchmark entries.
        model_training_cutoff: The model's training-data cutoff, as a
            ``datetime.date`` or an ISO ``YYYY-MM-DD`` string.

    Returns:
        A :class:`ContaminationReport` partitioning the dataset.
    """
    cutoff = _as_date(model_training_cutoff)
    eligible: list[BenchEntry] = []
    unsourced: list[str] = []
    pre_cutoff: list[str] = []
    for entry in dataset:
        if entry.evidence_date is None:
            unsourced.append(entry.finding_id)
            continue
        evidence = datetime.date.fromisoformat(entry.evidence_date)
        if evidence > cutoff:
            eligible.append(entry)
        else:
            pre_cutoff.append(entry.finding_id)
    return ContaminationReport(
        eligible=tuple(eligible),
        excluded_unsourced=tuple(unsourced),
        excluded_pre_cutoff=tuple(pre_cutoff),
        model_training_cutoff=cutoff,
    )


@dataclass(frozen=True)
class AppendOnlyReport:
    """The outcome of an append-only check from one corpus version to the next."""

    ok: bool
    removed: tuple[str, ...]  # finding_ids in old missing from new (violation)
    mutated: tuple[str, ...]  # shared finding_ids whose row changed (violation)
    added: tuple[str, ...]  # finding_ids new in this version (informational)

    @property
    def violations(self) -> tuple[str, ...]:
        """All violating finding_ids (removed plus mutated), sorted."""
        return tuple(sorted(self.removed + self.mutated))


def assert_append_only(
    old: Sequence[BenchEntry],
    new: Sequence[BenchEntry],
    *,
    raise_on_violation: bool = False,
) -> AppendOnlyReport:
    """Check that ``new`` is an append-only superset of ``old``.

    Two invariants of a frozen, append-only corpus version are enforced:

    * **No removal:** every finding_id in ``old`` is still present in ``new``.
    * **No mutation:** a finding_id present in both has an unchanged row
      (``BenchEntry`` equality, field for field).

    A correction is expressed as a NEW row with ``supersedes`` set, never an
    in-place edit, so a changed shared row is always a violation.

    Args:
        old: The earlier (frozen) corpus version.
        new: The candidate next version.
        raise_on_violation: When True, raise ``ValueError`` if not append-only.

    Returns:
        An :class:`AppendOnlyReport`.

    Raises:
        ValueError: If either side has a duplicate finding_id, or
            ``raise_on_violation`` is set and a violation is found.
    """
    old_by = _index(old, side="old")
    new_by = _index(new, side="new")

    removed = tuple(sorted(fid for fid in old_by if fid not in new_by))
    mutated = tuple(sorted(fid for fid in old_by if fid in new_by and old_by[fid] != new_by[fid]))
    added = tuple(sorted(fid for fid in new_by if fid not in old_by))
    ok = not removed and not mutated

    if raise_on_violation and not ok:
        raise ValueError(f"append-only violation: removed={removed}, mutated={mutated}")
    return AppendOnlyReport(ok=ok, removed=removed, mutated=mutated, added=added)
