"""Publication firewall: a STRUCTURAL path-allowlist that fails closed.

This is the security control for the PUBLIC benchmark tree. Its single job is to
keep an answer key (a ``fp_killer`` plus a scored ``ground_truth`` label) for an
embargoed or held-out finding from ever reaching the public repository.

Design (deliberately matching the s22 flaw-hunt requirements):

* **Path-allowlist, not a per-row flag.** A scoring row carries an answer key. In
  the public tree such a row is permitted ONLY if it lives in a file on the
  explicit :data:`PUBLICATION_ALLOWLIST`. The firewall NEVER trusts a per-row
  self-flag such as ``excluded_from_scoring`` (a self-flag is data the author
  controls; the allowlist is a human-reviewed permission set). A vuln row planted
  outside the allowlist fails even if it flags itself excluded.
* **Fail-closed.** A new, unreviewed data file defaults to FORBIDDEN. An unreadable
  or unparseable data file under the scanned dirs is a violation, never a pass.
* **Scope: ``seeds/**`` and ``datasets/**`` only** (where scored / answer-key
  content lives). The package source and tests are out of scope by construction,
  so the literal identifiers ``fp_killer`` / ``ground_truth`` in *code* never trip
  it; only DATA files are scanned.

Adding a file to the allowlist is a deliberate act, and for any positive (``vuln``)
finding it is additionally gated by the embargo rule (only a published or a
``secure`` finding may be allowlisted). This module does NOT itself check live
disclosure state; it is the structural layer. The embargo gate (live ``state``
check) and the mirror-divergence check are the complementary layers.

Honest scope note: the decisive answer-key marker is the ``"fp_killer"`` key and a
labeled ``*.jsonl`` bench row. A result/measurement ``.json`` that merely echoes a
``ground_truth`` outcome (no ``fp_killer``) is NOT an answer key and is not flagged;
the EXISTENCE of an embargoed finding is governed by the embargo gate and the
divergence check, not by this file scanner.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
from dataclasses import dataclass

__all__ = [
    "PUBLICATION_ALLOWLIST",
    "FirewallReport",
    "scan_tree",
]

#: Files explicitly approved to carry answer keys (``fp_killer`` + ``ground_truth``)
#: in the PUBLIC tree. POSIX-relative glob patterns, matched against the repo root.
#: Two categories, both human-reviewed and embargo-cleared:
#:   - the public SCORED slice (``secure`` negatives), and
#:   - the public DEMO seed (already-public positives, marked excluded_from_scoring).
#: A new data file is NOT on this list and therefore defaults to FORBIDDEN.
PUBLICATION_ALLOWLIST: tuple[str, ...] = (
    "datasets/authz_v1.jsonl",
    "seeds/decode_v1/decode_v1.jsonl",
    # Future explicit demo path (kept here so the convention is visible even before
    # any file exists under it; a glob entry is harmless when it matches nothing):
    "seeds/**/demo/*.jsonl",
)

#: Directories under the repo root that the firewall scans.
_SCAN_DIRS: tuple[str, ...] = ("seeds", "datasets")

#: The decisive answer-key marker. Every labeled bench row carries it; result and
#: baseline JSON files do not.
_ANSWER_KEY_MARKER = '"fp_killer"'


@dataclass(frozen=True)
class FirewallReport:
    """The outcome of a publication-firewall scan over a tree."""

    ok: bool
    violations: tuple[str, ...]

    def __bool__(self) -> bool:  # truthy iff clean
        return self.ok


def _is_allowlisted(relpath: str, allowlist: tuple[str, ...]) -> bool:
    """True if ``relpath`` (POSIX) matches any allowlist glob pattern."""
    rp = relpath.replace(os.sep, "/")
    return any(fnmatch.fnmatch(rp, pattern) for pattern in allowlist)


def _scan_file(path: str, relpath: str) -> list[str]:
    """Return violation messages for a single non-allowlisted file (fail-closed)."""
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{relpath}: unreadable data file under a scanned dir, fail-closed ({exc})"]

    violations: list[str] = []
    if _ANSWER_KEY_MARKER in text:
        violations.append(
            f"{relpath}: carries an fp_killer answer key outside the publication allowlist"
        )
        return violations  # decisive; no need to also row-scan

    if relpath.endswith(".jsonl"):
        for lineno, line in enumerate(text.splitlines(), start=1):
            stripped = line.strip()
            if not stripped:
                continue
            try:
                obj = json.loads(stripped)
            except json.JSONDecodeError:
                violations.append(
                    f"{relpath}:{lineno}: unparseable row in a scanned .jsonl, fail-closed"
                )
                continue
            if isinstance(obj, dict) and "ground_truth" in obj:
                violations.append(
                    f"{relpath}:{lineno}: a scored ground_truth bench row outside the "
                    f"publication allowlist"
                )
    return violations


def _scan_allowlisted_file(path: str, relpath: str) -> list[str]:
    """Inside an allowlisted file, flag any SCOREABLE vuln answer key.

    The path-allowlist permits answer keys in this file, but a positive (``vuln``)
    answer key is publishable ONLY as an already-public DEMO row (marked
    ``excluded_from_scoring: true``). A plain ``vuln`` row here is a scored or
    embargoed positive leaking through an allowlisted path. The motivating case:
    the full labeled dev slice (with its vuln answer keys) accidentally pushed over
    the public secure-only slice at the SAME path. The path-allowlist alone cannot
    see that, so this content check closes it. Secure negatives are always fine.

    Note on layering: this is the one place the firewall reads a per-row field
    (``excluded_from_scoring``). It is a SECONDARY publish-readiness guard, not the
    primary control. A demo vuln still has to live in an allowlisted path (the path
    rule) AND clear the embargo gate (live disclosure state, checked elsewhere)
    before it is ever public.
    """
    if not relpath.endswith(".jsonl"):
        return []
    try:
        text = open(path, encoding="utf-8").read()
    except (OSError, UnicodeDecodeError) as exc:
        return [f"{relpath}: unreadable allowlisted data file, fail-closed ({exc})"]
    violations: list[str] = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            obj = json.loads(stripped)
        except json.JSONDecodeError:
            violations.append(
                f"{relpath}:{lineno}: unparseable row in an allowlisted .jsonl, fail-closed"
            )
            continue
        if (
            isinstance(obj, dict)
            and obj.get("ground_truth") == "vuln"
            and obj.get("excluded_from_scoring") is not True
        ):
            violations.append(
                f"{relpath}:{lineno}: a scoreable vuln answer key in the public tree "
                f"(ground_truth=vuln not marked excluded_from_scoring); a scored or "
                f"embargoed positive must never be public"
            )
    return violations


def scan_tree(root: str, *, allowlist: tuple[str, ...] = PUBLICATION_ALLOWLIST) -> FirewallReport:
    """Scan ``root`` for answer-key content outside the publication allowlist.

    Walks every file under ``root/seeds/**`` and ``root/datasets/**``. A file that
    is on ``allowlist`` is approved and skipped. Any other file that carries an
    ``fp_killer`` answer key, or that is a ``*.jsonl`` with scored ``ground_truth``
    bench rows, is a violation. Unreadable/unparseable data files are violations
    too (fail-closed).

    Args:
        root: The repository root to scan.
        allowlist: POSIX-relative glob patterns approved to carry answer keys.

    Returns:
        A :class:`FirewallReport`; ``ok`` is True only when no violation is found.
    """
    violations: list[str] = []
    for scan_dir in _SCAN_DIRS:
        base = os.path.join(root, scan_dir)
        if not os.path.isdir(base):
            continue
        for path in sorted(glob.glob(os.path.join(base, "**", "*"), recursive=True)):
            if not os.path.isfile(path):
                continue
            relpath = os.path.relpath(path, root).replace(os.sep, "/")
            if _is_allowlisted(relpath, allowlist):
                violations.extend(_scan_allowlisted_file(path, relpath))
            else:
                violations.extend(_scan_file(path, relpath))
    return FirewallReport(ok=not violations, violations=tuple(violations))
