"""Deterministic target-value (blast-radius) gate for sota_bench.

STDLIB-ONLY, NO LLM. Decides whether a vuln-hunting target is worth deep effort
by measuring its real-world BLAST RADIUS (reverse-dependency reach) and project
importance, so effort concentrates on production-grade, widely-depended-on
software instead of high-severity-but-low-impact targets (a severity-over-importance ranking error).

Primary signal: **deps.dev ``directDependentCount`` at the package's DEFAULT
version** -- the count of packages that directly depend on it, i.e. the code a
vulnerability would actually expose. This is empirically a better importance
proxy than GitHub stars or download counts (which measure human attention /
popularity, not code reuse: e.g. ``left-pad`` has millions of downloads but few
direct dependents). Verified live 2026-06-06: deps.dev v3alpha ``:dependents``
returns ``{dependentCount, directDependentCount, indirectDependentCount}``.

Fallback signal: **OpenSSF Criticality Score** (0..1, Rob Pike weighted mean) for
raw repos / when deps.dev has no dependents endpoint for the ecosystem (e.g. Go
returns 404). It is passed in by the caller (computed out-of-band via the
``ossf/criticality_score`` CLI or read from the hosted CSV), never inferred.

Downloads are a TIE-BREAK only across same-tier candidates (a caller concern);
they NEVER promote a tier here, because they are weak and actively gamed.

Thresholds + axis order are PRE-REGISTERED in ``PROTOCOL.md`` (L6); the module
defaults mirror that pre-registration so the gate cannot be tuned post-hoc.

DETERMINISM is conditional: :func:`decide_tier` is a pure, total function (same
inputs -> same report, no clock, no network), exhaustively unit-tested. The fetch
layer (:func:`resolve_default_version`, :func:`fetch_dependents`) pulls LIVE
signals that drift day-to-day, so :func:`score_target` records ``fetched_at`` and
``resolved_version`` to make a re-run's divergence attributable to source drift,
not code. FAIL-SAFE: a missing/absent signal is ``None`` ("unavailable"), NEVER
coerced to ``0`` (which would falsely trigger reject); when BOTH signals are
unavailable the gate returns ``reject`` with ``manual_override_required=True``.

Citations (verified 2026-06-06):
  - deps.dev dependents (v3alpha): https://docs.deps.dev/api/v3alpha/
  - OpenSSF Criticality Score: https://github.com/ossf/criticality_score
"""

from __future__ import annotations

import datetime
import http.client
import json
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, replace
from typing import Any, Final

__all__ = [
    "DEPS_DEV_SYSTEMS",
    "T1_DEPENDENTS",
    "T2_DEPENDENTS",
    "T3_DEPENDENTS",
    "T1_CRITICALITY",
    "T2_CRITICALITY",
    "T3_CRITICALITY",
    "REJECT_DEP_FLOOR",
    "REJECT_CRIT_FLOOR",
    "TIERS",
    "TargetValueReport",
    "decide_tier",
    "resolve_default_version",
    "fetch_dependents",
    "score_target",
]

# --- Pre-registered thresholds (PROTOCOL.md L6). Project choices, pinned here. ---
#: direct-dependents tier floors (>= is the test).
T1_DEPENDENTS: Final[int] = 5000
T2_DEPENDENTS: Final[int] = 500
T3_DEPENDENTS: Final[int] = 50
#: OpenSSF criticality fallback tier floors (>= is the test).
T1_CRITICALITY: Final[float] = 0.80
T2_CRITICALITY: Final[float] = 0.60
T3_CRITICALITY: Final[float] = 0.40
#: fast-reject floors: tiny reverse-dep reach AND not an important repo.
REJECT_DEP_FLOOR: Final[int] = 50
REJECT_CRIT_FLOOR: Final[float] = 0.40

#: deps.dev package systems that expose a dependents endpoint at version scope.
DEPS_DEV_SYSTEMS: Final[frozenset[str]] = frozenset(
    {"npm", "pypi", "cargo", "maven", "go", "nuget"}
)

#: Allowed tier outcomes.
TIERS: Final[frozenset[str]] = frozenset({"tier1", "tier2", "tier3", "reject"})

_DEPS_DEV_BASE: Final[str] = "https://api.deps.dev"
_USER_AGENT: Final[str] = "sota_bench-target-value"


@dataclass(frozen=True)
class TargetValueReport:
    """The deterministic outcome of valuing a target.

    ``tier`` is one of :data:`TIERS`. ``primary_axis`` names which signal set the
    tier (``"dependents"`` | ``"criticality"`` | ``"none"`` for reject).
    ``direct_dependents`` / ``criticality`` / ``downloads`` are the inputs as
    seen (``None`` = unavailable, never ``0``). ``resolved_version`` and
    ``fetched_at`` are provenance for live-signal drift. ``manual_override_required``
    is True only when no deterministic importance signal was available at all.
    """

    tier: str
    primary_axis: str
    direct_dependents: int | None
    total_dependents: int | None
    criticality: float | None
    downloads: int | None
    resolved_version: str | None
    system: str | None
    fetched_at: str | None
    manual_override_required: bool
    reasons: tuple[str, ...]


def _validate_count(value: int | None, name: str) -> None:
    """Reject a non-None count that is a bool or negative (fail closed)."""
    if value is None:
        return
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} must be an int or None, got {type(value).__name__}")
    if value < 0:
        raise ValueError(f"{name} must be >= 0, got {value}")


def decide_tier(
    *,
    direct_dependents: int | None,
    criticality: float | None,
    downloads: int | None = None,
    system: str | None = None,
    resolved_version: str | None = None,
    total_dependents: int | None = None,
    fetched_at: str | None = None,
    t1_dep: int = T1_DEPENDENTS,
    t2_dep: int = T2_DEPENDENTS,
    t3_dep: int = T3_DEPENDENTS,
    t1_crit: float = T1_CRITICALITY,
    t2_crit: float = T2_CRITICALITY,
    t3_crit: float = T3_CRITICALITY,
    reject_dep_floor: int = REJECT_DEP_FLOOR,
    reject_crit_floor: float = REJECT_CRIT_FLOOR,
) -> TargetValueReport:
    """Pure, total tier decision from measured signals (no clock, no network).

    Ladder (first match wins), per PROTOCOL.md L6:

    * BOTH signals ``None`` -> ``reject`` + ``manual_override_required`` (absence
      of a deterministic importance signal is never read as "important").
    * fast reject: ``direct_dependents < reject_dep_floor`` AND criticality is
      unavailable-or-``< reject_crit_floor`` (tiny reach, not important).
    * ``tier1`` if ``direct_dependents >= t1_dep`` OR ``criticality >= t1_crit``;
      then ``tier2`` / ``tier3`` analogously; else ``reject``.

    ``None`` is treated as "does not satisfy any ``>=`` test"; it is NEVER read as
    ``0``. Downloads are recorded but never affect the tier.

    Raises:
        ValueError: on a malformed count (bool/negative) or out-of-range
            criticality (must be in ``[0.0, 1.0]``).
    """
    _validate_count(direct_dependents, "direct_dependents")
    _validate_count(total_dependents, "total_dependents")
    _validate_count(downloads, "downloads")
    if criticality is not None:
        if isinstance(criticality, bool) or not isinstance(criticality, (int, float)):
            raise ValueError(
                f"criticality must be a float or None, got {type(criticality).__name__}"
            )
        if not (0.0 <= float(criticality) <= 1.0):
            raise ValueError(f"criticality must be in [0.0, 1.0], got {criticality}")

    d = direct_dependents
    c = criticality

    def dep_ge(threshold: int) -> bool:
        return d is not None and d >= threshold

    def crit_ge(threshold: float) -> bool:
        return c is not None and c >= threshold

    def build(tier: str, axis: str, override: bool, reasons: list[str]) -> TargetValueReport:
        return TargetValueReport(
            tier=tier,
            primary_axis=axis,
            direct_dependents=d,
            total_dependents=total_dependents,
            criticality=c,
            downloads=downloads,
            resolved_version=resolved_version,
            system=system,
            fetched_at=fetched_at,
            manual_override_required=override,
            reasons=tuple(reasons),
        )

    if d is None and c is None:
        return build(
            "reject",
            "none",
            True,
            [
                "no deterministic importance signal (dependents and criticality "
                "both unavailable); manual operator override required"
            ],
        )

    if d is not None and d < reject_dep_floor and not crit_ge(reject_crit_floor):
        if c is None:
            # criticality -- the signal that matters for end-user frameworks /
            # self-hosted apps, which under-count on directDependentCount (R6) --
            # was NEVER measured. Do not silently skip: a single measured signal
            # that says "small" plus an unattempted second signal escalates to a
            # logged operator decision, mirroring the both-unavailable branch.
            return build(
                "reject",
                "none",
                True,
                [
                    f"fast-reject-uncertain: direct_dependents={d} < {reject_dep_floor} "
                    "and criticality unavailable; supply OpenSSF criticality or "
                    "override (frameworks/apps under-count on dependents)"
                ],
            )
        return build(
            "reject",
            "none",
            False,
            [
                f"fast-reject: direct_dependents={d} < {reject_dep_floor} and "
                f"criticality {c:.4g} < {reject_crit_floor}"
            ],
        )

    for tier, dep_t, crit_t in (
        ("tier1", t1_dep, t1_crit),
        ("tier2", t2_dep, t2_crit),
        ("tier3", t3_dep, t3_crit),
    ):
        if dep_ge(dep_t):
            return build(tier, "dependents", False, [f"{tier}: direct_dependents={d} >= {dep_t}"])
        if crit_ge(crit_t):
            return build(tier, "criticality", False, [f"{tier}: criticality={c:.4g} >= {crit_t}"])

    return build("reject", "none", False, ["reject: below all tier floors"])


# --- Fetch layer (LIVE, non-deterministic across days; isolated from the core) ---


def _http_get_json(url: str, *, timeout: float) -> dict[str, Any] | None:
    """GET ``url`` and parse a JSON object. ``None`` on HTTP 404 (absent).

    Raises:
        urllib.error.URLError: on non-404 transport/HTTP failure (caller fails safe).
        ValueError: if the body is not a JSON object.
    """
    req = urllib.request.Request(
        url, headers={"Accept": "application/json", "User-Agent": _USER_AGENT}
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
            raw = resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 404:
            return None
        raise
    obj = json.loads(raw)
    if not isinstance(obj, dict):
        raise ValueError(f"deps.dev returned non-object JSON for {url}")
    return obj


def resolve_default_version(system: str, package: str, *, timeout: float = 10.0) -> str | None:
    """Return the deps.dev ``isDefault`` version string for a package, or ``None``.

    The dependents count is VERSION-specific and swings up to ~100x across
    versions, so the default version MUST be resolved and pinned before querying
    dependents. ``None`` means the package or a default version was not found.

    Raises:
        ValueError: if ``system`` is not a supported deps.dev system.
        urllib.error.URLError: on non-404 transport failure.
    """
    sys_l = system.lower()
    if sys_l not in DEPS_DEV_SYSTEMS:
        raise ValueError(
            f"unsupported deps.dev system {system!r}; one of {sorted(DEPS_DEV_SYSTEMS)}"
        )
    url = f"{_DEPS_DEV_BASE}/v3/systems/{sys_l}/packages/{urllib.parse.quote(package, safe='')}"
    obj = _http_get_json(url, timeout=timeout)
    if obj is None:
        return None
    versions = obj.get("versions")
    if not isinstance(versions, list):
        return None
    for ver in versions:
        if isinstance(ver, dict) and ver.get("isDefault") is True:
            key = ver.get("versionKey")
            if isinstance(key, dict):
                value = key.get("version")
                if isinstance(value, str):
                    return value
    return None


def fetch_dependents(
    system: str, package: str, version: str, *, timeout: float = 10.0
) -> tuple[int | None, int | None]:
    """Return ``(direct_dependent_count, total_dependent_count)`` from deps.dev.

    Uses the v3alpha ``:dependents`` endpoint keyed by an exact version. A 404
    (the ecosystem has no dependents endpoint, e.g. Go) yields ``(None, None)``
    so the caller falls back to criticality -- it is NEVER ``(0, 0)``.

    Raises:
        ValueError: if ``system`` is not a supported deps.dev system.
        urllib.error.URLError: on non-404 transport failure.
    """
    sys_l = system.lower()
    if sys_l not in DEPS_DEV_SYSTEMS:
        raise ValueError(
            f"unsupported deps.dev system {system!r}; one of {sorted(DEPS_DEV_SYSTEMS)}"
        )
    pkg = urllib.parse.quote(package, safe="")
    ver = urllib.parse.quote(version, safe="")
    url = f"{_DEPS_DEV_BASE}/v3alpha/systems/{sys_l}/packages/{pkg}/versions/{ver}:dependents"
    obj = _http_get_json(url, timeout=timeout)
    if obj is None:
        return (None, None)

    def _as_count(value: Any) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int):
            return None
        return value if value >= 0 else None

    return (_as_count(obj.get("directDependentCount")), _as_count(obj.get("dependentCount")))


def score_target(
    *,
    system: str,
    package: str,
    criticality: float | None = None,
    downloads: int | None = None,
    timeout: float = 10.0,
    today: str | None = None,
) -> TargetValueReport:
    """Fetch live blast-radius signals and decide a tier, failing safe.

    Resolves the default version, fetches the direct/total dependent counts, and
    runs :func:`decide_tier`. Any deps.dev transport failure is caught and
    recorded; dependents stay ``None`` (NOT ``0``) so the gate falls back to the
    passed-in ``criticality`` (or to ``manual_override_required`` when both are
    unavailable). ``today`` overrides the recorded ``fetched_at`` (for tests).
    """
    fetched_at = today if today is not None else datetime.date.today().isoformat()
    fetch_reasons: list[str] = []
    resolved_version: str | None = None
    direct: int | None = None
    total: int | None = None
    try:
        resolved_version = resolve_default_version(system, package, timeout=timeout)
        if resolved_version is None:
            fetch_reasons.append(
                f"deps.dev: no default version for {system}:{package}; dependents unavailable"
            )
        else:
            direct, total = fetch_dependents(system, package, resolved_version, timeout=timeout)
            if direct is None:
                fetch_reasons.append(
                    f"deps.dev :dependents 404/empty for {system}:{package}@{resolved_version}; "
                    "fell back to criticality"
                )
    except (OSError, urllib.error.URLError, http.client.HTTPException, ValueError) as exc:
        # OSError subsumes URLError/TimeoutError/ConnectionResetError/ssl.SSLError;
        # http.client.HTTPException subsumes IncompleteRead/RemoteDisconnected
        # (IncompleteRead is HTTPException-only, NOT an OSError, so this clause is
        # load-bearing); ValueError keeps the non-dict-body/JSON-decode and the
        # unsupported-system cases. Any real deps.dev transport failure thus fails
        # safe to criticality/override instead of crashing.
        fetch_reasons.append(
            f"deps.dev fetch error ({type(exc).__name__}: {exc}); dependents unavailable, "
            "failing safe to criticality/override"
        )

    report = decide_tier(
        direct_dependents=direct,
        criticality=criticality,
        downloads=downloads,
        system=system,
        resolved_version=resolved_version,
        total_dependents=total,
        fetched_at=fetched_at,
    )
    if fetch_reasons:
        return replace(report, reasons=tuple(fetch_reasons) + report.reasons)
    return report
