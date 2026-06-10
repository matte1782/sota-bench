# sota_bench SOTA-validation DELTA loop, PROTOCOL

**Status:** pre-registered. **Format version:** 3 (additive bump; see the
format-version-2 amendments (L1-L5) and the L6 target-value gate, then the
format-version-3 carve-out (L7) at the end. All earlier sections, including the
"corpus is PRIVATE and dated" text below, are retained UNCHANGED as the historical
record; L7 re-scopes them, it does not rewrite them). **Scope:** the
`authz`/`decode` verticals defined in `sota_bench/schema.py`.

This document specifies, in advance, exactly how `sota_bench` measures whether a
method (a detection scaffold, agent, or pipeline) adds value *on top of a naive
single frontier-model call*, and how that value moves as the frontier improves.
It is pre-registered so the headline number cannot be chosen after seeing the
results.

## Why a signed delta, not an absolute score

Raw absolute scores on a vuln-detection benchmark are not decision-useful: they
rise automatically every time a better base model ships, with or without any
methodological contribution. The quantity that actually answers *"is the method
worth running?"* is the **signed delta**:

```
delta[metric] = method_metrics[metric] - naive_metrics[metric]
```

A positive delta means the scaffold beats a single call on that metric *for this
release*; a negative delta means it regressed (the base model now does the job
unaided). Publishing the signed delta keeps the claim honest as models improve:
a method whose edge erodes to zero is reported as such.

## The pre-registered loop

### 1. Define and pin the naive baseline

- The **naive baseline** is a single frontier-model call: one prompt, one
  response, parsed into a `Prediction` by `predict_fn`. No retrieval, no tools,
  no multi-step scaffold. It is itself a `ModelAdapter` (so the loop scores it
  with identical code to the method).
- The **method** is the full scaffold under test, also a `ModelAdapter`.
- Both are run over the **same** private dated corpus and scored by the **same**
  deterministic `scorer_fn`. `run_delta(...)` returns a `DeltaResult` carrying
  `naive_metrics`, `method_metrics`, and the signed `delta`.
- Freeze the first run with `pin_baseline(result, path)`. This pinned
  `DeltaResult` is the named reference (`model_label`, e.g. `frontier-2026.06`)
  that all future releases are differenced against.

### 2. Re-run on every frontier release

On each new model:

1. Re-run `run_delta(dataset, naive_adapter, method_adapter, predict_fn, scorer_fn,
   model_label="frontier-YYYY.MM", dataset_fingerprint=...)` over the **same**
   corpus and **same** scorer.
2. Compute `delta_vs_baseline(new_result, load_baseline(path))`, the
   release-over-release change in the signed method-minus-naive gap. This is the
   second-order signal: *as the frontier got better, did the method's edge grow,
   hold, or shrink?*

### 3. Publish the signed delta

The published artifact for each release is the pair:

- `new_result.delta`, method minus naive, this release; and
- `delta_vs_baseline(new_result, baseline)`, movement vs the pinned baseline.

Absolute `naive_metrics` / `method_metrics` are reported as supporting context,
never as the headline.

## Invariants (what makes the number trustworthy)

- **No LLM-as-judge.** `scorer_fn` is a pure, deterministic function over labels
  and predictions. The loop module only does the arithmetic of differencing
  metric maps; it never asks a model to grade anything.
- **Same corpus, same scorer, both passes.** The naive and method passes in a
  single `run_delta` use the identical dataset and the identical scorer, so the
  delta isolates the method.
- **Identical metric keys.** `signed_delta` raises if the two metric maps differ
  in their key sets, so a renamed metric can never silently produce a misaligned
  delta.
- **Deterministic, offline tests.** `StubAdapter` supplies canned outputs (no
  network, no randomness), so the documented naive-misses / method-hits split is
  exactly reproducible, see `tests/test_loop.py`.
- **Versioned baselines.** Pinned baselines carry `format_version`;
  `load_baseline` refuses a future version rather than misreading it.

## The corpus is PRIVATE and dated

> Re-scoped by the format-version-3 carve-out (L7) at the end of this document: the
> privacy invariant below binds to SCORED, held-out slices only, and the public
> decode demo (`seeds/decode_v1/`) is non-scored public by design. The original text
> is retained here unchanged as the historical record.

- The scored corpus is **private** and **dated**. Only the signed deltas (and, as
  context, aggregate metrics) are published, never the labeled items. This keeps
  the benchmark from leaking into training data and keeps each release's
  measurement a genuine held-out test.
- Each run records a `dataset_fingerprint` so a published delta is attributable
  to a specific corpus version without revealing its contents.
- Pinning happens once per named baseline; the dated corpus and the pin are
  archived together so any release's delta can be re-derived.

## Minimal usage

```python
from sota_bench.loop import run_delta, pin_baseline, load_baseline, delta_vs_baseline

# First release: pin the baseline.
result = run_delta(
    dataset, naive_adapter, method_adapter, predict_fn, scorer_fn,
    model_label="frontier-2026.06", dataset_fingerprint="corpus-v1",
)
pin_baseline(result, "baselines/frontier-2026.06.json")
print(result.delta)  # signed method-minus-naive, this release

# Next release: re-run and report movement vs the pin.
baseline = load_baseline("baselines/frontier-2026.06.json")
new_result = run_delta(
    dataset, naive_adapter, method_adapter, predict_fn, scorer_fn,
    model_label="frontier-2026.07", dataset_fingerprint="corpus-v1",
)
print(new_result.delta)                              # this release's signed delta
print(delta_vs_baseline(new_result, baseline))       # change in the gap vs the pin
```

## Adapters

The `sota_bench.adapters` package holds every model seam. Its core
(`adapters/base.py`) is stdlib-only and re-exported from the package root:

- `ModelAdapter` (abstract): the only model seam, `run(prompt: str) -> str`.
- `StubAdapter(responses, *, default=None)`: deterministic, offline; `responses`
  is a `Mapping[str, str]` (exact-prompt lookup) or a `Callable[[str], str]`.
  Used for tests and reproducible fixtures.
- `make_openai_adapter(...)`: a thin, OPTIONAL, lazily-imported reference for a
  real networked adapter. The core never imports it; downstream users install the
  extra or subclass `ModelAdapter` directly.

### Optional: Inspect AI packaging

`adapters/inspect_eval.py` is an OPTIONAL, best-effort reference scaffold that
packages the `authz_v1` slice as a UK-AISI [Inspect](https://inspect.aisi.org.uk/)
`Task`. It maps each `BenchEntry` to a `Sample` (input = a code-audit prompt
referencing `repo@sha file:line` + the decisive `fp_killer`; target =
`ground_truth`) and grades with a **non-LLM** scorer that wraps
`sota_bench.scorer`, there is no LLM-as-judge. `inspect_ai` is imported
**lazily inside the functions** (a clear `ImportError` with an install hint is
raised when absent), so importing the package never pulls it in. Install with
`pip install "sota_bench[inspect]"`; it stays in
`[project.optional-dependencies] inspect`, never a core dependency.

## Pinned baseline 2026-06-03

First pinned run over the full labeled `authz_v1` set (its positive items and two
secure twins are withheld from the public slice pending coordinated disclosure, so
these numbers are not reproducible from the 8-entry public slice yet), scored with sota_bench's **own non-LLM scorer**
(`sota_bench.scorer.score`), no LLM-as-judge anywhere. Two blind prediction sets
from a frontier (Opus-class) agent were scored:

- **naive**, a single-pass blind code-only read.
- **method**, the same agent applying the SIBLING-GUARD / RUNTIME-GATING oracle
  with the explicit SECURE (credential-forwarded / re-checked-at-dispatch) carve-out.

**Protocol, blind, code-only, no advisory lookup.** Both sets were produced
reasoning *solely from fetched source* at the pinned `repo@sha file:line`; no
GHSA/CVE/issue/changelog/advisory was consulted, so the realized GHSA outcomes in
the dataset `notes` did not leak into the predictions. **Coverage: every item
had `code_located: true`** in both sets (the agent reached and read the target
dispatch site for every item).

**Headline: the method did NOT beat naive on the full labeled set, naive was strictly
better on detection.** naive recall 0.833 / precision 1.00 / fp_rate 0.00 /
Youden J 0.833 / pairwise 0.833; method recall 0.667 / precision 0.80 /
fp_rate 0.10 / Youden J 0.567 / pairwise 0.60. Signed delta (method − naive):
recall −0.167, precision −0.200, fp_rate +0.100, Youden J −0.267, pairwise
−0.233, inflation_mae +0.594, deflation_mae +0.388.

The method's extra runtime-gating skepticism flipped two calls the wrong way on
this set. One was a false negative on an embargoed target (the method cleared a
real vuln to `secure`); the per finding identity, repo, and exploitation detail
for that item are WITHHELD PENDING COORDINATED DISCLOSURE and will be published
once the advisory is public. The other was a false positive on
`authz-anythingllm-shared-carveout`, flagged as `vuln` although it is a
by-design shared capability. It also widened severity error in both directions.
Note the `vd_s` reading on this set: naive meets the FPR cap (achieved 0.0 ≤
0.005, so vd_s = 1 − recall = 0.167) while
method's achieved FPR 0.10 exceeds the cap, so its `vd_s` is *undefined* and
surfaces as 0.0 in the flattened map. Read the structured `ScoreResult`, not the
flattened map, to keep an undefined rate apart from a genuine zero.

The dated baseline record encodes the embargoed positive set, so it is withheld
pending coordinated disclosure and will be checked in as the pinned reference for
the framework-vs-baseline delta experiment once the underlying advisories are public.

## v2 runtime baseline 2026-06-03

A second, **dynamic** baseline (`mode: "v2 dynamic runtime fp_killer"`). Where the
v1 static method reasons solely from fetched source at `repo@sha file:line`, the
v2 runtime method stands the target up, drives the agent/tool-dispatch path with a
fresh CSPRNG sentinel, and lets the **fp_killer** fire (or not) against a live
oracle: the same low-privilege principal that is DENIED on the REST/entitlement
sibling either does or does not reach the restricted resource through the dispatch
sink.

**The per finding runtime corpus for this baseline is WITHHELD PENDING COORDINATED
DISCLOSURE.** The runtime subset is built entirely from embargoed targets, so the
finding_ids, repos, GHSA ids, the per-finding naive-vs-static-vs-runtime table,
and all target-specific exploitation detail are withheld and will be published
once the relevant advisories are public. Only the general methodology and the
aggregate framing are reported here.

**Aggregate framing (computed honestly), no embargoed target named.** On this
small runtime subset the dynamic method matched ground truth on every covered
finding. Its one decisive correction over the v1 static method was a repaired
static **false negative**: a case where a scoped access decorator made the
dispatch "look gated" so static skepticism cleared a real vuln to `secure`, and
the runtime fp_killer, fired on a live re-run with fresh per-run CSPRNG sentinels,
flipped it back to `vuln` because the low-privilege principal that is denied on
the REST sibling reached owner-private content through the agent dispatch sink with
no authz denial. The remaining covered findings were already correct under the
static method and stayed correct. So static skepticism failed exactly once here
and the runtime oracle repaired it; everywhere else the two methods agree with
ground truth.

**Coverage / honesty caveats.**
- **Live-reran: a strict subset of the covered findings** (fresh stacks brought up
  and torn down; fresh per-run sentinels).
- **Recorded-evidence only: the remaining covered findings.** Their live re-run was
  not performed in that recorded run (the running containers were not available to
  bootstrap into, and standing up the full multi-service stack was not feasible).
  Verdicts rest on the recorded oracle; **no NEW sentinel was minted through the
  dispatch path in that recorded run** for those items.
- **Not covered: the AnythingLLM static FALSE POSITIVE.** The static method's
  *other* v1 error, `authz-anythingllm-shared-carveout` (static `vuln` vs
  ground-truth `secure`, a by-design shared capability), is **not** in this subset
  because AnythingLLM was not cloned/re-run. Its runtime exoneration is future
  **"expand"** work. This runtime result therefore demonstrates the method
  correcting a static **false negative**, but does **not** yet show it clearing the
  static **false positive**.

The naive-vs-method baselines and the labeled POSITIVE corpus underlying this
runtime baseline are WITHHELD PENDING COORDINATED DISCLOSURE and will be published
once the advisories are public.

## Pre-registered amendments, format version 2 (L1-L5)

Format version 2 hardens the protocol with five structural layers, each enforced
in code (see the cited modules) and each tested. The on-disk pinned-baseline
schema gains `dataset_hash`, `scorer_version`, and a `significance` block;
`BenchEntry` gains optional `evidence_date`, `added_in_corpus_version`, and
`supersedes`. Legacy v1 baselines and rows still load (the new fields default to
non-comparable sentinels / `None`), so this amendment is additive.

### L1: Comparability binding (`sota_bench/loop.py`)

- Every run records a content-addressed `dataset_hash` (SHA-256 of the exact
  scored corpus, computed by the loop, NOT caller-supplied) and a
  `scorer_version`. `dataset_fingerprint` is a human label only and is never the
  comparability key.
- `delta_vs_baseline` REFUSES to difference two runs unless their `dataset_hash`
  AND `scorer_version` both match. A grown or relabeled corpus, or a changed
  scorer, can never be silently differenced against an old pin; growth happens
  only by minting a NEW fingerprinted pin and starting a new series.
- `pin_baseline` is write-once: it refuses to overwrite a non-empty pin without an
  explicit `overwrite=True`, so a frozen reference is a property of storage.
- `scorer_version` MUST fold in every scoring parameter that can change a metric,
  including the VD-S FPR cap (`vd_s_fpr_target`, default 0.005). Changing the cap
  is a new `scorer_version` and forks a new comparison lineage.

### L2: Statistical honesty (`sota_bench/stats.py`)

- The headline comparison is the paired method-vs-naive correctness over the SAME
  findings, tested with McNemar's two-sided EXACT-BINOMIAL test, never a
  chi-squared approximation, never a raw proportion difference.
- **Primary metric (pre-registered): the signed delta on RECALL** (method recall
  minus naive recall). It is always defined and maps directly onto the McNemar
  paired correctness. All other metrics (precision, VD-S, Youden's J, pairwise,
  calibration) are SECONDARY and their p-values are Holm-corrected. The primary
  metric is fixed here so it cannot be chosen after seeing results.
- **UNDERPOWERED is mandatory.** Below 10 discordant pairs (`MIN_DISCORDANT_PAIRS`)
  no significance may be claimed: the `significance` block records `powered: 0` and
  `significant: -1`, and the headline MUST carry the UNDERPOWERED label. At the
  current corpus size this is the expected, honest state, the only durable fix is
  more rows in naive-weak classes, not a different test.
- Uncertainty is reported with Wilson score intervals (small-N-correct), never a
  bare point estimate and never a bootstrap CI (anti-conservative at n ≤ 20).

### L3: Provenance and contamination (`sota_bench/provenance.py`, `schema.py`)

- `evidence_date` is the ISO date of the EARLIEST public artifact for a finding -
  the fix commit / patch PR, which predates the CVE/advisory by months. It is the
  contamination anchor; the CVE/advisory date is NOT used because the patch
  circulates first.
- **Contamination gate.** A finding is eligible for a model release only if its
  `evidence_date` is strictly AFTER that model's training cutoff. Rows with no
  `evidence_date` are UNSOURCED and excluded (fail-safe): a missing date is never
  read as safe, and is NEVER fabricated.
- **Append-only corpus.** Rows are immutable; a correction is a NEW row carrying
  `supersedes`, never an in-place edit. From version N to N+1,
  `ids(vN) ⊆ ids(vN+1)` and shared rows are byte-identical (`assert_append_only`).

### L4: Slice-admission bar (`sota_bench/admission.py`)

- A new slice / vertical is admissible only if (a) its naive baseline is committed
  alongside it, (b) the naive baseline is WEAK, **naive recall < 0.5** on the
  slice, (c) its metric key-set is ADDITIVE over any prior pinned baseline
  (new metrics allowed; dropping or renaming a published key is not), and (d) the
  gating metric is computed over **at least `MIN_SLICE_N = 10` items**
  (`sample_n >= MIN_SLICE_N`; for the default recall metric, the count of
  positive / `vuln` rows the naive recall was measured over).
- The 0.5 bar is the pre-registered midpoint that cleanly separates the anchors:
  authz naive recall 0.833 (REJECTED, commoditized, more raw-authz-detection rows
  would dilute the signal) vs decode naive recall 0 (ADMITTED, the moat region).
  It can change ONLY via a new `format_version`, so it cannot be tuned post-hoc.
- The `MIN_SLICE_N = 10` floor (condition d) is the anti-anecdote lock: without it
  a 1-row seed with naive recall 0 mechanically passes (a)-(c), so "naive-weak"
  would be asserted from a single 1/1 naive-miss rather than a measured RATE
  (disqualifier #6: n=1-treated-as-a-rate). The floor is **fail-safe**, a slice
  whose `sample_n` is not supplied is REJECTED, never admitted on a missing signal
  (mirrors the L3/L6 provenance fail-safe). It is pinned at 10 to align with the
  L2 `MIN_DISCORDANT_PAIRS` significance floor and the pre-registered "n >= ~10"
  calibrated-rate threshold, and changes ONLY via a new `format_version`. This is
  exactly why `decode_v1` ships first as an UNDERPOWERED n=1 SEED (registered
  "Planned", NOT admitted): admission waits until it carries >= 10 naive-scored
  positives, the point at which naive-weakness becomes a rate rather than an anecdote.

### L5: Slice registry and salience (`SLICES.md`)

- Every scored slice is registered in `SLICES.md` BEFORE its first scored run, with
  its date and naive-weakness status. An unregistered `datasets/*.jsonl` slice
  fails CI (`tests/test_protocol.py`).
- **Publish ALL pinned slices' deltas every release, never a chosen subset.** The
  L1-L4 structure guarantees each published number is internally honest, but it
  cannot enforce WHICH number is headlined; this register-before-run +
  publish-all rule is the salience guard, auditable via the registry's history.

### L6: Target-value (blast-radius) gate (`sota_bench/target_value.py`)

Selection control for WHERE to hunt: a deterministic, STDLIB-ONLY, NO-LLM gate
that values a target by real-world BLAST RADIUS and importance, so deep effort
concentrates on production-grade, widely-depended-on software rather than
high-severity-but-low-impact targets (a severity-over-importance ranking error, where
a low-adoption project could be ranked PRIMARY purely on a high CVSS). Enforced in code and
tested in `tests/test_target_value.py` (42 cases, offline).

- **Primary signal: deps.dev `directDependentCount` at the package's `isDefault`
  version**, reverse-dependency reach, i.e. the code a vulnerability would
  actually expose. Empirically a better importance proxy than GitHub stars or
  download counts (which measure attention/popularity, not reuse). The dependents
  count is VERSION-specific (swings up to ~100x across versions), so the default
  version MUST be resolved and pinned before querying; `score_target` records the
  resolved version.
- **Fallback signal: OpenSSF Criticality Score (0..1)** for raw repos / ecosystems
  with no dependents endpoint (e.g. Go returns 404). It is passed IN (computed
  out-of-band via the `ossf/criticality_score` CLI or the hosted CSV), never
  inferred by a model.
- **Tie-break only: package downloads**, recorded, but NEVER promote a tier
  (weak, CI/mirror-inflated, actively gamed).

**Pinned thresholds (project choices, fixed here so the tier cannot be tuned
post-hoc; changeable ONLY via a new `format_version`):**
- direct-dependents: `tier1 >= 5000`, `tier2 >= 500`, `tier3 >= 50` (`>=` test).
- criticality (fallback): `tier1 >= 0.80`, `tier2 >= 0.60`, `tier3 >= 0.40`.
- fast-reject: `direct_dependents < 50` AND (criticality unavailable OR `< 0.40`).
- **Hunt rule:** PRIMARY requires `tier1` or `tier2`; `tier3` is opportunistic and
  effort-capped (source-confirmed report, no full standup); `reject` is skipped.

**Fail-safe invariants (mirror the L3 provenance fail-safe):**
- A missing/absent signal is `None` ("unavailable"), NEVER coerced to `0` (which
  would falsely trigger reject). `0` is a real measured value; `None` is absence.
- When BOTH dependents and criticality are unavailable, the gate returns `reject`
  with `manual_override_required=True`, absence of a deterministic importance
  signal is never read as "important"; any override is a logged operator decision.
- **Determinism is conditional.** `decide_tier` is a pure, total, clock-free,
  network-free function (exhaustively unit-tested). The fetch layer pulls LIVE
  signals that drift day-to-day, so `score_target` records `fetched_at` and
  `resolved_version`; a re-run's divergence is attributable to source drift, not
  code. Tests stub the HTTP call (no network).

**Scope.** L6 selects WHERE to hunt (importance/blast radius). It does NOT replace
L4 (naive-weak slice admission, does the class have method headroom) or L3
(provenance / dedup / contamination). A high-blast-radius target can still yield a
naive-aceable or duplicate slice; run all three.

**Citations (verified 2026-06-06):** deps.dev dependents
(`https://docs.deps.dev/api/v3alpha/`, live shape `{dependentCount,
directDependentCount, indirectDependentCount}`); OpenSSF Criticality Score
(`https://github.com/ossf/criticality_score`, Rob Pike weighted-arithmetic-mean);
"stars/downloads mislead vs reverse-dependents" verified on requests/express/
left-pad/react. SOTA grounding for the L4 naive-weak gate and the embargoed
(model-cutoff-relative) row pattern: Risse et al. (arXiv 2408.12986), PrimeVul
(arXiv 2403.18624), LiveCodeBench (arXiv 2403.07974).

## Pre-registered amendment, format version 3 (L7: public demo carve-out)

Dated 2026-06-10. Additive. This amendment does not rewrite any earlier section or
threshold; it re-scopes the privacy invariant and records the structural control.
The original "The corpus is PRIVATE and dated" section, and the full commit history
(including the commit that first published the decode demo answer keys), are retained
as the historical record. Nothing is retconned.

### L7.1 The privacy invariant binds to SCORED slices only

The "corpus is PRIVATE and dated" rule applies to SCORED, held-out slices: the
labeled items behind a published delta are not released while that slice is the
held-out test. It does NOT mean every artifact in the repository is secret. The
durability of a scored slice comes from DATE, not secrecy: per the L3 contamination
gate a finding is scored against a model only if its `evidence_date` is strictly
after that model's training cutoff, so a label can be fully public and still a valid
held-out test for every model whose cutoff predates it.

### L7.2 The decode demo is non-scored public by design

The `seeds/decode_v1/` rows are a PUBLIC DEMO / CALIBRATION set, not a scored slice.
They are already-public, previously-disclosed findings, shipped WITH their answer
keys as a worked illustration, and each carries `excluded_from_scoring: true`. They
are permanently non-scoreable: their labels are public and their evidence dates
predate current model cutoffs. Publishing them does not violate L7.1 because they are
not a held-out test. This records the status of content first published in the seed
commit; it is a reclassification of already-public material, not a new disclosure.

### L7.3 The publication firewall is the structural control

The boundary between public and held-out content is enforced in code and CI by the
publication firewall (`sota_bench/publication_firewall.py`,
`tests/test_publication_firewall.py`, `.github/workflows/ci.yml`), and documented,
with its breach playbook, in `PUBLICATION_FIREWALL.md`. It is a path-allowlist that
fails closed and never trusts a per-row self-flag: a scoreable `vuln` answer key
outside the explicit demo allowlist fails the build. The firewall is the structural
layer; the embargo gate (a live disclosure-state check) and operator review are the
complementary layers.
