# sota_bench SOTA-validation DELTA loop, PROTOCOL

**Status:** pre-registered. **Format version:** 1. **Scope:** the `authz`/`decode`
verticals defined in `sota_bench/schema.py`.

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
better on detection.** naive recall 1.00 / precision 1.00 / fp_rate 0.00 /
Youden J 1.00 / pairwise 1.00; method recall 0.80 / precision 0.80 /
fp_rate 0.10 / Youden J 0.70 / pairwise 0.72. Signed delta (method − naive):
recall −0.200, precision −0.200, fp_rate +0.100, Youden J −0.300, pairwise
−0.280, inflation_mae +0.633, deflation_mae +0.413.

The method's extra runtime-gating skepticism flipped two calls the wrong way on
this set. One was a false negative on an embargoed target (the method cleared a
real vuln to `secure`); the per finding identity, repo, and exploitation detail
for that item are WITHHELD PENDING COORDINATED DISCLOSURE and will be published
once the advisory is public. The other was a false positive on
`authz-anythingllm-shared-carveout`, flagged as `vuln` although it is a
by-design shared capability. It also widened severity error in both directions.
Note the `vd_s` reading on this set: naive meets the FPR cap (achieved 0.0 ≤
0.005, so vd_s = 1 − recall = 0.0, since naive caught every positive) while
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
  not performed this session (the running containers were not available to
  bootstrap into, and standing up the full multi-service stack was not feasible).
  Verdicts rest on the recorded oracle; **no NEW sentinel was minted through the
  dispatch path this session** for those items.
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
