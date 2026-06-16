# sota_bench

**An open, model-agnostic benchmark for agent tool-dispatch
authorization-confusion vulnerability detection and severity calibration, plus
a non-LLM scorer and a pre-registered SOTA-validation loop.**

`sota_bench` is a standalone benchmark for evaluating automated
vulnerability-discovery systems (LLM agents, static analyzers, hybrid pipelines)
on a security bug *class* that frontier coding agents now produce and miss in
roughly equal measure: **agent tool-dispatch authorization confusion**, a
privileged operation dispatched through an agent / MCP / tool-calling surface
*without re-checking the caller's authorization at the point of dispatch*, or
gated on one path (e.g. REST) but not its equivalent tool/agent twin. Each item
is a labeled finding pinned to a precise `(repo, commit_sha, file, line)`
location with a ground-truth disposition, OWASP/CWE taxonomy, the decisive
runtime-gating check that resolves it, an expected CVSS band/vector, and its
realized disclosure outcome. The core data model, dataset loader, and scorer have
**zero third-party dependencies**; an optional adapter packages the dataset as a
[UK-AISI Inspect](https://inspect.aisi.org.uk/) eval `Task`.

## The measurement-first thesis

Raw absolute scores on a vuln-detection benchmark are not decision-useful: they
rise automatically every time a better base model ships, with or without any
methodological contribution. `sota_bench` is built around a different question:
*does a method add value on top of a naive single frontier-model call, and how
does that value move as the frontier improves?* The unit of measurement is the
**signed delta** (`method_metrics − naive_metrics`), pre-registered in
[`PROTOCOL.md`](PROTOCOL.md) so the headline number cannot be chosen after seeing
results. Three properties make the numbers trustworthy:

- **No LLM-as-judge.** Every metric is a closed-form function of labels and
  predictions. The loop only does the arithmetic of differencing metric maps.
- **Exonerated negatives are first-class.** Each vulnerable finding is paired with
  near-duplicate `secure` / patched twins at the same code location, so a system
  cannot win by pattern-matching the surrounding code: it must reason about the
  gating check. Correctly *clearing* a secure variant counts exactly as much as
  flagging a real bug.
- **Severity is calibrated, both ways.** CVSS error is reported as separate
  non-negative inflation (over-rating) and deflation (under-rating) magnitudes, so
  a system that systematically over- or under-states severity cannot hide behind a
  symmetric mean that cancels to zero.

## Install

```bash
pip install -e .                 # core, stdlib-only, no runtime dependencies
pip install -e ".[inspect]"      # + optional UK-AISI Inspect adapter
pip install -e ".[dev]"          # + pytest, ruff (for development)
```

Requires Python >= 3.11. The core (`sota_bench.schema`, `sota_bench.scorer`,
`sota_bench.loop`, `sota_bench.cvss`, `sota_bench.triad`, and the stdlib
adapters) imports nothing outside the standard library; `inspect_ai` is imported
lazily and only when the optional adapter is actually called.

## Usage

### 1. Load a labeled dataset

```python
from sota_bench import load_dataset, BenchEntry

entries: list[BenchEntry] = load_dataset("datasets/authz_v1.jsonl")
```

`load_dataset` validates every row with a strict, fail-closed, line-aware
validator (`validate_entry`); a bad field names the offending 1-based line.

### 2. Score predictions (non-LLM)

```python
from sota_bench import Prediction
from sota_bench.scorer import score

predictions = [
    Prediction(finding_id=e.finding_id, predicted_label="vuln",
               predicted_cvss_score=None, predicted_cvss_band="high")
    for e in entries
]

result = score(entries, predictions)
print(result.recall, result.precision, result.youden_j)
print(result.inflation_mae, result.deflation_mae)   # severity error, both ways
print(result.to_metrics_dict())                      # flat dict[str, float]
```

`score` matches predictions to entries by `finding_id` and returns a frozen
`ScoreResult` with the OWASP confusion matrix (TP/FP/TN/FN, recall, precision,
specificity, Youden's J), pairwise accuracy over every `(vuln, secure)` pair, the
PrimeVul VD-S operating point, and both-ways CVSS calibration.

### 3. Run the SOTA-validation loop

```python
from sota_bench.loop import run_delta, pin_baseline, load_baseline, delta_vs_baseline
from sota_bench.scorer import scorer_fn

# First release: measure method-minus-naive and pin it.
result = run_delta(
    entries, naive_adapter, method_adapter, predict_fn, scorer_fn,
    model_label="frontier-2026.06", dataset_fingerprint="corpus-v1",
)
pin_baseline(result, "baselines/frontier-2026.06.json")
print(result.delta)                                  # signed method − naive

# Next release: re-run on the same frozen corpus and report movement vs the pin.
baseline = load_baseline("baselines/frontier-2026.06.json")
new_result = run_delta(
    entries, naive_adapter, method_adapter, predict_fn, scorer_fn,
    model_label="frontier-2026.07", dataset_fingerprint="corpus-v1",
)
print(delta_vs_baseline(new_result, baseline))       # change in the gap
```

`naive_adapter` and `method_adapter` are both just `ModelAdapter` subclasses
(the single seam is `run(prompt: str) -> str`), so the identical scoring code
measures the signed delta between them. A deterministic, offline `StubAdapter`
ships for reproducible fixtures and tests. The loop is model-agnostic and imports
no vendor SDK.

## The two pinned baselines (reported honestly)

Both baselines were produced by a frontier (Opus-class) agent and scored with
sota_bench's **own non-LLM scorer**, no LLM-as-judge anywhere. The full
methodology, headline numbers, and caveats are in [`PROTOCOL.md`](PROTOCOL.md);
the public dataset slice is under `datasets/`; the labeled positive corpus and the
dated baselines are withheld pending coordinated disclosure.

### Static baseline

A blind, code-only read over the full labeled `authz_v1` set (the positive items
and two secure twins are withheld from the public slice pending coordinated
disclosure), no advisory lookup. **Result: the method did NOT beat naive on this
slice: naive was strictly better on detection** (naive recall 0.83, precision 1.00,
Youden J 0.83; the runtime-gating "method" proxy lower at recall 0.67, precision
0.80, Youden J 0.57; signed method-minus-naive delta: recall −0.167, Youden J
−0.267, over the pinned 16-item 2026-06-03 baseline). The method's extra skepticism
flipped two calls the wrong way: it cleared
one real vuln to `secure` (a false negative, where an owner-scoped argument made
the dispatch *look* gated) and flagged a by-design shared-capability surface as
`vuln` (a false positive). We publish this negative result as-is. The specific
labeled POSITIVE items behind these counts, and the naive-vs-method baselines that
turn on them, are WITHHELD PENDING COORDINATED DISCLOSURE and will be published
once the underlying advisories are public.

### Runtime baseline (a diagnostic, not a demonstrated edge over naive)

A second, **dynamic** baseline stands the target up, drives the agent/tool-dispatch
path with a fresh per-run CSPRNG sentinel, and lets the runtime gating check fire (or
not) against a live oracle. On this small multi-finding subset the runtime method
matches ground truth, and its one decisive correction flips a static *false negative*
back to `vuln`: a low-privilege member denied on the REST entitlement sibling reached
owner-private content through the agent dispatch sink.

Read honestly, that correction is narrower than it first looks, and we label runtime a
**diagnostic, not an edge over a naive call**. The false negative it repaired was
introduced by the static *method's* own extra skepticism; the **naive single call
already flagged that same row `vuln`**. So on the one row that was truly re-run live,
runtime's delta over naive is **zero**: it undid a mistake the method made and naive
did not. Runtime has not been shown to beat a naive call, and it has not cleared the
method's other v1 error (the AnythingLLM false *positive*), whose runtime exoneration
remains future "expand" work. Two further caveats stated in the artifact and
`PROTOCOL.md`: only part of the subset was truly live-reran (the rest rest on recorded
evidence with no new sentinel minted), and this is not a full re-scoring of the v1
slice. Runtime is a per-row validation technique under test here, not the benchmark's
thesis. The per-target identities, the labeled POSITIVE corpus, and the naive-vs-method
baselines behind this subset are WITHHELD PENDING COORDINATED DISCLOSURE and will be
published once the underlying advisories are public.

## Differentiation

`sota_bench` is positioned against three reference points.

### vs. ZeroPath
ZeroPath is a strong commercial agentic scanner. `sota_bench` adds two axes it
does not score explicitly: **REST-vs-agent path-divergence** (the same operation
gated on one entry point but not its tool/agent twin) and **severity calibration**
(not just "is it a bug?" but "how bad, signed both ways?"). It is also open and
reproducible.

### vs. BACFuzz
BACFuzz is a dynamic broken-access-control fuzzer. `sota_bench` is
**model/language-agnostic and static-capable**, it scores systems that never run
the target, and it treats **exonerated negatives as first-class** labels rather
than as the absence of a crash, so a system is rewarded for correctly clearing
secure code, not only for triggering a failure.

### vs. Anthropic Mythos
Mythos is a large internal evaluation effort. `sota_bench` is **open,
model-agnostic, and honest-band-anchored**: severity is anchored to hand-assessed
CVSS bands rather than self-reported confidence. Be honest about provenance: the
widely-cited Mythos throughput figures are Anthropic *estimates*. The defensible,
comparable signal is the hand-assessed slice: high/critical true-positive rate,
exact-band severity agreement versus security firms, and the small fraction of
disclosed findings that reach a CVE/GHSA. `sota_bench` is built so the numbers it
reports are of the *hand-assessed, reproducible* kind, not the estimated kind.

## Durability: a dated corpus, a non-LLM oracle, and published losses

The durable asset here is not secrecy. It is three things a stronger model cannot
quietly erase:

- **A deterministic, non-LLM differential oracle over a DATED corpus.** Each scored
  item turns on a closed-form check (`fp_killer`) and a paired `secure` twin at the
  same code location, graded by a pure function of labels and predictions (no
  LLM-as-judge). A frontier agent can read the source and even execute it; it cannot
  fabricate a non-LLM oracle's verdict, and it cannot train on a finding whose public
  `evidence_date` postdates its training cutoff.
- **Temporal contamination control, not a secret split.** A benchmark whose labels are
  merely hidden is brittle and unverifiable: a reviewer cannot reproduce it, and the
  hidden labels still leak the day anyone indexes them. Instead, the public `authz_v1`
  slice is the open, reproducible front door, and contamination is controlled by DATE:
  a finding is scored against a model M only if its `evidence_date` is strictly after
  M's training cutoff ([`PROTOCOL.md`](PROTOCOL.md) L3). The same row can therefore be
  fully public AND a valid held-out test for every model whose cutoff predates it. Each
  run is stamped with a content-addressed `dataset_hash` so a published delta is
  attributable to an exact corpus version.
- **Published losses.** The headline is reported as-is, including where the method
  LOSES to a naive single call (the `authz_v1` static baseline below). A method whose
  edge erodes is published as eroded; the pre-registered SOTA loop is the mechanism
  that says so, on schedule.

There is a separate, disclosure-safety reason to hold a finding back: an UNFIXED
advisory. An embargoed vulnerability sits in a private vault, never scored and never
sent to a hosted model, until its advisory publishes, at which point it becomes a
PUBLIC DATED row (verifiable, and contamination-controlled for every prior model).
That vault is a coordinated-disclosure safeguard, not the durability mechanism, and
nothing in it is ever the headline.

## Selected public findings

The track record behind the method: coordinated security disclosures by the author
that are now public (severity as the official advisory rates it). Generated from a
single source of truth; each row is verified against the live advisory state before
it ships.

<!-- PUBLIC-FINDINGS:START (generated by the portfolio's tools/generate_disclosures.py from public-findings.json; do not edit by hand) -->
| finding | severity | identifier | advisory |
|---|---|---|---|
| Open WebUI | High 8.5 | CVE-2026-54008 | [CVE-2026-54008](https://github.com/open-webui/open-webui/security/advisories/GHSA-226f-f24g-524w) |
| dex | High | GHSA-7qjx | [GHSA-7qjx](https://github.com/dexidp/dex/security/advisories/GHSA-7qjx-gp9h-65qj) |
| Langroid | High | GHSA-2pq5 | [GHSA-2pq5](https://github.com/langroid/langroid/security/advisories/GHSA-2pq5-3q89-j7cc) |
| Open WebUI | High 7.3 | GHSA-3wgj | [GHSA-3wgj](https://github.com/advisories/GHSA-3wgj-c2hg-vm6q) |
| MCP Registry | Mod 6.3 | CVE-2026-44430 | [CVE-2026-44430](https://github.com/advisories/GHSA-r48c-v28r-pf6v) |
| GitHub MCP Server | Mod 6.0 | CVE-2026-48529 | [CVE-2026-48529](https://github.com/github/github-mcp-server/security/advisories/GHSA-pjp5-fpmr-3349) |
| Kirby | Mod 5.3 | CVE-2026-45334 | [CVE-2026-45334](https://github.com/getkirby/kirby/security/advisories/GHSA-39vq-49qm-r2mc) |
| Outline | Mod | CVE-2026-43890 | [CVE-2026-43890](https://github.com/outline/outline/security/advisories/GHSA-gf8h-cv9v-q4fw) |
| Google MCP Toolbox | Mod | PR #3324 | [PR #3324](https://github.com/googleapis/mcp-toolbox/pull/3324) |
<!-- PUBLIC-FINDINGS:END -->

Additional findings are in private coordination and are not listed until their
advisories publish.

## Verticals

The flagship vertical is `authz` (agent tool-dispatch authorization confusion):
broken object-/function-level authorization on tool handlers, REST-vs-agent path
divergence, and confused-deputy delegation through a tool-calling layer. A second
`decode` vertical is reserved for parsing/decoding-primitive bugs.

## Metrics, in brief

- **OWASP confusion matrix**: TP/FP/TN/FN with **Youden's J**
  (`sensitivity + specificity − 1`), rewarding systems that both catch vulns *and*
  exonerate secure variants.
- **PrimeVul VD-S**: false-negative rate at a fixed false-positive operating
  point, for comparability with the vulnerability-detection literature.
- **Signed both-ways CVSS-v3.1 calibration MAE**: inflation and deflation kept
  separate, plus exact-band agreement.
- **SOTA-validation delta loop**: continuous, pre-registered re-evaluation of the
  signed method-minus-naive gap on a frozen slice, so regression and saturation
  surface over time.

## References

- OWASP API Security Top 10 (2023): `API1:2023` Broken Object Level
  Authorization, `API5:2023` Broken Function Level Authorization.
  <https://owasp.org/API-Security/editions/2023/en/0x11-t10/>
- CWE-862 Missing Authorization; CWE-863 Incorrect Authorization; CWE-285
  Improper Authorization. <https://cwe.mitre.org/>
- CVSS v3.1 Specification (FIRST). <https://www.first.org/cvss/v3-1/specification-document>
- PrimeVul / VD-S: Ding et al., *Vulnerability Detection with Code Language
  Models: How Far Are We?* <https://arxiv.org/abs/2403.18624>
- UK AI Safety Institute, *Inspect* evaluation framework.
  <https://inspect.aisi.org.uk/>
- Model Context Protocol (MCP) specification. <https://modelcontextprotocol.io/>

## License

Apache-2.0. See [`LICENSE`](LICENSE).
