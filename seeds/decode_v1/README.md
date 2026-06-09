# decode_v1 - SEED (n=3, UNDERPOWERED, recall-only, NOT an admitted slice)

This directory holds the **seed** for the `decode` vertical of `sota_bench`. It is
deliberately **outside `datasets/`** so CI (`tests/test_protocol.py`) does not treat
it as a shipped slice, and it is **not** registered as admitted in `SLICES.md`
(it stays under *Planned / not yet shipped*).

## What this is
Three real, **publicly-disclosed** decode-incompleteness findings (see
`decode_v1.jsonl` + `measurements_2026-06-09.json`):
1. **Monetrix M-01** (Code4rena, Solidity/DeFi) - the `0x811` precompile read keeps
   supply, **drops the borrow/debt leg** → phantom-yield backing. *Subtle.*
2. **Kora GHSA-x442** (Solana/Rust) - an unrecognized instruction is rebuilt as an
   **empty stub** (`accounts=[]`, `data=[]`), dropping the fields the fee-payer
   policy needs → fail-open. *Subtle, cross-domain.*
3. **Debita Pyth #499** (Solidity/oracle) - `getThePrice` **drops `expo`** (the
   scaling exponent) → mispriced collateral. *Eyeball-able CONTROL (naive catches it).*

## The measurement (see `measurements_2026-06-09.json`)
Blind, code-only, clean-room; undirected naive vs decode-completeness method.
**Across n=3: method recall 3/3, naive 1/3** - but the entire edge is on the **two
subtle** cases (naive reaches the decode and rules it out); on the eyeball-able
control naive also catches it. **Recall-only**: all three are positives, so
precision/FP-rate is **unmeasured** until secure/negative decode rows are added.

## What this is NOT
- **NOT a calibrated rate.** n=3, recall-only. `3/3` vs `1/3` is *suggestive*, not a
  measured rate (and precision is unmeasured: no secure decode rows yet).
- **NOT admissible.** `admission.py`'s `MIN_SLICE_N = 10` floor mechanically rejects
  any slice with fewer than 10 scored items (disqualifier #6: n=1-treated-as-a-rate).
- **NOT the headline.** The published headline result is the **authz_v1 LOSS**
  (naive recall 0.833 > method 0.667, delta -0.167). This decode win is the *inverse
  anchor*: the one in-hand class where the method shows an edge, recorded honestly as
  a single underpowered datapoint.

## To turn this seed into a measurement
Accumulate **>= 10** discordant decode findings (each a real, dup-verifiable,
public-once-disclosed decode bug), score each blind/clean-room, then - only then -
register `decode_v1` in `SLICES.md`, ship its naive baseline in the same commit, and
let it pass the L4 admission bar. Until then it remains a seed.

## Honesty note
A first naive run was **discarded as contaminated** (its prompt leaked the
"is it a decode bug?" direction). The valid run uses an undirected naive prompt.
The benchmark exists precisely to stop us from over-claiming a rate from an anecdote.
