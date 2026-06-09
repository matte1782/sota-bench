# sota_bench slice registry (SLICES.md)

Append-only registry of every scored corpus slice. A slice MUST be registered
here, with its date, **before** its first scored run (the register-before-run rule
of `PROTOCOL.md` L5). Every release publishes the delta for **all** registered and
pinned slices — never a chosen subset. This file is the salience guard that code
cannot enforce; its git history is the audit trail.

Entries are append-only: to correct one, add a new row that supersedes it; never
edit a past row in place. CI (`tests/test_protocol.py`) fails if any shipped
`datasets/*.jsonl` slice is missing from this registry.

| slice | dataset file | vertical | registered | naive-weak (recall < 0.5)? | role | status |
|---|---|---|---|---|---|---|
| authz_v1 | `datasets/authz_v1.jsonl` | authz | 2026-06-03 | NO — naive recall 0.833 | INVERSE-ANCHOR (commoditized; the method must at least not regress) | pinned (`datasets/baseline_authz_v1_2026-06-03.json`) |

## Planned / not yet shipped

- **decode_v1** (`vertical: decode`) — the moat region: naive-weak (naive recall
  ≈ 0 on the M-01 anchor, where the method scored 2/2). There is NO shipped
  `datasets/decode_v1.jsonl` yet. Admit it under the L4 bar once it ships its naive
  baseline in the same commit; register it here before its first scored run.
  **Admission also requires `sample_n >= MIN_SLICE_N` (=10) naive-scored positive
  rows (L4 condition d).** The current M-01 anchor is a single discordant pair, so
  a `decode_v1` SEED is UNDERPOWERED (n=1): it stays "Planned" here and is NOT
  admitted — `admission.py` mechanically rejects it (fail-safe) until the sample
  reaches the floor. The n=1 seed is a suggestive datapoint, not a measured rate.

## Notes

- `authz_v1` is retained as a deliberate **inverse-anchor**: a naive single call
  already aces it (recall 0.833), so under the L4 admission bar (`naive recall <
  0.5`) it would NOT be admitted as a *new* slice today. It stays as the
  calibration / negative reference — the place the method must at least not regress
  — not as a growth target. Growth goes to naive-weak (decode-like) classes.
