# Publication firewall and breach playbook

The benchmark keeps a portion of its labeled corpus out of the public tree: the
answer keys for findings that are still under coordinated disclosure (unfixed
vulnerabilities). This document is the control that keeps those answer keys from
reaching the public repository, and the response if one ever does.

## What is protected

An answer key is a `fp_killer` (the decisive reasoning that resolves a finding)
together with a scored `ground_truth` label. For a fixed-or-secure finding this is
safe to publish. For an unfixed vulnerability under embargo it is not: publishing it
is an uncoordinated disclosure.

## The control (enforced in code and CI)

`sota_bench/publication_firewall.py` is a structural path-allowlist that fails
closed. It is exercised by `tests/test_publication_firewall.py` (red-team tests) and
runs on every push and pull request via `.github/workflows/ci.yml`.

Two layers:

1. **Path-allowlist (primary).** Only files on `PUBLICATION_ALLOWLIST` may carry
   answer keys in the public tree. Any other file under `seeds/**` or `datasets/**`
   that carries an `fp_killer`, or that is a `*.jsonl` with scored `ground_truth`
   rows, fails the build. A new, unreviewed data file defaults to forbidden. The
   firewall never trusts a per-row self-flag: a vuln row planted outside the
   allowlist fails even if it marks itself excluded from scoring.
2. **Scoreable-vuln guard (secondary).** Inside an allowlisted file, a positive
   (`ground_truth: vuln`) row is permitted only if it is an already-public demo row
   marked `excluded_from_scoring: true`. This closes the case where a full labeled
   working slice is pushed over a public secure-only slice at the same path. Secure
   negatives are always allowed.

The complementary layers, enforced outside this file:

- **Embargo gate.** A finding is publishable only when a fresh, live disclosure
  state check says it is published (or it is a secure negative). The authoritative
  signal is always the live state, never a stored string.
- **Mirror-divergence check.** The public mirror must be the intended-public subset
  of the development tree: no development-only private row leaked in, no public row
  missing.
- **Operator review.** Nothing is pushed or published without an explicit human
  approval of the diff.

## Breach playbook (if an embargoed answer key ever reaches the public tree)

A zero-defect control still needs a defined response. If a row that should have been
embargoed is found in the public repository:

1. **Contain.** Remove the offending content and force the public tree back to a
   clean state. Treat the exposure as real from the moment of push, not the moment
   of discovery (search engines and scrapers index quickly).
2. **Notify the maintainer immediately.** Tell the affected project that their
   unfixed finding was briefly exposed, with the exposure window (push time to
   removal time) and what was visible.
3. **Request an embargo extension and reset the disclosure timeline.** Offer to
   restart the coordinated-disclosure clock at the maintainer's discretion; do not
   treat the accidental exposure as a disclosure that starts a public countdown.
4. **Log an incident note.** Record the finding id, the commit that introduced it,
   the exposure window, the root cause (why the firewall or a complementary layer
   did not catch it), and the fix to the control. Add a regression test that would
   have failed on the leak.
5. **Do not re-publish** the finding until its advisory is genuinely public, at
   which point it becomes a normal public dated row.

The control is built to make step 1 through 5 unnecessary. The playbook exists so
that if they ever are necessary, the response is immediate and coordinated rather
than improvised.
