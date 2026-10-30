---
name: research-build-loop
description: Use when extending this repo (or a similar security/ML research codebase) with a new idea — understand architecture, implement with a runnable eval, red-team it, and write findings/docs. Cuts re-prompting and token use by fixing the order of work and the validity checks.
---

# Research build loop

## 0. Orient (≤5 tool calls, batched)
- Read `CLAUDE.md` (invariants, findings, commands) and `docs/ARCHITECTURE.md` only. Do not scan the tree.
- Grep for the touched symbol (`SecurityTCB.invoke`, `policy.py`, etc.); read only those ranges.
- State invariants before coding; violating one = stop and ask. Here:
  - LLM untrusted; no LLM/learned-probabilistic model inside TCB.
  - Complete mediation: `task → role → SecurityTCB.invoke → monitor → tool`.
  - Learning is offline, narrowing-only, verified on benign corpus, versioned, rollback-able.
  - Provenance tracked by TCB, never by caller.
- Ask ≤3 questions in one round only if the answer changes the result (dataset? metric? model?). Else pick a default and say it.

## 1. Before writing code (reuse order)
Existing project code → stdlib → existing dep → minimal new code. Extend `features.py`, `rule_induction.py`, `policy_update.py`, existing runners; new runner = one file `benchmarks/runners/run_<idea>.py` + one `make` target. Edit in place; never rewrite whole files.

## 2. Evaluate every idea with these (report all, not just the good one)
- ASR↓ (with 95% CI, n stated), TPR/containment↑, **FPR↓ on benign**, utility/benign-task completion↑, held-out ASR, latency p50/p95, complete mediation = 1.0.
- Baselines: no gate, base policy, previous best. Ablate each new component.
- Splits: grouped train/test (`make split`); held-out families/domains; multiple seeds (≥20 offline, report ±).
- Benign breadth is the anti-overfit lever: test with narrow AND broad benign corpus.

## 3. Validity checklist (past failures — check before claiming a number)
- Label leakage in adapters (role/trust/tool choice derived from label). Never add label-dependent fields.
- Fixed-arg or trivially-matching datasets inflate TPR (lakera/a3s slot arms) → use FPR only there.
- Substring matching for "grounded" checks is bypassable → exact identifier match; red-team (`make redteam`) every structural/learned rule.
- Tuned-after-first-pass numbers must be labeled as tuned; residual = declared known gaps.
- Tiny LLM (3B) following 0 injections = null result, not evidence; use a tool-capable model (qwen2.5:7b+), report hijack rate beside ASR.
- Attack-only datasets: say so; no FPR claim.
- Dataset lacking concrete tool targets (TAMAS, ACIArena) → out of scope, document why, move on.
- Learned text scorers: test on unseen benign domain first (AUC 0.49 killed one). Prefer structural controls (slot/allowlist/RBAC/redaction) over string heuristics.
- Prefer redact/hard-block + risk tiers over ask-tier when asks are mostly attacks.

## 4. Run
`PYTHONPATH=src`; `make test` first (fast), then the one relevant target. Long runs (`live-*`, `llm-eval`) in background; quote only the shortest failing line. Results go to `results/{offline,llm}/<name>.json`; logs git-ignored; never commit `.env`.

## 5. Docs (write once, small)
- Append to `CLAUDE.md` "Findings": `YYYY-MM-DD <phase> (\`make X\` -> results/path.json): headline metric before→after, n/CI, cost, residual`. One line-bullet each; no duplicate sections (the file already has a duplicated 2026-10-29 block — dedupe, don't add).
- Long-form goes in `docs/` (EVALUATION, FRESH_START, FINAL_REPORT); link, don't paste. Structure: question → method → table of metrics (incl. FPR, held-out) → threats to validity → residual/next.
- Confirm format only if the user didn't name one; default = markdown in repo.

## 6. Token discipline
- Batch independent reads/greps in one message; use file:line refs, not pasted blocks.
- Don't re-read files you just edited; don't re-derive facts in CLAUDE.md.
- Delegate wide searches to a subagent; do ≤5-call lookups inline.
- Final answer: result + metrics + one-line caveats. No workflow narration.

## 7. Done =
Tests pass, one `make` target reproduces the number, red-teamed, FPR + held-out reported, CLAUDE.md finding added, nothing committed unless asked.
