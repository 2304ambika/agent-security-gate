# CLAUDE.md — agent-security-gate

Per-repo research notes. Keep this file current; each repository keeps its own CLAUDE.md.

## Research question
Can a system-level security architecture (deterministic TCB + reference monitor in front of every tool) prevent unauthorized actions/data flows even when the LLM agent is successfully manipulated? Grounded in arXiv:2605.18991 (*Agent Security is a Systems Problem*).

## Stance / invariants
- LLM is **untrusted**. No LLM inside the TCB (would reintroduce a probabilistic reference monitor).
- Complete mediation: every tool call goes `task → role → SecurityTCB.invoke → reference monitor → tool`.
- Learning = offline harness (`policy_update.py`) promoting hosts/patterns into policy from labeled FNs; narrowing-only, verified on a benign regression corpus, versioned, rollback-able. Not an in-TCB model.
- Provenance is tracked by the TCB (`session.py`, `session_tracking=True`), not by the caller.

## Layout
- `src/agent_security_gate/` — TCB, monitor, policy, detectors, `session.py` (idea 1), `policy_update.py` (idea 2), `learning.py` (old baseline)
- `docs/ARCHITECTURE.md` (tool-call flow, harness), `docs/EVALUATION.md` (results, validity issues)
- `benchmarks/data/` — scenarios, incident catalog (45 cases), external adapters/datasets
- `benchmarks/runners/` — no-LLM evals (`run_bench`, `run_split_bench`, `run_external_bench`)
- `benchmarks/llm/` — LLM agents behind TCB (`live_agent.py`, `llm_eval.py`)
- `results/{offline,llm}/` metrics JSON; `logs/` git-ignored; `docs/RESEARCH_SUMMARY.md` write-up

## Commands
`make test | demo | ideas | cross | bench | split | split-internal | external | live-mock | llm-eval MODEL=llama3.2 N=3`
(`PYTHONPATH=src`; live-attack/benign need API key + credits.)

## Findings so far
- Canonical paper patterns (P01–P11, "easy"): ASR 0% without learning.
- Hard tier: ASR 9%→0% after absorbing FN `ADV01`.
- Held-out: ASR 17% — `ADV02` (`PROTOCOL_MIRAGE`) still succeeds; snippet learning memorizes, doesn't generalize.
- Structural controls (DNS allowlist, RBAC, immutable config, EXTERNAL→memory deny, sensitive paths) transfer better than string heuristics.
- Trade-off: strict EXTERNAL scanning false-blocks benign security articles quoting injection phrases.
- Monitor latency is sub-millisecond.

## Metrics tracked
ASR↓, TPR/containment↑, FPR↓, utility retention↑, complete mediation =1.0, privilege reduction↑, F1, latency p50/p95. Report held-out ASR and FPR as first-class.

## Findings, 2026-10-29 (see docs/EVALUATION.md)
- `make ideas` → results/offline/ideas_metrics.json: session gate ASR 100%→0% on 13 sessions; 97%→15% on 42 red-team variants (tuned after first pass; residual = declared known gaps).
- `make cross` → results/offline/cross_dataset.json: verified learning transfers weakly across datasets (a3s 50→61%, Lakera 0.5→4% LOSO); FPR 10→30% on coding_agent when the regression corpus has no coding benign data.
- `make split` → results/offline/split_metrics.json: within-pool pooled TPR 68%→82% (verified) vs 73% (snippet), FPR 13.7%.
- External adapters were label-leaky (coding_agent role/trust, hendar tool choice); fixed. Do not reintroduce label-dependent fields in adapters.
- A learned lexical scorer was tried and removed: AUC 0.49 on an unseen benign domain.

## Findings, 2026-10-29 (details in docs/EVALUATION.md)
- `make ideas` -> results/offline/ideas_metrics.json: session gate ASR 100%->0% on 13 sessions; 97%->15% on 42 red-team variants (tuned after a first pass; residual = declared known gaps).
- `make cross` -> results/offline/cross_dataset.json: verified learning transfers weakly across datasets (A3S 50->61%, Lakera 0.5->4% leave-one-out); FPR 10->30% on coding_agent when the regression corpus has no coding benign data.
- `make split` -> results/offline/split_metrics.json: within-pool pooled TPR 68%->82% (verified) vs 73% (snippet), FPR 13.7%.
- External adapters were label-leaky (coding_agent role/trust, hendar tool choice); fixed. Do not reintroduce label-dependent fields in adapters.
- A learned lexical scorer was tried and removed: AUC 0.49 on an unseen benign domain.

## Open questions / next
- Generalizing detectors for instruction-like content on allowlisted destinations.
- Verifiable policy generation; instruction/data separation; IFC.
- Reduce over-blocking of educational EXTERNAL text.
- Avoid train/test leakage: use `make split` (grouped 70/30) for claims.

## Conventions
- Update "Findings" with date + command + metrics file when results change.
- Never commit `.env` (use `.env.example`); no live exploits against production systems.
