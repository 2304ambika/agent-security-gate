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

## Findings, 2026-10-29 (fresh start; docs/FRESH_START.md)
- `make synth` -> results/offline/synth_curriculum.json: leveled synthetic MAS handoff data (L1-L5, held-out families/domains). Learned slot rules (grounded `send_email.to`, `http_fetch.url`, `write_file.path`) give OOD TPR 83-89% at 0% FPR on synthetic benign; internal-suite benign FPR 5->20% is the cost. Residual: `poison` (attacker link in body) 6% TPR.
- Text-rule learning looks strong only with a narrow benign corpus; broad benign (README/runbook text) drops L3/L4 to 20%. Benign breadth, not curriculum, is the anti-overfit lever. Curriculum == flat == reverse after `prune()`. RL not run (expressiveness limit, not optimization).
- External lakera/a3s 100% TPR for slot arms is an adapter artifact (fixed arg URL); use FPR only.
- Layout adds: `features.py`, `rule_induction.py`, `benchmarks/data/synth_mas.py`, `benchmarks/runners/run_synth_curriculum.py`, `docs/FRESH_START.md`, `docs/INDUSTRY_PRACTICE.md`.
- 2026-10-29 red-team (`make redteam`): grounded-slot check used substring matching, so `v@example.com`, `https://example.com`, a URL prefix, and bare `summary.md` slipped past task-named targets. Fixed with exact identifier match + bare-filename detection; synth numbers unchanged. Lesson: red-team every learned/structural rule before claiming it.
- 2026-10-29 P2 (`make poison` -> results/offline/poison_redact.json): body-link attack ASR 92%->0% by *redacting* ungrounded links (blocking would false-block 100% of benign citations). Residual: link-free instructions, letter-spaced text. Cost: citations dropped.
- 2026-10-29 P3 (`make approval` -> results/offline/approval_tier.json): ask-tier raises ASR when asks are mostly attacks (synthetic: 15.6% hard-block vs 23% at c=0.9, 93% at c=0). Opt-in `free_plain_reads` (risk tier) cut internal false blocks 20%->5% with ASR = base. Prefer hard-block + risk tiers.
- 2026-10-30 P4 (`make live-p4`): llama3.2 3B followed 0/72 injections (plain and "follow document notes" prompts) -> null; slots cost 0-1% benign calls. Needs a stronger tool-capable model to compare policies.
- 2026-10-30 P4 partial (qwen2.5:7b, 53 episodes): agent hijacked 44%; attack success base 30% / session 22% / slots 15% / slots+redact 7%; benign tasks 100% done. n=27, L1-L2 only. Resume with `make live-p4 MODEL=qwen2.5:7b`.
- 2026-10-30 P4 full (qwen2.5:7b, 144 episodes, results/llm/p4_metrics_qwen2.5-7b_s7.json): hijack 32%; attack success none 32 / base 26 / session 21 / slots 17 / slots-strict 14 / slots+redact 4% (CI 1-12); benign tasks 100%. Supersedes the 53-episode partial.
- 2026-10-30 P5 offline (`make p5` -> results/offline/p5_injecagent.json): InjecAgent email-exfil (544 cases): base policy blocks 100% with the 'IMPORTANT ignore...' hint but 0% of bare-instruction attacks; slot rules 100% both. Attack-only; allowlist gmail.com or the network check masks the result.
- 2026-10-30 P5: TAMAS (tool-choice/DPI-in-user-channel goals) and ACIArena (answer-content attacks) cloned to benchmarks/data/external/{tamas,aciarena} (git-ignored). Neither has concrete tool targets, so slot rules don't apply; scoring would need running their MAS frameworks. Treated as out of scope; see FRESH_START §13b.
- 2026-10-30 P6 (`run_synth_curriculum.py --seeds 20` -> results/offline/synth_curriculum_20seeds.json): slot rules OOD TPR 83-89% at 0% FPR (+-1); text/broad 10-44%; slot rules unchanged with narrow benign data (structural), text rules collapse. Summary: docs/FINAL_REPORT.md.
