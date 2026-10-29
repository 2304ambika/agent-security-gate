# Agent Security Gate

A research prototype: put a small, deterministic **reference monitor** in front of every tool an LLM agent can call, so that unauthorized actions and data flows fail **even when the model has been manipulated**. Grounded in [arXiv:2605.18991](https://arxiv.org/abs/2605.18991) (*Agent Security is a Systems Problem*). The LLM is untrusted and no model sits inside the trusted code.

Two ideas are built on top of the basic gate:

1. **History-aware, risk-adaptive gating** (`src/agent_security_gate/session.py`). The gate tracks provenance itself, so a later call is judged against what the session has already read: recipients or paths taken from untrusted content, secrets leaving in any encoding, effects after injected text. Cheap structural checks run on every call, and the expensive scan can be deferred on read-only calls.
2. **Verified policy-update harness** (`src/agent_security_gate/policy_update.py`). Labelled false negatives become new block rules only if they pass a benign regression check. Rules only narrow policy, every change is versioned and can be rolled back, and anything that would relax policy is queued for a human.

How a tool call flows and how the harness works: **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**. What was measured and what was not claimed: **[docs/EVALUATION.md](docs/EVALUATION.md)**.

## Quick start

```bash
make test        # unit tests (no dependencies beyond Python 3.10+)
make demo        # 3 calls through the gate: allow, injected deny, RBAC deny
make live-mock   # scripted hijackable agent in a real tool loop, with the gate trace
make ideas       # idea 1 (sessions + red-team variants) and idea 2 (in-repo tiers)
make cross       # idea 2 on external data: train on datasets, test on separate benchmarks
```

All other targets: `make help`. Metrics go to `results/offline/` and `results/llm/`; logs go to `logs/` (git-ignored). The Makefile sets `PYTHONPATH=src`.

## Layout

| Path | What is there |
|---|---|
| `src/agent_security_gate/` | The system under test: `tcb`, `reference_monitor`, `roles`, `policy`, `detectors`, `session` (idea 1), `policy_update` (idea 2), `learning` (older baseline learner) |
| `benchmarks/data/` | Datasets and adapters: `catalog.py` (45 incidents), `scenarios.py` (48 synthetic scenarios, easy/hard/held-out), `session_scenarios.py` and `session_variants.py` (multi-step sessions), `external_adapters.py`, `external/` (downloaded corpora) |
| `benchmarks/runners/` | Evaluations that need no LLM: `run_bench`, `run_ideas_bench`, `run_cross_dataset_bench`, `run_split_bench`, `run_external_bench` |
| `benchmarks/llm/` | Real agents behind the gate: `live_agent.py` (Claude or mock), `llm_eval.py` (Ollama) |
| `examples/demo.py` | Smallest end-to-end example |
| `tests/` | `test_gate.py`, `test_session_and_updates.py` (includes a regression guard over the red-team variants) |
| `docs/` | `ARCHITECTURE.md`, `EVALUATION.md`, `GLOSSARY.md`, `BACKGROUND.md` (problem, dataset design, metric definitions), `RESEARCH_SUMMARY.md` (earlier write-up) |
| `results/` | Committed metrics JSON |

## Status in one table

| Question | Result | Where |
|---|---|---|
| Stateless gate on the paper's 11 attacks | ASR 0% | `make bench` |
| Session gate, 13 sessions where the caller attaches no provenance | ASR 100% (stateless) to 0% | `make ideas` |
| Session gate, 42 red-team variants (tuned after a first pass) | ASR 97% to 15%; the 15% are declared gaps | `make ideas` |
| Verified learning, train on datasets, test on separate benchmarks | Small gains (A3S +1 to +11 pp, Lakera up to about +4 pp); FPR rose from 10% to 30% on a domain with no benign regression data | `make cross` |
| Verified learning, same-dataset split | Pooled TPR 68% to 82%, FPR to 13.7% | `make split` |

Not claimed: robustness to an adaptive attacker, results on a live agent, or any comparison against published systems (CaMeL, Fides, Progent, PCAS, APPA). The scenarios are written for this repo.

## Data

External corpora are downloaded by `benchmarks/data/download_external.sh` and prepared by `prepare_hard_sets.py`.

| Suite | Source | Used as |
|---|---|---|
| `internal` | `scenarios.py` | synthetic baseline |
| `hendar` | [Hendar](https://huggingface.co/datasets/h0000w/hendar-agentic-ai-dataset) | train dataset (prompt-injection config only) |
| `coding_agent` | [rogue-security](https://huggingface.co/datasets/rogue-security/coding-agent-security-benchmark) | train dataset (has benign rows) |
| `lakera_l2` | [Lakera B3](https://huggingface.co/datasets/Lakera/b3-agent-security-benchmark-weak) | test benchmark |
| `injecagent_hard` | [InjecAgent](https://github.com/uiuc-kang-lab/InjecAgent) | test benchmark |
| `a3s_hard` | [A3S-Bench](https://huggingface.co/datasets/inclusionAI/A3S-Bench) | test benchmark |
| `agentharm_toolish` | [AgentHarm](https://huggingface.co/datasets/ai-safety-institute/AgentHarm) | test benchmark |

Terms (TCB, ASR, IFC, ...): `docs/GLOSSARY.md`. Secrets: copy `.env.example` to `.env` (git-ignored); needed only for the live-Claude runs.
