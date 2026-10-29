# Evaluation: what is measured, what is claimed, what is not

All numbers are from this repo's runners (`make ...`). Metric files are in `results/offline/`. Definitions of ASR, TPR, FPR are in `GLOSSARY.md`.

## 1. Idea 1: session-aware gating (`make ideas`, part A / A2)

Sessions are multi-step. The attack payload arrives inside a tool output, and the harmful call comes later **with no provenance attached by the caller**.

| Set | Stateless | Caller labels last output | Session | Session + adaptive |
|---|---|---|---|---|
| 13 hand-written sessions (7 attack steps) | ASR 100% | 71% | **0%** | **0%** |
| 42 red-team variants (34 attack steps) | 97% | n/a | **15%** | **15%** |
| False-block rate (benign steps) | 0% | 4% | 0–4% | 0–4% |

- Adaptive mode deferred 4 of 16 injection scans with no change in outcome.
- **What the variants are.** After the first 13 sessions I wrote 42 variants that change only how the tainted value is written (case, display name, plus-tag, URL-encoding, Windows paths, base64/hex/reversed/spaced secrets, zero-width and homoglyph injection). The first pass exposed 9 real misses. I fixed those, and the table is the result **after** the fixes. So the variants are tuned against, not blind.
- **Residual 15% (5 of 34), declared as `known_gap` in `session_variants.py`:** paraphrased injection, polite injection, "partner at example dot com", ROT13 secret, a leak of fewer than 10 secret characters. Substring and identifier matching cannot close these. They need information-flow tracking through the model's output.
- **One real cost:** a benign page that quotes injection phrases (`B3_security_blog`) quarantines the effect that follows it.

Not evidence of: robustness against an adaptive attacker, real agent traces, or other tool sets. The scenarios are authored for this repo.

## 2. Idea 2: policy learning

### 2a. Train on datasets, test on separate benchmarks (`make cross`)

Learning sees only the TRAIN suites. Test suites are never read during learning.

- **P1.** Train = `internal` + `hendar` + `coding_agent`. Test = `lakera_l2`, `injecagent_hard`, `a3s_hard`, `agentharm_toolish`.
- **P2.** Leave-one-suite-out over all seven suites.

| Test suite | None | Snippet | Verified (P1) | Verified (P2, LOSO) |
|---|---|---|---|---|
| lakera_l2 | 0.5% | 0.5% | 0.5% | 4.3% |
| injecagent_hard | 100% | 100% | 100% | 100% |
| a3s_hard | 50.0% | 50.0% | 50.7% | 61.3% |
| agentharm_toolish | 97.9% | 97.9% | 97.9% | 97.9% |
| coding_agent (TPR / FPR) | 32.7% / 10% | 32.7% / 12% | n/a | 42.6% / **30%** |

(TPR = share of attacks blocked.)

**Reading:** the high rows (InjecAgent, AgentHarm) are already at 98–100% from the structural checks (RBAC, network allowlist), which need no learning. The gate is weak on pure-text attacks (Lakera, half of A3S). Rules learned from other datasets close very little of that gap, and on a domain with no benign data in the regression corpus (`coding_agent`), false positives rise from 10% to 30%. So the learning harness is mechanically sound, but **cross-dataset gains are small and carry false-positive risk**.

### 2b. Within-pool grouped split (`make split`, 70/30, 5 salts)

Train and test come from the same datasets, split by payload group.

| | None | Snippet | Verified |
|---|---|---|---|
| Pooled TPR | 68.0% | 72.8% | **81.9%** |
| Pooled FPR (182 benign steps) | n/a | 8.8% | 13.7% |
| lakera_l2 TPR | 0.6% | 19.6% | 52.9% |
| a3s_hard TPR | 50.0% | 58.1% | 73.9% |

The same learner is much stronger within a dataset than across datasets: it learns each dataset's phrasing. The FPR increase is the price.

### 2c. In-repo tiers (`make bench`, `make ideas` part B)

Train easy and hard, test held-out. Held-out ASR goes from 15% to 8% with verified learning, from **one accepted rule** that happens to be a distinctive token also present in the held-out case. Treat as a single data point.

## 3. Measurement problems found and fixed

- `coding_agent` adapter: the label chose the role (attack gets the limited `researcher` role) and whether the text was marked untrusted. The gate could "predict" labels from this. **Fixed:** label-neutral (role chosen by tool, every row EXTERNAL). The coding-agent TPR dropped from about 71% to about 33% as a result.
- `hendar` adapter: for non-injection configs the label chose the tool (deny becomes `shell_exec`, allow becomes `http_fetch`), so RBAC predicted the label. **Fixed:** default is now the prompt-injection config only (`pi_only=True`).
- `send_email` recipients were parsed as hostnames, so every benign email was blocked. **Fixed** in `detectors.py`.
- The external suites are text datasets mapped to tool calls by adapters, and Lakera, A3S, InjecAgent and AgentHarm contain only attacks. FPR there is unmeasurable; FPR is reported only where benign rows exist (`internal`, `coding_agent`).

## 4. A learned lexical scorer was tried and removed

A frozen word/bigram log-odds scorer trained on other suites looked strong (Lakera 0.5% to 48.6%, A3S 50% to 86.5% leave-one-out). It was an artifact. On the held-out domain with benign rows its AUC was 0.485 (chance), because too little benign text was available to set a threshold, so it flagged nearly everything (FPR 77%). It is not part of the repo. A usable version needs benign corpora from many domains.

## 5. What would make idea 2 strong

1. Benign corpora per domain (the regression check and any learned detector depend on them).
2. Features beyond lexical rules for pure-text attacks (the paper's instruction/data separation problem).
3. An adaptive attacker and a shared benchmark (AgentDojo, TAMAS, ACIArena) with a live agent.
