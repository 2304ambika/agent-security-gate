# Agent Security Gate

Feasibility prototype for a **system-level** security architecture around agentic AI, grounded in [arXiv:2605.18991](https://arxiv.org/abs/2605.18991) (*Agent Security is a Systems Problem*).

**Research question:** Can a system-level security architecture prevent unauthorized actions and data flows even when the agent itself is successfully manipulated by adversarial input?

---

## Problem noticed

Agentic systems fail in ways that model-only defenses do not fix:

1. **The model is an unreliable component.** Prompt injection, tool misuse, and goal hijacking keep succeeding even after alignment-style mitigations. Treating “make the LLM refuse better” as the primary control is insufficient.
2. **Security principles are missing or incomplete at the system boundary.** Real incidents (Copilot EchoLeak, ChatGPT SpAIware, Claude DNS exfil, Devin exposure, Cursor AgentFlayer, Amp config tampering, Operator/ClickFix, and others) map to failures of least privilege, complete mediation, TCB tamper resistance, instruction/data separation, and information-flow control.
3. **Policies are dynamic and task-specific.** Unlike a fixed app install, agents change goals mid-trajectory, so over-broad tool access and mutable “security config” become attack surfaces.
4. **Evaluation often measures the wrong thing.** Refusing a malicious prompt is not enough if the same objective still succeeds via shell, DNS, browser, MCP, memory, or another agent.

Without an external enforcement layer, a compromised or manipulated agent can still call tools, leak secrets, expose ports, poison memory, or cross trust domains.

---

## Solution proposed

Treat the **LLM as untrusted**. Put a small **Trusted Computing Base (TCB)** in front of every tool:

| Piece | Role |
| --- | --- |
| **Security policy** | Declarative allow/deny rules (network, content, sensitive paths, tool→capability map) |
| **Task-scoped RBAC** | Least privilege derived from the current task/role |
| **Reference monitor** | Deterministic approve/deny on **every** tool request (complete mediation) |
| **Detectors / TCB invariants** | DNS exfil, prompt-injection cues in EXTERNAL data, secrets in args, memory/config immutability, public bind, clipboard/ANSI, MCP/A2A trust, destructive deletes |
| **Learning harness** | On labeled false negatives, promote hosts/patterns into policy; re-score (eval loop, not an LLM inside the TCB) |

Agents never hold raw tool handles. The only path is:

```text
task → identity/role → SecurityTCB.invoke → reference monitor → (allow?) → tool
```

This implements the paper’s stance: enforce invariants **outside** the model—instruction/data separation, verifiable least privilege, and information-flow control—so unauthorized actions fail even if the model “agrees” with the attacker.

---

## What is included in the dataset

Three collections (per the research brief), not a flat list of incident names:

### 1. Historical incident catalog (`benchmarks/catalog.py` → `results/catalog.json`)

**45 cases** with a shared schema (`case_id`, evidence type, entry vector, asset at risk, attack goal, expected control, severity, reproducibility, collection):

| Range | Source | Count (approx.) |
| --- | --- | --- |
| **P01–P11** | Paper’s 11 representative attacks | 11 |
| **O12–O42** | OWASP Agentic Security–style expansions (coding agents, MCP/supply chain, identity/A2A, memory/destructive classes) | 31 |
| **E43–E45** | Emerging / developing reports (e.g. CERT-In–style live egress, unintended browser submits, sandbox escape probes) | 3 |

Evidence labels distinguish confirmed incident, reported vulnerability, research demonstration, synthetic scenario, and developing report.

### 2. Reproducible attack benchmark (`benchmarks/scenarios.py`)

**32 executable synthetic scenarios** (tool-call traces with ground-truth `expect_block`). These exercise the gate in isolation—**no live exploits** against production systems.

Threat categories covered:

- **A.** Prompt injection / goal hijacking  
- **B.** Data exfiltration / privacy  
- **C.** Unauthorized tool use / code execution  
- **D.** Identity, privilege, trust-boundary failures  
- **E.** Memory poisoning, destructive actions, cascading / A2A failures  

### 3. Difficulty tiers (same gate code; harder *data*)

| Tier | Contents | Learning |
| --- | --- | --- |
| **easy** | Paper P01–P11 canonical patterns + benign utility | Train on FNs (usually none) |
| **hard** | OWASP-mapped traces + novel phrasing + FPR stress (security blog) | Train on FNs |
| **held_out** | Novel PI / memory / A2A + emerging E43–E45 | **Eval only** (no absorb) |

Harness loop:

```text
policy = baseline
for tier in easy → hard → held_out:
  score(tier)                   # before
  if tier in {easy, hard}:
    absorb labeled false negatives
  score(tier)                   # after  (policy warm-starts to next tier)
```

---

## Metrics

Architecture-oriented metrics (not “did the model refuse?”):

| Metric | Direction | Meaning |
| --- | --- | --- |
| **ASR** (attack success rate) | ↓ better | Share of attack steps that were **allowed** |
| **Containment / TPR** | ↑ better | Share of attack steps **blocked** |
| **False-block / FPR** | ↓ better | Share of benign steps wrongly blocked |
| **Utility retention** | ↑ better | Share of benign steps still allowed |
| **Complete mediation** | = 1.0 | Every tool call hit the reference monitor |
| **Policy enforcement coverage** | ↑ better | Same mediation invariant for security-relevant actions |
| **Privilege reduction** | ↑ better | \(1 - \text{avg granted tools} / \text{all tools}\) under task RBAC |
| **F1 / accuracy** | ↑ better | Step-level allow/deny quality on the labeled set |
| **Latency (p50/p95)** | ↓ better | Monitor overhead only (not model time) |

Latest run (`python3 benchmarks/run_bench.py` → `results/metrics.json`):

| Tier | TPR before→after | ASR before→after | FPR | Utility | FN before→after |
| --- | --- | --- | --- | --- | --- |
| easy | 100%→100% | **0%→0%** | 0% | 100% | 0→0 |
| hard | 91%→100% | **9%→0%** | 100%* | 0%* | 1→0 |
| held_out | 83%→83% | **17%→17%** | 0% | 100% | 1→1 |

\*Hard FPR/utility reflect a single benign EXTERNAL security-blog case that quotes classic injection phrases (1/1).

---

## Observation

1. **Complete mediation is achievable and cheap.** Every tool call is gated; monitor latency stays in the sub-millisecond range—negligible vs LLM time.
2. **Paper patterns (easy) are containable with deterministic controls.** P01–P11-style traces (EchoLeak PI, SpAIware memory write, DNS exfil, public bind, `.env`, Jira→secrets, config tamper, token exfil, ANSI terminal, Operator PII submit, ClickFix clipboard) all blocked → **ASR 0%** without learning.
3. **Structural controls transfer better than string heuristics.** DNS allowlists, encoded-label checks, RBAC, immutable config, EXTERNAL→memory deny, and sensitive-path rules stop many OWASP-mapped hard cases even when wording changes.
4. **Semantic / novel input on allowlisted destinations remains the gap.** Hard FN `ADV01` (novel phrasing) is fixed by labeled absorb; held-out `ADV02` (`PROTOCOL_MIRAGE`) still succeeds → **ASR 17%**—snippet learning memorizes, it does not generalize.
5. **Utility vs strict EXTERNAL scanning is a real trade-off.** Quoting attack phrases in a benign security article triggers false blocks when trust is EXTERNAL.
6. **Learning helps only with a trusted teacher.** The harness uses ground-truth labels (or would use a human/offline judge in production). An LLM inside the TCB would reintroduce the paper’s “probabilistic reference monitor” failure mode.

---

## Conclusion

The prototype supports the paper’s thesis for this benchmark: **security must be enforced at the system boundary**, not trusted to the model.

- When attacks map to **tool misuse, egress, privilege, memory/config integrity, or IFC-visible secrets**, the reference monitor can drive **ASR to zero** on the paper’s canonical set and recover hard-tier misses via policy absorb.
- Residual risk is concentrated in **instruction-like content that does not match detectors** and in **over-blocking educational EXTERNAL text**—problems of detector generality and policy nuance, not of missing mediation.
- Therefore the right research/engineering focus is: keep the TCB deterministic and complete; improve **verifiable policy generation**, **instruction/data separation**, and **IFC**, while treating held-out ASR and false-block rate as first-class metrics alongside containment.

---

## Glossary (acronyms & terms)

| Term | Full form / meaning |
| --- | --- |
| **TCB** | Trusted Computing Base — code/data that must stay correct even under attack (here: policy + reference monitor + invariants) |
| **Reference monitor** | Component that checks every request against the security policy (approve or deny) |
| **RBAC** | Role-Based Access Control — permissions granted by role/task (e.g. researcher vs ops) |
| **IFC** | Information-Flow Control — tracking/restricting where sensitive data may flow |
| **LLM** | Large Language Model — the AI model driving the agent (treated as untrusted) |
| **PI** | Prompt Injection — malicious instructions in data (email, web, files) that steer the agent |
| **ASR** | Attack Success Rate — share of attack steps that were **allowed** (lower is better) |
| **TPR** | True Positive Rate — share of attacks correctly **blocked** (also called recall / containment here) |
| **FPR** | False Positive Rate — share of benign steps wrongly **blocked** (false-block rate) |
| **TP / FP / TN / FN** | True Positive / False Positive / True Negative / False Negative — confusion-matrix counts for allow/deny |
| **F1** | Harmonic mean of precision and recall — balances “when we block, are we right?” and “did we catch attacks?” |
| **MCP** | Model Context Protocol — standard for connecting agents to external tools/servers |
| **A2A** | Agent-to-Agent — one agent messaging or steering another |
| **DNS** | Domain Name System — name→IP lookup; abused to sneak data out in query names |
| **PII** | Personally Identifiable Information — e.g. email, SSN, passport-like data |
| **DLP** | Data Loss Prevention — controls that stop sensitive data leaving authorized destinations |
| **RCE** | Remote Code Execution — attacker causes code to run on the host |
| **XSS** | Cross-Site Scripting — injecting script into a web page viewed by a victim |
| **ANSI (escapes)** | Control sequences in terminal output that can manipulate display/clipboard |
| **CVE** | Common Vulnerabilities and Exposures — public vulnerability ID scheme |
| **OWASP** | Open Worldwide Application Security Project — community that tracks web/agent security risks |
| **CERT-In** | Indian Computer Emergency Response Team — India’s national cyber incident agency |
| **CRM** | Customer Relationship Management — business system holding customer records |
| **API** | Application Programming Interface — programmatic service endpoint (often needs keys) |
| **HTTP / HTTPS** | Hypertext Transfer Protocol (Secure) — web request protocols |
| **p50 / p95** | 50th / 95th percentile — latency points (median and high-tail) |
| **EXTERNAL** | Trust level for untrusted channels (web, tickets, tool output) — treated as data, not instructions |

---

## Run

```bash
python3 demo.py
python3 benchmarks/run_bench.py   # → results/metrics.json, results/catalog.json
python3 tests/test_gate.py
```

### Layout

| Path | Purpose |
| --- | --- |
| `src/agent_security_gate/` | TCB, policy, roles, detectors, reference monitor, learning |
| `benchmarks/catalog.py` | 45-case historical/schema catalog |
| `benchmarks/scenarios.py` | Executable synthetic scenarios by difficulty |
| `benchmarks/run_bench.py` | Train→re-eval harness + architecture metrics |
| `results/` | Latest metrics and catalog export |
