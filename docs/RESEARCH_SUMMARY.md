# Agent Security Gate — Full Research Summary

Consolidated summary of architecture diagrams, dataset design, metrics,
observations, novelty vs arXiv:2605.18991, and next steps.

> **Earlier write-up** (written before the session gate and verified learning, and before the adapter label-leaks were fixed). For current design and numbers see `ARCHITECTURE.md` and `EVALUATION.md`.

---

## 1. Problem & research question

Agentic systems fail when security is left to the model alone. Incidents
(EchoLeak, SpAIware, Claude DNS exfil, Devin, AgentFlayer, Amp, Operator,
ClickFix, …) violate least privilege, complete mediation, TCB integrity,
instruction/data separation, and IFC.

**Research question:** Can a system-level security architecture prevent
unauthorized actions and data flows even when the agent is successfully
manipulated?

---

## 2. Diagram — paper security architecture

```
Untrusted System (LLM + agent)
        │  request
        ▼
 Security Boundary
        │
        ▼
 Reference Monitor  ←→  Security Policy
        │
        ▼
       TCB  → allow / deny (+ IFC on response)
```


| Principle                     | Meaning                            | In this prototype                  |
| ----------------------------- | ---------------------------------- | ---------------------------------- |
| Complete mediation            | Every tool request checked         | `SecurityTCB.invoke` only path     |
| Least privilege               | Min caps for current task          | Task-scoped RBAC                   |
| TCB tamper resistance         | Trusted core not attacker-writable | No EXTERNAL→memory; no self-config |
| Instruction / data separation | Untrusted text ≠ instructions      | `TrustLevel.EXTERNAL` + heuristics |
| IFC                           | Control long-range data flow       | DNS/secret/egress/PII sinks (lite) |


Paper stance: model is untrusted; LLM-as-monitor is rejected as primary TCB.

---

## 3. Diagram — prototype runtime path

```
Agent/bench
  → begin_task(principal, task) → role + capabilities
  → SecurityTCB.invoke(tool, args, data_channel, trust)
  → ReferenceMonitor.check
       · RBAC
       · network / DNS
       · secrets in args
       · sensitive paths
       · TCB invariants (memory, config, bind, clipboard, MCP, A2A, …)
       · PI patterns in EXTERNAL data
  → allow? → tool  |  deny + audit
```

Learning (eval harness only): labeled FN → absorb host/pattern → re-score.
Teacher = ground truth, not an LLM inside the TCB.

Typical: mediation **100%**, monitor **≪1 ms**, privilege reduction **~63%**.

---

## 4. Dataset & benchmark


| Collection           | Where                                            | What                                           |
| -------------------- | ------------------------------------------------ | ---------------------------------------------- |
| Historical catalog   | `benchmarks/catalog.py` → `results/catalog.json` | **45** cases P01–P11 + O12–O42 + E43–E45       |
| Executable benchmark | `benchmarks/scenarios.py`                        | **32** synthetic tool traces + `expect_block`  |
| Novel / held_out     | `difficulty=held_out`                            | Emerging + paraphrased PI; **no train absorb** |


Threat categories: **A** PI/hijack · **B** exfil/privacy · **C** unauthorized tools ·
**D** identity/privilege · **E** memory/destructive/cascade.

Harness:

```text
policy = baseline
for tier in easy → hard → held_out:
  score → (if easy|hard: absorb FNs) → re-score
```

Gate code frozen; difficulty lives in data.

---

## 5. Metrics


| Metric              | Better | Meaning                    |
| ------------------- | ------ | -------------------------- |
| ASR                 | ↓      | Attack steps allowed       |
| Containment / TPR   | ↑      | Attack steps blocked       |
| FPR / false-block   | ↓      | Benign wrongly blocked     |
| Utility retention   | ↑      | Benign still allowed       |
| Complete mediation  | =1.0   | Every call hit the monitor |
| Privilege reduction | ↑      | 1 − granted/all tools      |
| F1                  | ↑      | Precision/recall balance   |
| Latency p50/p95     | ↓      | Monitor overhead           |


### Latest results


| Tier     | TPR before→after | ASR before→after | FPR   | Note                              |
| -------- | ---------------- | ---------------- | ----- | --------------------------------- |
| easy     | 100%→100%        | **0%→0%**        | 0%    | Paper P01–P11 all contained       |
| hard     | 91%→100%         | **9%→0%**        | 100%* | ADV01 learned; blog FP remains    |
| held_out | 83%→83%          | **17%→17%**      | 0%    | ADV02 PROTOCOL_MIRAGE still slips |


1/1 benign EXTERNAL security blog quoting classic PI phrases.

---

## 6. What worked vs what did not

**Worked (structural):** DNS allowlist + encoded labels; RBAC; immutable config /
no EXTERNAL memory; sensitive paths; clipboard/ANSI; public bind; BCC; A2A
unauth; paper set ASR 0%.

**Did not (semantic / trade-off):** Novel PI on allowlisted HTTP; entity
obfuscation until absorbed; held-out PROTOCOL_MIRAGE; educational EXTERNAL
quotes → FP; snippet learning does not generalize.

---

## 7. Novelty vs the paper


| From the paper (instantiated)                                | Your addition (operational)                          |
| ------------------------------------------------------------ | ---------------------------------------------------- |
| Untrusted model; TCB; least privilege; IFC; instr/data split | Runnable reference-monitor prototype                 |
| 11 attacks mapped to principles                              | 45-case catalog + 32 executable scenarios            |
| No shipped benchmark/metrics                                 | Tiered harness + ASR/containment/utility/mediation   |
| Warns against LLM-as-TCB                                     | Labeled FN absorb; held_out shows non-generalization |


**Direction:** Dataset + benchmark + architecture metrics are the right vehicle.
Novelty is **operationalizing and measuring** the paper’s stance. Next gains:
IFC labels, verifiable task→policy, controlled endorsement — not more regexes
or LLM-in-monitor.

---

## 8. Recommended next steps

1. Provenance / IFC labels on tool I/O
2. Task → formal checkable policy
3. Endorsement path for EXTERNAL data (utility vs PI)
4. Keep held-out ASR + utility as KPIs

---

## 9. Key acronyms

TCB Trusted Computing Base · RBAC Role-Based Access Control · IFC Information-Flow
Control · ASR Attack Success Rate · TPR/FPR True/False Positive Rate · PI Prompt
Injection · MCP Model Context Protocol · A2A Agent-to-Agent · LLM Large Language
Model (untrusted here).

---

## Entrypoints

`README.md` · `benchmarks/catalog.py` · `benchmarks/scenarios.py` ·
`benchmarks/run_bench.py` · `src/agent_security_gate/` · `results/metrics.json`