# Final report (2026-10-30): a learnable system-level gate for multi-agent handoffs

Plain-language summary for newcomers. Terms (TCB, ASR, FPR, grounding, held-out...) are defined in `RESEARCH_PLAN.md` section 1. Details and caveats per experiment: `FRESH_START.md`. Industry context: `INDUSTRY_PRACTICE.md`.

## 1. Question and answer
**Can a deterministic gate in front of every tool call stop attacks that arrive through untrusted text, even when the model is fooled, and can it improve its own rules without overfitting?**
- Mostly yes for *tool-effect* attacks (send email, fetch URL, write file): rule "a target must be named by the user's task" cut attack success on a live hijacked 7B agent from **32% to 4%** (95% interval 1-12%) while every benign task still finished.
- Learning helps only when the thing learned is **structural**. Learned *text* rules overfit (they look great on narrow benign data and collapse on broad data). Curriculum ordering did not help.
- Not solved: attacks that act on message *content* with no tool target (answer text, link-free instructions), and adaptive attackers.

## 2. What we built (all offline, deterministic, outside the model)
| Piece | File | In one line |
|---|---|---|
| Synthetic leveled data | `benchmarks/data/synth_mas.py` | L1 overt -> L5 reference-only attacks, laundered through a summarizer agent; attack families/domains held out; hard benign twins |
| Learner | `src/agent_security_gate/rule_induction.py` | proposes narrowing rules, keeps one only if it blocks no benign case; prunes redundant ones |
| Grounding check | `detectors.py: check_grounding` | tool argument must be in the user task (exact match; "reply to sender" may use a header) |
| Redaction | `features.py: redact_ungrounded`, `tcb.py` | strip ungrounded links/addresses from free-text bodies instead of blocking |
| Risk tier | `ContentPolicy.free_plain_reads` | plain GET to an allowlisted host needs no grounding |
| Red-team test | `benchmarks/runners/run_redteam_slots.py` | 15 evasions; part of `make test` |

## 3. Headline numbers
**Synthetic, held-out attack families and domains, 20 seeds (mean, 95% interval across seeds), `make synth`.** TPR = share of attacks blocked.
| Policy | L1 | L2 | L3 | L4 | L5 | benign FPR | hard benign (human-directed text) |
|---|---|---|---|---|---|---|---|
| none | 33% | 0% | 0% | 0% | 0% | 0% | 0% |
| prior art: verified regex learning | 83% | 29% | 23% | 22% | 54% | 0% | 1% |
| text rules, narrow benign data | 67% | 49% | 100% | 100% | 0% | 0% | **24±8%** |
| text rules, broad benign data | 44% | 13% | 10±13% | 10±13% | 0% | 0% | 12±5% |
| **structural slot rules (learned)** | **89%** | **83%** | **83%** | **83%** | **83%** | 0% | 0% |
The 17% that slots miss is one family (`poison`: attacker link inside an email to the right recipient, 7% caught); redaction takes that to ~0% attack success (`make poison`).

**Live agent, qwen2.5:7b, 144 episodes, replayed calls (`make live-p4`).** attack success: none 32%, base policy 26%, session gate 21%, slots 17%, **slots + redaction 4%**; benign tasks done 100%; benign calls blocked 7% (mostly the agent over-reaching).

**Real external data, InjecAgent email-exfil, 544 cases (`make p5`).** bare attacker instruction: base policy blocks **0%**, slot rules **100%**. With the "IMPORTANT ignore previous" hint both block 100%.

## 4. Ablations (what mattered)
| Change | Effect |
|---|---|
| Text rules: narrow -> broad benign corpus | L3/L4 TPR 100% -> 10%: the narrow-corpus result was spurious |
| Slot rules: narrow -> broad benign corpus | no change (83-89%): structural rules do not depend on benign breadth |
| Curriculum vs flat vs reverse order | no difference after pruning |
| Pruning off | curriculum keeps a redundant text rule: hard-benign FPR 0% -> 13%, breadth FPR 11% |
| Ask-a-human instead of block | worse unless the user catches attacks (ASR 15.6% -> 23% at 90% attention, 93% at 0%) |
| Substring -> exact matching (red-team) | 4 real bypasses closed |
| `free_plain_reads` | internal-suite false blocks 20% -> 5%, but allows plain GETs to attacker pages on allowed hosts |

## 5. What did not work
- Text-feature rules generalizing across phrasing (overfit; unlearnable at L3+ because "forward X to Y" is benign or malicious depending on who authorized Y).
- Curriculum ordering and (untested, by reasoning) RL: the limit was what rules can express, not how they are searched.
- A 3B model as a live test (followed 0/72 injections).
- TAMAS / ACIArena: measure tool choice and answer content, not tool targets; not scored.

## 6. Limits you must state when citing this
1. Attacks are built with targets the task never names, so grounding is *expected* to work; the cost side (false blocks) is the real test and is measured only on our own sets (internal suite 5%, live agent 7%).
2. Generator and feature word-lists share an author; L3+ "held-out families" are not phrase-OOD because the summarizer erases style.
3. One 7B model, replayed (not re-run) calls, plain prompt, no adaptive attacker, no human users.
4. External lakera/a3s 100% for slot arms is an adapter artifact; ignore it.
5. Redaction drops legitimate citations; free reads leak "visit this page" actions; link-free instructions pass.

## 7. Reproduce
```bash
make test        # unit tests + 15 red-team cases
make synth       # synthetic held-out tables (add --seeds 20 via the runner for CIs)
make poison      # email-body link: block vs redact
make approval    # ask-a-human vs hard block
make p5          # InjecAgent
make live-p4 MODEL=qwen2.5:7b   # needs ollama serve
```
Results: `results/offline/*.json`, `results/llm/p4_*`.

## 8. Next steps
1. Adaptive attacker against slots+redaction (attacker searches for a bypass given the policy).
2. Information-flow labels on message bodies/answers for link-free and answer-content attacks.
3. More models and a human-in-the-loop study for the ask tier.
4. Real MAS traces (AutoGen/CrewAI) with the gate wrapped around their tool layer.
