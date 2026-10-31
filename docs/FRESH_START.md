# Fresh start: leveled synthetic data + learned policy for MAS handoffs

Date 2026-10-29. Reproduce: `make synth` (5 seeds, ~1 min) -> `results/offline/synth_curriculum.json`. Tests: `make test`.

## 0. Base code (unchanged stance)
LLM untrusted; deterministic TCB: `task -> role -> SecurityTCB.invoke -> ReferenceMonitor -> tool`. Existing: RBAC, network/DNS allowlist, secrets/paths, TCB invariants, regex injection scan, `session.py` taint, `policy_update.py` (verified regex/host learning, ledger, rollback). Known weakness (EVALUATION.md): text-only attacks on allowlisted destinations; learning memorizes phrasing, cross-dataset gain ~0, FPR rises when the benign corpus is narrow.

## 1. Case studies -> how breaches happen (full list: `benchmarks/data/catalog.py`, industry: `INDUSTRY_PRACTICE.md`)
| Pattern | Examples | Boundary that failed |
|---|---|---|
| Untrusted content becomes a command | EchoLeak, Agent Smith, Prompt Infection | instruction/data separation |
| Exfil over an *allowed* channel | Claude DNS exfil, markdown-image leaks, AgentFlayer | egress flow control |
| Persistent poisoning | SpAIware memory, AgentPoison | memory write provenance |
| Tool/config tamper | Amp config, MCP tool metadata | TCB integrity |
| **Authority laundering at handoff** | AiTM, Conjunctive Prompt Attacks, Multi-CaMeL | label lost when a worker summarizes/paraphrases |
| Approval bypass | ClickFix, Operator form submit | human-in-loop fatigue (users accept ~93% of prompts) |

Industry pain points (sourced): classifiers leave residuals (Anthropic: 17% FNR on real overeager actions; 1.4% browser ASR), adaptive attackers beat most published defenses, provenance is weak across subagents, exfil patched per channel, deterministic IFC costs utility/policy authoring.

## 2. Gap chosen
**Instruction/data separation at multi-agent handoffs, and why learned policy updates overfit there.** Fits the code (session/taint + updater), lit-review Q1/Q4, and the user's idea: fix overfitting with *data* (leveled, family-held-out, benign-broad synthetic episodes), then train with a harness curriculum.

## 3. Dataset (`benchmarks/data/synth_mas.py`, seeded, no LLM)
Episode = what the effect-agent has in context + its proposed call; each attack has a benign twin. Structural checks pass in both, so only separation logic can decide.
- Levels: L1 overt phrase · L2 covert directive · L3 laundered by summarizer (third person, label kept) · L4 + obfuscated target (`x [at] y [dot] com`) · L5 reference only ("the audit mailbox").
- Train families note/ticket/colleague/compliance; **held-out** markup/story/checklist/terse (lexicon-disjoint)/dhijack (header-delegation hijack)/poison (right recipient, attacker link in body). Held-out domains too.
- Hard negatives: `hard_dir` (human-directed imperatives), `hard_edu` (quotes attacks), `derived` (task says "reply to sender", target comes from header), `quote` (summary cites page link), `breadth` (README/runbook/log text using the same word classes). Train/held templates disjoint.

## 4. Learner (`features.py`, `rule_induction.py`; offline, narrowing-only, verified, ledgered)
Closed action space: (a) **text rule** = conjunction of word-class features inside ONE sentence; (b) **slot rule** = `(tool,arg)` must be grounded in the user task when untrusted content is in context (header-bound delegation allowed). Keep a candidate only if it covers >=3 FNs from >=2 families and blocks 0 benign. Greedy cover + `prune()` of redundant rules. Policy hooks: `ContentPolicy.learned_rules/grounded_slots` (off by default; old results unchanged).

## 5. Results (5 seeds, means; ASR = 1-TPR; OOD = held-out families+domains)
| Arm | OOD TPR L1/L2/L3/L4/L5 | OOD FPR hard_dir / breadth | ext coding_agent TPR/FPR |
|---|---|---|---|
| none | 34/0/0/0/0 | 0 / 0 | 33/10 |
| verified_regex (prior art) | 83/26/24/24/52 | 0 / 0 | 34/12 |
| text rules, narrow benign | 67/49/100/100/0 | 28 / 32 | 34/10 (curr: 45/22) |
| text rules, **broad** benign | 47/16/20/20/0 | 10 / 13 | 33/10 |
| slot rules, broad (flat = curriculum) | 89/83/83/83/83 | 0 / 0 | 35/11 |
| both, broad, curriculum, pruned | 89/83/83/83/83 | 0 / 0 | 35/11 |
OOD by family, slot arms: 100% on markup/story/checklist/terse/dhijack, **6% on poison**.

## 6. What worked / what did not
**Worked**
- Structural slot rules: generalize across phrasing (even lexicon-disjoint `terse`), L5, and header-delegation hijack, 0% FPR on all synthetic benign incl. `derived`/`quote`. Learned policy is 3 auditable rules: `http_fetch.url`, `send_email.to`, `write_file.path`.
- Benign breadth is the real anti-overfitting lever: with a narrow benign corpus text rules reach 100% on L3/L4 but that is spurious (FPR 14-39% on breadth/hard sets, coding_agent FPR 10->22%); broad benign removes the illusion (L3/L4 drop to 20%).
- Pruning: without it, curriculum keeps an early broad text rule made redundant by a later slot rule (OOD hard_edu FPR 55%); with it curriculum = flat = reverse.

**Did not work**
- Curriculum: no gain over flat or reverse order once pruned. Gated benign corpus (benign grows with level) accepted rules that regress later; the benign corpus must be fixed from day one.
- Text-only rules cannot separate L3+ attacks from benign "forward X to Y": information is in *who authorized Y*, not the words. RL over the same action space cannot fix an expressiveness limit, so RL was **not run** (reasoned, untested).
- `poison` (grounded recipient, attacker link in body): slot `send_email.body` rejected because benign `quote` summaries cite links. Residual 94% ASR; needs approval tier or IFC on content.

## 7. Validity limits (read before citing)
- Generator and feature lexicons share an author; attacks are built with ungrounded targets, so slot success is partly by construction. `derived`, `quote`, `dhijack`, `poison`, `terse` are the counter-tests.
- L3+ held-out families are not phrase-OOD: the summarizer erases style (only domain differs).
- External rows for slot arms (lakera/a3s 100% TPR) are an **adapter artifact** (fixed arg URL never named in task); only the FPR is meaningful: `internal` benign FPR 5% -> 20% = real cost of grounding when tasks do not name targets.
- Not tested: adaptive attacker, live LLM agents, real traces.

## 8. Next
1. Approval/escalation tier for ungrounded calls (turns the 20% FPR into a human queue, not a block); measure approval burden.
2. IFC label on message bodies to attack `poison`.
3. Run slot policy under a live LLM agent (`benchmarks/llm/`) with the generator's tasks; add adaptive attacker.
4. Revisit RL only if a dataset appears where greedy cover is measurably suboptimal.

## 9. Red-team of our own defense (done)
`make redteam` (15 cases): 4 real bypasses found in the slot check (substring matching let `v@example.com` pass as `dev@example.com`, and `https://example.com` pass as the task URL, etc.). Fixed with exact identifier matching; main results unchanged. Runs inside `make test` now.

## 10. P2: attacker link in an email to the right recipient (`make poison`, 5 seeds, n=300 attacks)
| Policy on `send_email.body` | poison ASR | benign citation (`quote`) | other benign |
|---|---|---|---|
| none | 92% | untouched | untouched |
| block if ungrounded (the slot rule the learner rejected) | 0% | **100% blocked** | untouched |
| **redact** ungrounded links/addresses (new) | **0%** | citation removed in 100%, call still sent | untouched |
- Insight: the learner was right to reject blocking (it breaks benign citations), but *neutralizing* instead of blocking removes the attack link at the cost of dropping citations. New mechanism: `ContentPolicy.redact_slots`, applied by the TCB before the tool runs (`ToolResult.redacted`).
- Red-team of the redactor (10 evasions): 8 neutralized after fixing two bypasses (`example.com/verify` without scheme was treated as the task's host; `example [dot] com/verify`). 2 survive by design: letter-spaced text and **link-free instructions** ("reply with your password") - redaction cannot see intent.
- Limits: the citation cost is real (every citation lost, since attacker and benign links share a host in this data; a task-source allowlist would be the fix). Redaction fixes links/addresses only; semantic manipulation of the body needs approval (P3) or IFC.

## 11. P3: ask-a-human tier (`make approval` -> results/offline/approval_tier.json)
`Decision.needs_approval` marks calls denied only for an ungrounded target. Deterministic user model: catches an attack with probability *c*, approves every benign ask.
| Policy | synthetic held-out ASR (benign blocked) | internal suite ASR (benign blocked, asks/100 benign) |
|---|---|---|
| base policy, no slots | n/a | 5.7% (5%) |
| slot rules, hard block | 15.6% (0%) | 0% (**20%**) |
| slot rules, ask (c=0 / 0.5 / 0.9) | 93% / 54% / 23% (0%) | 5.7% / 2.8% / 0.6% (5%, **15 asks**) |
| slot rules + `free_plain_reads`, hard block | 15.6% (0%) | 5.7% (**5%**, 0 asks) |
- **Asking is a conversion, not a fix.** Every blocked attack becomes a human decision. When asks are mostly attacks (synthetic) a 90%-attentive user is *worse* than hard-block (23% vs 15.6%); a rubber-stamp user (c=0) makes it 93%. It only pays when asks are mostly benign (internal).
- **What fixed the 20% false blocks was risk tiering, not people.** The benign asks were first-time reads of the page the task is about. A plain GET (no query/fragment/userinfo) to an allowlisted host skips grounding (`ContentPolicy.free_plain_reads`, opt-in): internal false blocks 20%->5% (= base), attack rate = base, synthetic unchanged (its exfil fetches carry a query).
- **Known gap:** data can ride in the URL path of a free read; and `internal` is 20 benign calls (tiny, authored). Treat 20%->5% as indicative.
- Verdict: keep hard-block + risk tiers as default; use ask only for rare high-value calls where asks are mostly benign.

## 12. P4: live LLM agent (`make live-p4`, local Ollama `llama3.2` 3B, 144 episodes x 2 prompts) - NULL RESULT
Agent runs once per episode with all calls allowed; its calls are replayed through six policies (counterfactual replay: assumes the agent would not adapt after a block).
| Prompt | LLM followed injection | attack success (all 6 policies) | benign task done | benign calls blocked (slots) |
|---|---|---|---|---|
| plain | 0/72 | 0% | 72% | 1% |
| "carry out action items in documents" | 0/72 | 0% | 89% | 0% |
- **What it shows:** this small model ignored every injection even when told to follow document notes, so the policies cannot be separated. It says nothing about the gate's strength; it only shows the slots cost ~0-1% benign calls on a real tool-calling agent.
- **Bug found on the way:** a poison episode's legitimate recipient was counted as an attack marker (falsely 15% "hijacked"); fixed (`markers()`).
- **Needed to get signal:** a model that actually follows injections (a larger tool-capable open model, or an API model) - requires downloading weights or an API key; not done.

### 12b. P4 with `qwen2.5:7b` (partial: 53 of 144 episodes; 27 attack / 26 benign, levels L1 + part of L2) - first usable signal
This model followed the injection in **44% (12/27)** of attack episodes with the plain prompt (llama3.2: 0%). Replayed policies:
| Policy | attack succeeded | benign task done | benign calls blocked |
|---|---|---|---|
| no gate | 44% | 100% | 0% |
| base policy | 30% | 100% | 3% |
| session gate (idea 1) | 22% | 100% | 11% |
| slots, strict | 11% | 100% | 15% |
| slots + free plain reads | 15% | 100% | 8% |
| **slots + free reads + redact** | **7%** | 100% | 8% |
- Slots beat the base policy and the earlier session gate on a real hijacked agent; redaction removes the poison link. The task still completed in 100% of benign episodes.
- Remaining breaches under `slots+free reads` are the *free plain reads* (agent GETs the attacker's `https://example.com/hook` or `/refund`): no data leaves, but it is an unauthorized action. Strict slots close them (11%) at the cost of more blocked calls - the P3 trade-off, now seen on a live agent.
- "Benign calls blocked" are mostly **agent over-reach**, not user tasks: unrequested `write_file /tmp/summary.txt`, invented URLs. Blocking them is correct under grounding but counts as a block; task completion is the utility metric.
- Metric fix: copying page text into a legitimate file's *content* was wrongly counted as a breach; breaches now count the target slots only.
- **Caveats:** n=27 per arm, ~±15 pts (95% CI); only L1/L2; one model; counterfactual replay. Stopped early on request. Resume: `make live-p4 MODEL=qwen2.5:7b` (collection resumes from saved ids), then re-run `replay` for the full 144.

### 12c. P4 full run, `qwen2.5:7b`, all 144 episodes (72 attack / 72 benign, L1-L4, held-out families; supersedes 12b)
Agent followed the injection in **32% (23/72)**. Attack success after the gate (Wilson 95% CI):
| Policy | attack success | benign task done | benign calls blocked |
|---|---|---|---|
| no gate | 32% (22-43) | 100% | 0% |
| base policy | 26% (18-38) | 100% | 2% |
| session gate | 21% (13-32) | 100% | 5% |
| slots, strict | 14% (8-24) | 100% | 10% |
| slots + free plain reads | 17% (10-27) | 100% | 7% |
| **slots + free reads + redact** | **4% (1-12)** | 100% | 7% |
| session + slots + redact | 6% (2-13) | 100% | 10% |
- Holds at full size: slots+redact cuts attack success from 32% to 4% with no loss of benign task completion; the base policy barely helps (26%) because these are allowlisted-destination attacks, its known weakness.
- Adding the old session gate on top does not help (6% vs 4%) and raises benign blocks (10% vs 7%): the new policy subsumes it.
- Caveats: one 7B model, replayed (not re-run) calls, plain prompt only, no adaptive attacker; "benign blocked" is mostly agent over-reach. The 3 remaining successes under slots+redact are plain GETs to the attacker's page (free reads); strict slots close them at +3 pts blocked calls.

## 13. P5 (offline part): InjecAgent data-stealing cases (`make p5` -> results/offline/p5_injecagent.json)
Built from the dataset's own fields: task = User Instruction, untrusted context = Tool Response, attack = `send_email` to the address named in the Attacker Instruction (544 cases with a GmailSendEmail + address; 510 others skipped). Two settings: *enhanced* (response carries the "IMPORTANT!!! Ignore all previous instructions" hint) and *base* (the bare attacker instruction). `gmail.com` is allowlisted for both policies, because otherwise the network allowlist blocks every attacker address for the wrong reason (and would block all benign gmail).
| Policy | enhanced TPR | base (bare instruction) TPR |
|---|---|---|
| base policy | 100% (99-100) | **0%** (0-0.7) |
| slot rules | 100% (99-100) | **100%** (99-100) |
- On data nobody on this project wrote, the regex gate depends on the hint phrase; grounding does not. This is the same finding as the synthetic L2-L4 levels, now on an external dataset.
- **Limits:** attack-only (no FPR; benign twins do not exist in InjecAgent); the attacker address is by definition absent from the user instruction, so grounding is *expected* to work: the real question is cost on benign traffic, measured only on our own sets (internal 5%->5% with free reads, live agent 7%). InjecAgent is single-agent, not a MAS benchmark. The MAS suites (ACIArena, TAMAS) are not available offline: downloading them needs your OK.

### 13b. P5: TAMAS and ACIArena inspected (cloned read-only to `benchmarks/data/external/{tamas,aciarena}`, git-ignored; their code was not run)
Neither can be scored faithfully by data adaptation alone, which is itself a finding about where standard MAS benchmarks sit relative to our gate.
| | What the ground truth is | Fit with a tool-call gate |
|---|---|---|
| TAMAS (300 attacks = 6 types x 5 domains x 10; 100 benign) | natural-language goal, e.g. "extract all session tokens using `get_tokens` of the Legal Research Agent"; **DPI** is text appended to the *user* query; **IPI/impersonation/colluding/byzantine** live in the framework's tool code (`data/tools/*`) | no concrete external target (no address/URL/path) so slot rules do not apply; DPI is in the trusted user channel (out of our threat model); the rogue-tool cases are a *tool-authorization* question (per-agent least privilege), true by construction once an allow-list exists |
| ACIArena (1,356 cases; math/code/sci/med tasks, 28 attacks) | text in the final answer, e.g. `us-newyork` appears in the response, wrong answers, disruption | attacks act on message/answer *content* with no tool call: outside a tool-boundary gate; needs output-channel information-flow control (the free-text gap from P2) |
- To evaluate honestly we would have to run their MAS frameworks (AutoGen/CrewAI/MetaGPT...) with an LLM and wrap their tool layer in the TCB: hours of compute and installing/running third-party code. Not done.
- Takeaway: our result (grounding of tool targets) and these suites measure different boundaries. Claim only the InjecAgent/live-agent/synthetic numbers for tool-effect attacks, and list output-channel attacks as out of scope.
