---
name: solution-design-review
description: Use when planning, writing, or reviewing a tech/product solution (design doc, BBD/NFR plan, rate limiting, topic/queue isolation, new feature) or when asked to understand an unfamiliar codebase. Gives a senior-engineer checklist: requirement first, options, risks, rollout, verification, and how to explore code cheaply.
---

# Solution design & review (senior-engineer way)

Lessons come from past reachout-gateway / reachout-bot sessions: rate limiting (Guava vs Bucket4j, per-pod vs global), ingress topic isolation (P0/P1), NFR load plans, CLAUDE.md creation.

## 1. State the requirement before the solution
Write 3 lines: **Who/what is protected or improved? What exact outcome? What is out of scope?**
- Past miss: "we have rate limiting" ≠ requirement. Real one: *per-client/tenant limit on direct API calls, to absorb spikes*.
- Name the **limits of the environment** up front (e.g. only one DB available, no Redis; clients adopt contract changes slowly; no lookups possible before publish). Many "good" options die here.
- Ask the user at most 3 questions, only if the answer changes the design.

## 2. Check what exists first (cheap code exploration)
- Read `CLAUDE.md`, then grep the entry point (controller/consumer) and follow one request end to end. Don't read whole packages.
- Answer "where does X happen" with file:line, and say what is checked **before** what (e.g. rate limit rejects at entry → nothing is published).
- Separate **per-instance vs shared/global** state, **sync vs async** path, **who owns the retry**. Most wrong answers confuse these.
- Verify the claim in code before agreeing with a senior or a doc ("is it Guava or Bucket4j?" → look, don't recall).

## 3. Options table (always 2–4, incl. "do nothing/smallest change")
| Option | How | Pros | Cons | Cost/effort | Reversible? |
Pick one with a one-line reason. Say what you reject and why — reviewers always ask "what about the alternative?".

## 4. Stress-test the pick (pre-mortem)
- **Failure**: what breaks if a dependency is down, slow, or sends garbage? Safe default? (missing header → old path, never block.)
- **Abuse**: can a client claim high priority/quota? Who confirms, what caps it?
- **Mixed cases**: one bucket/event/topic carrying different priorities or tenants.
- **Consistency**: per-pod limits multiply by pod count; global limits need shared state.
- **Backward compatibility**: old clients, old events, old config keep working.
- **Retry/dup**: where do failures go (retry queue vs original topic)? Idempotent?
- **Capacity**: rough numbers (QPS, pods, threads, lag). If unknown, say how you will measure; don't invent.
- **Cost/ops**: new infra, alerts, runbook, on-call burden.

## 5. Rollout & rollback
Feature flag/config default OFF → one tenant/zone → ramp → full. Rollback = flip flag, no data migration. Give the metric that says "go/stop".

## 6. Verify after the change (evaluate after-effects)
- Before/after on same metric: latency p50/p99, error rate, queue lag, rejected count, CPU/mem, thread pool saturation.
- NFR plan: tool, data source, target QPS, traffic suppression (so load doesn't hit real users/downstreams), cleanup, tuning knobs, steps (start → monitor → stop), pass/fail numbers.
- Test: unit for the decision logic, one integration/flow test, load test for the limit. Add logs/metrics for the new decision (allowed/blocked/defaulted) so you can prove it works in prod.

## 7. Writing the doc (manager-ready, short)
1. Problem & impact · 2. Goal / non-goals · 3. Current flow · 4. Options table · 5. Chosen design + diagram/flow · 6. Risks & mitigations · 7. Rollout/rollback · 8. NFR/test plan · 9. Open questions (owner + date).
- Plain words, short sentences, one idea per bullet. Define each acronym once. Numbers marked *measured* or *to measure*.
- Before presenting: "Would a senior ask 'why not X?' / 'what if Y fails?' / 'how do you know it works?'" — each must have an answer in the doc.

## 8. Code writing
- Smallest change that meets the requirement; reuse existing config/metrics/test patterns; match surrounding style.
- Config-driven (ConfigMap/dynamic props), safe defaults, fail-open vs fail-closed chosen explicitly and documented.
- Show only changed lines; no whole-file rewrites; no new dependency if existing one does it (e.g. Bucket4j already present).

## 9. Reply style (saves tokens and rounds)
Lead with the verdict ("Yes, sufficient except X" / "No, because Y"). Then the few concrete gaps, ranked. Mark each gap *must fix* vs *nice to have*. No restating the user's doc.
