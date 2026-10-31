# Architecture

Two ideas on top of the system-level reference-monitor stance of [arXiv:2605.18991](https://arxiv.org/abs/2605.18991):

1. **History-aware, risk-adaptive gating.** The gate tracks provenance itself and decides per call how much checking it needs.
2. **Verified policy-update harness.** Policy is updated from labelled failures, but only by rules that pass a benign regression check, are narrowing-only, and can be rolled back.

The LLM is untrusted and nothing in the TCB is a model.

## Code map

| File | Role |
|---|---|
| `src/agent_security_gate/tcb.py` | `SecurityTCB`: the only path from agent to tools. `begin_task`, `register_tool`, `invoke`, `audit_queue`. |
| `reference_monitor.py` | `ReferenceMonitor.check`: runs every detector, returns an allow/deny `Decision`. |
| `roles.py` | Task to role to capability set (least privilege). |
| `policy.py` | `SecurityPolicy`: allow/block hosts, injection patterns, tool-to-capability map, role capabilities. |
| `detectors.py` | Stateless checks: network/DNS, secrets in args, sensitive paths, TCB invariants, injection patterns. |
| `session.py` | **Idea 1.** `SessionState` (provenance, taint, secret fragments), `risk_tier`, `session_findings`. |
| `policy_update.py` | **Idea 2.** `PolicyUpdater`: propose, verify, activate, ledger, rollback, review queue. |
| `learning.py` | The earlier snippet-absorb learner. Kept as the baseline arm in the benchmarks. |

## Life of one tool call

```
agent loop (benchmarks/llm/live_agent.py)
  model emits tool_use(name, args)
        │                        the agent never holds a tool handle
        ▼
SecurityTCB.invoke(name, args)                          tcb.py
  1. ToolRequest(tool, args, data_channel?, data_trust)
  2. ReferenceMonitor.check(identity, req, session, adaptive)       reference_monitor.py
       a. tier  = high if session.suspicious else risk_tier(tool)   session.py
       b. context = caller's data_channel (EXTERNAL),
                    else everything the session has ingested (EXTERNAL)
       c. cheap, always run (structural):
            RBAC · network/DNS allowlist · secret-in-args · sensitive path · TCB invariants
       d. deep scan (skipped for low-risk calls when adaptive=True):
            injection patterns over 4 views (raw, canonical, zero-width/homoglyph, base64)
            a hit sets session.suspicious
       e. session_findings:
            secret_taint      secret read earlier appears in an egress arg (raw/b64/hex/reversed/window)
            session_quarantine  effect-capable call after instruction-like content was ingested
            taint_flow        recipient/URL/path in an effect arg came from untrusted content, not the user task
       f. allowed  ⇔  no finding has severity "block"; append an AuditEntry
  3. denied  → ToolResult(ok=False, error=reason); the tool never runs; agent is told "BLOCKED"
     allowed → handler(args) runs, then session.observe_output(tool, output):
                 ingest tools (fetch, browse, read_file, mcp, agent_message) → output becomes ambient EXTERNAL text
                 secret-looking values in any output → remembered as secret fragments
  4. (identity, req, decision) is appended to tcb.audit_queue for the harness
```

Why this shape:
- **Complete mediation.** Tools are registered inside the TCB, so `invoke` is the only way to reach them. `calls_seen` and `calls_bypassed` are counted.
- **Provenance is the TCB's job.** Older code relied on the caller passing `data_channel`. Now `session_tracking=True` marks tool output EXTERNAL automatically. A caller that forgets cannot create a gap.
- **Risk tiers (idea 1).** The cheap structural checks run on every call. The expensive injection scan can be deferred on read-only calls, because the ingested text stays in the session and is scanned at the next effect-capable call. In `adaptive` mode, `risk_tier` marks a call `low` only if its capability is read-only (`risk_tier` in `session.py`).

## The policy-update harness (idea 2)

```
tcb.audit_queue ──► teacher(identity, req)  ──► True  = attack, but it was allowed (false negative)
 (every decision)   human / offline judge /     False = benign,  but it was blocked (false positive)
                    environment-effect check    None  = unknown, skip
                          │
        false negative ───┤                        false positive ──► expansion_requests
                          ▼                                          (never auto-applied; a human decides)
        PolicyUpdater.learn_from_fn / learn_batch
          candidates: blocked hosts from the evidence; injection patterns as order-insensitive
                      word sets, most general first, verbatim line last
          support:    a pattern must match >= 2 FN texts when learning in batch (anti-memorization)
          verify:     count benign regression-corpus calls the live policy allows but the candidate blocks;
                      reject if > fp_budget (default 0)
          activate:   mutate the live SecurityPolicy (same object the monitor holds)
          ledger:     VersionRecord(version, parent, kind, value, evidence, accepted, reason, regressions)
          rollback(v) restores blocked hosts + patterns of version v
```

Guarantees: only narrowing rules (more blocked hosts, more patterns). Allowlists, roles, and TCB invariants are never edited. Every rule has evidence and a version, and the ledger is JSON (`results/offline/policy_ledger.json`).

Limits:
- The regression check is only as good as the benign corpus. A rule can block benign traffic from a domain the corpus does not cover; see `docs/EVALUATION.md`.
- A false negative with no host or pattern to learn (a structural miss) is counted as `unlearnable_fn` and needs a new detector.
- The teacher is outside the TCB. In the benchmarks it is the dataset label.

## Extending

- New detector: add a function in `detectors.py`, call it from `ReferenceMonitor.check`, add a scenario in `benchmarks/data/scenarios.py`.
- New ingest tool: add its name to `INGEST_TOOLS` in `session.py`.
- New effect capability: add it to `EFFECT_CAPS` in `session.py`.
- New attack form for the session gate: add a `Variant` in `benchmarks/data/session_variants.py`. `tests/test_session_and_updates.py` fails if any variant not marked `known_gap` gets through.
