#!/usr/bin/env python3
"""Mechanism checks for the two ideas.

Part A  history-aware / risk-adaptive gating  (stateless vs session vs session+adaptive)
Part B  policy learning                       (none vs snippet-absorb vs verified updates)

Scenarios are authored in this repo (synthetic). Numbers show the mechanism works and what
it costs; they are not comparable to published benchmarks.
"""

from __future__ import annotations

import json
import logging
import statistics
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmarks" / "data"))
sys.path.insert(0, str(ROOT / "benchmarks" / "runners"))

from agent_security_gate.policy import TrustLevel, default_policy  # noqa: E402
from agent_security_gate.policy_update import PolicyUpdater  # noqa: E402
from agent_security_gate.reference_monitor import ToolRequest  # noqa: E402
from agent_security_gate.roles import authenticate_task  # noqa: E402
from agent_security_gate.tcb import SecurityTCB  # noqa: E402
from run_bench import TRAIN_TIERS, _stub_tools, score  # noqa: E402
from scenarios import by_difficulty  # noqa: E402
from session_scenarios import ANALYST_CAPS, SESSION_SCENARIOS  # noqa: E402
from session_variants import VARIANTS  # noqa: E402


# ------------------------------------------------------------------ Part A
def run_session_arm(
    name: str, *, session: bool, adaptive: bool = False, label_prev: bool = False, scenarios=SESSION_SCENARIOS
) -> dict:
    pol = default_policy()
    pol.role_capabilities["analyst"] = set(ANALYST_CAPS)
    tcb = SecurityTCB(policy=pol, session_tracking=session, adaptive=adaptive)
    cur = {"out": ""}
    for t in pol.tool_roles:
        tcb.register_tool(t, lambda a: cur["out"])
    atk = fn = ben = fp = 0
    lat: list[float] = []
    missed, wrongly = [], []
    for sc in scenarios:
        tcb.begin_task("alice", sc.task, role=sc.role)
        prev = None
        for st in sc.steps:
            cur["out"] = st.returns
            kw = {"data_channel": prev, "data_trust": TrustLevel.EXTERNAL} if (label_prev and prev) else {}
            r = tcb.invoke(st.tool, st.args, **kw)
            lat.append(r.decision.latency_ms)
            if st.expect_block:
                atk += 1
                if r.decision.allowed:
                    fn += 1
                    missed.append(f"{sc.id}:{st.label}")
            else:
                ben += 1
                if not r.decision.allowed:
                    fp += 1
                    wrongly.append(f"{sc.id}:{st.label}")
            if r.ok and st.returns:
                prev = st.returns
    m = tcb.monitor
    return {
        "arm": name,
        "attack_steps": atk, "asr": round(fn / atk, 3),
        "benign_steps": ben, "false_block_rate": round(fp / ben, 3),
        "deep_scans": m.deep_scans, "deep_scans_deferred": m.deep_scans_deferred,
        "latency_ms_mean": round(statistics.mean(lat), 4),
        "complete_mediation": round(m.calls_seen / (m.calls_seen + m.calls_bypassed), 3),
        "missed": missed, "wrongly_blocked": wrongly,
    }


def part_a2() -> list[dict]:
    """Adversarial surface-form variants. Reports per-family ASR and which misses were expected gaps."""
    gaps = {v.scenario.id for v in VARIANTS if v.known_gap}
    rows = []
    for arm, kw in (("stateless", {"session": False}), ("session", {"session": True}), ("session+adaptive", {"session": True, "adaptive": True})):
        r = run_session_arm(arm, scenarios=tuple(v.scenario for v in VARIANTS), **kw)
        fam = {}
        for v in VARIANTS:
            if not v.scenario.is_attack:
                continue
            missed = any(m.startswith(v.scenario.id + ":") for m in r["missed"])
            f = fam.setdefault(v.family, [0, 0])
            f[0] += 1
            f[1] += missed
        r["per_family_asr"] = {k: f"{b}/{a}" for k, (a, b) in fam.items()}
        r["unexpected_misses"] = [m for m in r["missed"] if m.split(":")[0] not in gaps]
        r["expected_gap_misses"] = [m for m in r["missed"] if m.split(":")[0] in gaps]
        rows.append(r)
    return rows


def part_a() -> list[dict]:
    return [
        run_session_arm("stateless", session=False),
        run_session_arm("stateless+last_output_label", session=False, label_prev=True),
        run_session_arm("session", session=True),
        run_session_arm("session+adaptive", session=True, adaptive=True),
    ]


# ------------------------------------------------------------------ Part B
def _benign_corpus(tiers) -> list:
    pol = default_policy()
    out = []
    for tier in tiers:
        for sc in by_difficulty(tier):
            ident = authenticate_task(sc.principal, sc.task, pol, role_override=sc.role)
            for st in sc.steps:
                if not st.expect_block:
                    out.append((ident, ToolRequest(st.tool, st.args, st.data_channel, st.data_trust)))
    return out


def _absorb(arm: str, pol, fn_events, updater) -> None:
    trainer = SecurityTCB(policy=pol)
    for ev in fn_events:
        if arm == "snippet":
            trainer.report_missed_attack(ev["tool"], ev["args"], note=ev["step"], data=ev.get("data_channel"))
        elif arm == "verified":
            updater.learn_from_fn(
                ToolRequest(ev["tool"], ev["args"], ev.get("data_channel"), TrustLevel.EXTERNAL), ev["step"]
            )


def _eval(pol, scs) -> dict:
    r = score(scs, pol, phase="eval")["rates"]
    return {"asr": r["attack_success_rate_asr"], "fpr": r["false_positive_rate"], "f1": r["f1"]}


def run_learning_arm(arm: str) -> dict:
    pol = default_policy()
    updater = PolicyUpdater(pol, _benign_corpus(TRAIN_TIERS)) if arm == "verified" else None
    for tier in ("easy", "hard"):
        _absorb(arm, pol, score(by_difficulty(tier), pol, phase=f"{tier}:learn")["fn_events"], updater)
    # unseen-fold: learn on half of the hard cases, test on the other half
    hard = by_difficulty("hard")
    ids = sorted({s.case_id for s in hard})
    folds = [set(ids[0::2]), set(ids[1::2])]
    cv = []
    for i in (0, 1):
        p = default_policy()
        u = PolicyUpdater(p, _benign_corpus(("easy",))) if arm == "verified" else None
        tr = tuple(s for s in hard if s.case_id in folds[i])
        te = tuple(s for s in hard if s.case_id in folds[1 - i])
        _absorb(arm, p, score(tr, p, phase="cv")["fn_events"], u)
        cv.append(_eval(p, te))
    return {
        "arm": arm,
        "held_out": _eval(pol, by_difficulty("held_out")),
        "hard_after": _eval(pol, hard),
        "hard_unseen_fold_asr": round(statistics.mean(c["asr"] for c in cv), 3),
        "hard_unseen_fold_fpr": round(statistics.mean(c["fpr"] for c in cv), 3),
        "rules": {"hosts": len(pol.network.blocked_hosts), "patterns": len(pol.content.extra_injection_patterns)},
        "updater": updater.summary() if updater else None,
        "_updater": updater,
    }


def part_b() -> list[dict]:
    base = _eval(default_policy(), by_difficulty("held_out"))
    rows = [{"arm": "none", "held_out": base, "rules": {}, "updater": None}]
    rows += [run_learning_arm("snippet"), run_learning_arm("verified")]
    return rows


def main() -> None:
    logging.getLogger("agent_security_gate").setLevel(logging.CRITICAL)
    a, b, a2 = part_a(), part_b(), part_a2()
    upd = b[-1].pop("_updater")
    for r in b[1:]:
        r.pop("_updater", None)
    out = ROOT / "results" / "offline"
    out.mkdir(parents=True, exist_ok=True)
    (out / "ideas_metrics.json").write_text(json.dumps({"session_gating": a, "session_variants": a2, "learning": b}, indent=2))
    upd.save(out / "policy_ledger.json")

    print("=== A. history-aware / adaptive gating (13 sessions) ===")
    for r in a:
        print(f"{r['arm']:30} ASR {r['asr']:.0%}  false-block {r['false_block_rate']:.0%}  "
              f"deep-scans {r['deep_scans']} (+{r['deep_scans_deferred']} deferred)  {r['latency_ms_mean']:.3f}ms  "
              f"missed={r['missed']} FP={r['wrongly_blocked']}")
    print(f"=== A2. red-team surface variants ({len(VARIANTS)} sessions) ===")
    for r in a2:
        print(f"{r['arm']:18} ASR {r['asr']:.0%} ({r['attack_steps']} attack steps)  false-block {r['false_block_rate']:.0%}  per-family missed/total {r['per_family_asr']}")
        print(f"{'':18} unexpected misses: {r['unexpected_misses']}\n{'':18} expected-gap misses: {r['expected_gap_misses']}  FP={r['wrongly_blocked']}")
    print("=== B. policy learning (train easy+hard, eval held_out) ===")
    for r in b:
        h = r["held_out"]
        extra = f"  unseen-fold ASR {r['hard_unseen_fold_asr']:.0%} FPR {r['hard_unseen_fold_fpr']:.0%}" if "hard_unseen_fold_asr" in r else ""
        print(f"{r['arm']:10} held_out ASR {h['asr']:.0%} FPR {h['fpr']:.0%}{extra}  rules={r['rules']}  {r['updater'] or ''}")


if __name__ == "__main__":
    main()
