#!/usr/bin/env python3
"""Difficulty-tiered harness over the paper/OWASP/emerging attack catalog."""

from __future__ import annotations

import json
import statistics
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "src"))

from agent_security_gate.policy import SecurityPolicy, default_policy  # noqa: E402
from agent_security_gate.tcb import SecurityTCB  # noqa: E402
from catalog import CASES, catalog_json  # noqa: E402
from scenarios import SCENARIOS, Difficulty, Scenario, by_difficulty  # noqa: E402

TIERS: tuple[Difficulty, ...] = ("easy", "hard", "held_out")
TRAIN_TIERS: frozenset[Difficulty] = frozenset({"easy", "hard"})

_ALL_TOOLS = (
    "http_fetch",
    "shell_exec",
    "read_file",
    "write_file",
    "delete_file",
    "dns_lookup",
    "ping",
    "send_email",
    "update_memory",
    "update_config",
    "start_server",
    "browser_navigate",
    "browser_submit",
    "clipboard_write",
    "mcp_invoke",
    "agent_message",
)


def _stub_tools(tcb: SecurityTCB) -> None:
    for name in _ALL_TOOLS:
        tcb.register_tool(name, lambda args, _n=name: {"tool": _n, "echo": args})


def _rates(tp: int, fp: int, tn: int, fn: int) -> dict[str, float]:
    attack = tp + fn
    benign = tn + fp
    tpr = tp / attack if attack else 0.0
    fpr = fp / benign if benign else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    recall = tpr
    f1 = (
        2 * precision * recall / (precision + recall) if (precision + recall) else 0.0
    )
    accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) else 0.0
    # Architecture-oriented metrics (brief §6)
    asr = fn / attack if attack else 0.0  # attack success = we failed to block
    containment = tpr
    unauthorized_action_rate = asr
    false_block_rate = fpr
    utility_retention = tn / benign if benign else 0.0
    return {
        "attack_block_rate_tpr": round(tpr, 4),
        "attack_success_rate_asr": round(asr, 4),
        "containment_rate": round(containment, 4),
        "unauthorized_action_rate": round(unauthorized_action_rate, 4),
        "false_positive_rate": round(fpr, 4),
        "false_block_rate": round(false_block_rate, 4),
        "utility_retention": round(utility_retention, 4),
        "false_negative_rate": round(fn / attack if attack else 0.0, 4),
        "precision": round(precision, 4),
        "recall": round(recall, 4),
        "f1": round(f1, 4),
        "accuracy": round(accuracy, 4),
    }


def score(
    scenarios: tuple[Scenario, ...],
    policy: SecurityPolicy,
    *,
    phase: str,
) -> dict[str, Any]:
    tcb = SecurityTCB(policy=policy)
    _stub_tools(tcb)
    tp = fp = tn = fn = 0
    latencies: list[float] = []
    by_family: dict[str, dict[str, int]] = {}
    step_rows: list[dict] = []
    fn_events: list[dict] = []
    tools_u = tools_g = 0
    case_fail: set[str] = set()
    case_ids: set[str] = set()

    for sc in scenarios:
        tcb.begin_task(sc.principal, sc.task, role=sc.role)
        tools_u += tcb.unrestricted_tool_count()
        tools_g += tcb.privilege_count()
        fam = by_family.setdefault(sc.family, {"tp": 0, "fp": 0, "tn": 0, "fn": 0})
        case_ids.add(sc.case_id)

        for step in sc.steps:
            res = tcb.invoke(
                step.tool,
                step.args,
                data_channel=step.data_channel,
                data_trust=step.data_trust,
            )
            blocked = not res.decision.allowed
            latencies.append(res.decision.latency_ms)
            if step.expect_block and blocked:
                tp += 1
                fam["tp"] += 1
            elif step.expect_block and not blocked:
                fn += 1
                fam["fn"] += 1
                case_fail.add(sc.case_id)
                fn_events.append(
                    {
                        "scenario": sc.id,
                        "case_id": sc.case_id,
                        "step": step.label,
                        "tool": step.tool,
                        "args": step.args,
                        "data_channel": step.data_channel,
                    }
                )
            elif not step.expect_block and blocked:
                fp += 1
                fam["fp"] += 1
            else:
                tn += 1
                fam["tn"] += 1

            step_rows.append(
                {
                    "phase": phase,
                    "scenario": sc.id,
                    "case_id": sc.case_id,
                    "family": sc.family,
                    "difficulty": sc.difficulty,
                    "control": sc.control,
                    "step": step.label,
                    "blocked": blocked,
                    "expect_block": step.expect_block,
                    "correct": blocked == step.expect_block,
                    "reason": res.decision.reason,
                    "latency_ms": round(res.decision.latency_ms, 4),
                }
            )

    mediation = tcb.monitor.calls_seen
    bypass = tcb.monitor.calls_bypassed
    rates = _rates(tp, fp, tn, fn)
    rates["complete_mediation_rate"] = round(
        mediation / (mediation + bypass) if (mediation + bypass) else 1.0, 4
    )
    rates["policy_enforcement_coverage"] = rates["complete_mediation_rate"]
    rates["privilege_reduction"] = round(
        1.0 - (tools_g / tools_u) if tools_u else 0.0, 4
    )
    attack_cases = {s.case_id for s in scenarios if s.is_attack}
    rates["case_containment_rate"] = round(
        1.0 - (len(case_fail & attack_cases) / len(attack_cases)) if attack_cases else 1.0,
        4,
    )
    return {
        "counts": {
            "scenarios": len(scenarios),
            "steps": len(step_rows),
            "cases": len(case_ids),
            "tp": tp,
            "fp": fp,
            "tn": tn,
            "fn": fn,
            "cases_with_fn": sorted(case_fail),
        },
        "rates": rates,
        "latency_ms": {
            "p50": round(statistics.median(latencies), 4) if latencies else 0.0,
            "p95": round(
                sorted(latencies)[max(0, int(len(latencies) * 0.95) - 1)], 4
            )
            if latencies
            else 0.0,
            "mean": round(statistics.mean(latencies), 4) if latencies else 0.0,
        },
        "by_family": by_family,
        "fn_events": fn_events,
        "steps": step_rows,
    }


def train_on_fns(tcb: SecurityTCB, fn_events: list[dict]) -> dict[str, int]:
    before_p = len(tcb.learning.learned_patterns)
    before_h = len(tcb.learning.learned_hosts)
    for ev in fn_events:
        tcb.report_missed_attack(
            ev["tool"],
            ev["args"],
            note=f"fn:{ev['case_id']}:{ev['step']}",
            data=ev.get("data_channel"),
        )
    return {
        "fns_absorbed": len(fn_events),
        "patterns_added": len(tcb.learning.learned_patterns) - before_p,
        "hosts_added": len(tcb.learning.learned_hosts) - before_h,
        "patterns_total": len(tcb.learning.learned_patterns),
        "hosts_total": len(tcb.learning.learned_hosts),
    }


def run_tier(
    tier: Difficulty,
    policy: SecurityPolicy,
    *,
    do_train: bool,
) -> tuple[dict[str, Any], SecurityPolicy]:
    scenarios = by_difficulty(tier)
    before = score(scenarios, policy, phase=f"{tier}:before")
    learn_stats: dict[str, Any] = {
        "fns_absorbed": 0,
        "patterns_added": 0,
        "hosts_added": 0,
        "patterns_total": len(policy.content.extra_injection_patterns),
        "hosts_total": len(policy.network.blocked_hosts),
        "trained": do_train,
    }
    if do_train and before["fn_events"]:
        trainer = SecurityTCB(policy=policy)
        _stub_tools(trainer)
        learn_stats = train_on_fns(trainer, before["fn_events"])
        learn_stats["trained"] = True
    elif do_train:
        learn_stats["trained"] = True

    after = score(scenarios, policy, phase=f"{tier}:after")
    return {
        "difficulty": tier,
        "trained": do_train,
        "before": {k: before[k] for k in ("counts", "rates", "latency_ms", "by_family")},
        "after": {k: after[k] for k in ("counts", "rates", "latency_ms", "by_family")},
        "learning": learn_stats,
        "delta": {
            "tpr": round(
                after["rates"]["attack_block_rate_tpr"]
                - before["rates"]["attack_block_rate_tpr"],
                4,
            ),
            "asr": round(
                after["rates"]["attack_success_rate_asr"]
                - before["rates"]["attack_success_rate_asr"],
                4,
            ),
            "fpr": round(
                after["rates"]["false_positive_rate"]
                - before["rates"]["false_positive_rate"],
                4,
            ),
            "f1": round(after["rates"]["f1"] - before["rates"]["f1"], 4),
            "fn_count": before["counts"]["fn"] - after["counts"]["fn"],
        },
        "fn_events_before": before["fn_events"],
        "steps_before": before["steps"],
        "steps_after": after["steps"],
    }, policy


def run() -> dict:
    policy = default_policy()
    tiers_out: dict[str, Any] = {}
    all_steps: list[dict] = []

    for tier in TIERS:
        result, policy = run_tier(tier, policy, do_train=tier in TRAIN_TIERS)
        tiers_out[tier] = {
            k: result[k]
            for k in (
                "difficulty",
                "trained",
                "before",
                "after",
                "learning",
                "delta",
                "fn_events_before",
            )
        }
        all_steps.extend(result["steps_before"])
        all_steps.extend(result["steps_after"])

    summary_rows = []
    for tier in TIERS:
        t = tiers_out[tier]
        br, ar = t["before"]["rates"], t["after"]["rates"]
        summary_rows.append(
            {
                "difficulty": tier,
                "trained": t["trained"],
                "before_tpr": br["attack_block_rate_tpr"],
                "after_tpr": ar["attack_block_rate_tpr"],
                "before_asr": br["attack_success_rate_asr"],
                "after_asr": ar["attack_success_rate_asr"],
                "before_fpr": br["false_positive_rate"],
                "after_fpr": ar["false_positive_rate"],
                "before_f1": br["f1"],
                "after_f1": ar["f1"],
                "before_containment": br["containment_rate"],
                "after_containment": ar["containment_rate"],
                "before_utility": br["utility_retention"],
                "after_utility": ar["utility_retention"],
                "mediation": ar["complete_mediation_rate"],
                "fns_before": t["before"]["counts"]["fn"],
                "fns_after": t["after"]["counts"]["fn"],
                "patterns_added": t["learning"].get("patterns_added", 0),
                "hosts_added": t["learning"].get("hosts_added", 0),
            }
        )

    executable_case_ids = sorted({s.case_id for s in SCENARIOS})
    return {
        "paper": "arXiv:2605.18991 — Agent Security is a Systems Problem",
        "dataset": {
            "catalog_cases": len(CASES),
            "executable_scenarios": len(SCENARIOS),
            "executable_case_ids": executable_case_ids,
            "collections": {
                "historical": sum(1 for c in CASES if c.collection == "historical"),
                "reproducible": sum(1 for c in CASES if c.collection == "reproducible"),
                "novel": sum(1 for c in CASES if c.collection == "novel"),
            },
            "note": (
                "Catalog holds all 45 brief cases; executable scenarios are "
                "synthetic tool traces for architecture testing (not live exploits)."
            ),
        },
        "harness": {
            "loop": "for tier in easy→hard→held_out: score → absorb FNs (train) → re-score",
            "warm_start": True,
            "train_tiers": sorted(TRAIN_TIERS),
            "held_out_trains": False,
            "gate_code_policy": "detectors+RBAC+TCB invariants; difficulty in dataset",
        },
        "tiers": tiers_out,
        "summary": summary_rows,
        "learned_policy_snapshot": {
            "blocked_hosts": sorted(policy.network.blocked_hosts),
            "extra_pattern_count": len(policy.content.extra_injection_patterns),
        },
        "steps": all_steps,
        "interpretation": {
            "research_question": (
                "Can a system-level security architecture prevent unauthorized "
                "actions and data flows even when the agent is manipulated?"
            ),
            "asr": "Lower is better — share of attack steps that were allowed.",
            "containment": "Higher is better — share of attack steps blocked.",
            "utility_retention": "Higher is better — benign steps still allowed.",
            "held_out": "No absorb; measures generalization beyond train tiers.",
        },
    }


def main() -> None:
    metrics = run()
    out_dir = ROOT / "results"
    out_dir.mkdir(exist_ok=True)
    out_path = out_dir / "metrics.json"
    catalog_path = out_dir / "catalog.json"
    out_path.write_text(json.dumps(metrics, indent=2))
    catalog_path.write_text(json.dumps(catalog_json(), indent=2))

    print("=== Agent Security Gate — paper/OWASP/emerging harness ===")
    ds = metrics["dataset"]
    print(
        f"catalog={ds['catalog_cases']} cases | "
        f"executable={ds['executable_scenarios']} scenarios | "
        f"collections={ds['collections']}"
    )
    for row in metrics["summary"]:
        print(
            f"[{row['difficulty']:8}] "
            f"TPR {row['before_tpr']:.0%}→{row['after_tpr']:.0%}  "
            f"ASR {row['before_asr']:.0%}→{row['after_asr']:.0%}  "
            f"FPR {row['before_fpr']:.0%}→{row['after_fpr']:.0%}  "
            f"util {row['before_utility']:.0%}→{row['after_utility']:.0%}  "
            f"F1 {row['before_f1']:.2f}→{row['after_f1']:.2f}  "
            f"FN {row['fns_before']}→{row['fns_after']}"
        )
    print(f"wrote {out_path}")
    print(f"wrote {catalog_path}")


if __name__ == "__main__":
    main()
