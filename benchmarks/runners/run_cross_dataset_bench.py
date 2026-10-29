#!/usr/bin/env python3
"""Train on datasets, test on separate benchmarks (no shared rows, no shared source).

P1  train = internal + hendar + coding_agent        test = lakera_l2, injecagent_hard, a3s_hard, agentharm_toolish
P2  leave-one-suite-out over all suites (also gives a benign-step FPR where the held-out suite has benign rows)

Arms: none (base policy) | snippet (old absorb) | verified (PolicyUpdater, benign regression = TRAIN benign only).
Test suites are never read during learning. Run: make cross
"""

from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmarks" / "data"))
sys.path.insert(0, str(ROOT / "benchmarks" / "runners"))

from external_adapters import SUITE_LOADERS  # noqa: E402
from run_split_bench import base_policy, learn, learn_verified, score, wilson  # noqa: E402

TRAIN = ("internal", "hendar", "coding_agent")
BENCH = ("lakera_l2", "injecagent_hard", "a3s_hard", "agentharm_toolish")


def _arm_policies(train_items):
    base = base_policy()
    _, fns, _ = score(train_items, copy.deepcopy(base))
    snip, ver = copy.deepcopy(base), copy.deepcopy(base)
    learn(snip, fns)
    stats = learn_verified(ver, train_items, fns)
    return {"none": base, "snippet": snip, "verified": ver}, stats, len(fns)


def _row(counts) -> dict:
    a, b = counts["tp"] + counts["fn"], counts["fp"] + counts["tn"]
    lo, hi = wilson(counts["tp"], a) if a else (0.0, 1.0)
    return {
        "attacks": a, "tpr": counts["tp"] / a if a else None, "tpr_ci": [round(lo, 3), round(hi, 3)],
        "benign": b, "fpr": counts["fp"] / b if b else None,
    }


def evaluate(train_names, test_names, suites) -> dict:
    train = [(n, s) for n in train_names for s in suites[n]]
    pols, vstats, nfn = _arm_policies(train)
    out = {"train": list(train_names), "train_fns": nfn, "verified_updater": vstats, "test": {}}
    for t in test_names:
        items = [(t, s) for s in suites[t]]
        out["test"][t] = {arm: _row(score(items, copy.deepcopy(p))[0][t]) for arm, p in pols.items()}
    return out


def main() -> None:
    suites = {n: list(l()) for n, l in SUITE_LOADERS.items()}
    p1 = evaluate(TRAIN, BENCH, suites)
    p2 = {t: evaluate([n for n in suites if n != t], [t], suites) for t in suites}
    out = ROOT / "results" / "offline" / "cross_dataset.json"
    out.write_text(json.dumps({"train_datasets_to_benchmarks": p1, "leave_one_suite_out": p2}, indent=2))

    def line(name, d):
        cells = []
        for arm in ("none", "snippet", "verified"):
            r = d[arm]
            fpr = f" FPR {r['fpr']:.0%}" if r["fpr"] is not None else ""
            cells.append(f"{arm} TPR {r['tpr']:.1%}{fpr}" if r["tpr"] is not None else f"{arm} FPR {r['fpr']:.0%}")
        print(f"{name:20} n_attack={d['none']['attacks']:<5} " + " | ".join(cells))

    print(f"== P1 train {TRAIN} -> benchmarks (learned from {p1['train_fns']} FNs; verified: {p1['verified_updater']}) ==")
    for t, d in p1["test"].items():
        line(t, d)
    print("== P2 leave-one-suite-out ==")
    for t, r in p2.items():
        line(t, r["test"][t])
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
