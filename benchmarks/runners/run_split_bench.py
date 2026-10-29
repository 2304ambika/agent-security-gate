#!/usr/bin/env python3
"""Leak-free evaluation: pooled internal + external suites, 70/30 grouped split.

- Split is by hash of a *group key* (suite + family + normalized payload), so
  duplicates/templated variants never straddle train and test.
- Learning (FN absorption) sees TRAIN only. TEST is scored with the base policy
  (control) and the learned policy. Never edit detectors after reading TEST misses.
- Repeated over several salts -> mean/min/max, plus Wilson 95% CIs per suite.
"""

from __future__ import annotations

import copy
import hashlib
import argparse
import json
import logging
import math
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(ROOT / "benchmarks" / "data"))

from agent_security_gate.policy import NetworkPolicy, TrustLevel, default_policy  # noqa: E402
from agent_security_gate.policy_update import PolicyUpdater  # noqa: E402
from agent_security_gate.reference_monitor import ToolRequest  # noqa: E402
from agent_security_gate.roles import authenticate_task  # noqa: E402
from agent_security_gate.tcb import SecurityTCB  # noqa: E402
from external_adapters import SUITE_LOADERS  # noqa: E402

TRAIN_FRAC = 0.70
SALTS = ("s0", "s1", "s2", "s3", "s4")


def base_policy():
    p = default_policy()
    allowed = set(p.network.allowed_hosts) | {
        "example.com", "docs.python.org", "arxiv.org", "api.github.com",
    }
    p.network = NetworkPolicy(
        allowed_hosts=frozenset(allowed),
        blocked_hosts=p.network.blocked_hosts,
        allow_dns_lookup=p.network.allow_dns_lookup,
        dns_allowlist=frozenset(set(p.network.dns_allowlist) | allowed),
        max_dns_label_len=p.network.max_dns_label_len,
        block_encoded_dns_labels=p.network.block_encoded_dns_labels,
    )
    return p


def group_key(suite: str, sc) -> str:
    blob = " ".join((s.data_channel or "") + str(s.args) for s in sc.steps) or sc.task
    blob = re.sub(r"\d+", "#", blob.lower())[:80]
    return f"{suite}|{sc.family}|{blob}"


def is_train(key: str, salt: str) -> bool:
    h = int(hashlib.sha256(f"{salt}|{key}".encode()).hexdigest(), 16) % 10_000
    return h < TRAIN_FRAC * 10_000


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float]:
    if n == 0:
        return (0.0, 1.0)
    p = k / n
    d = 1 + z * z / n
    c = p + z * z / (2 * n)
    m = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return ((c - m) / d, (c + m) / d)


def score(items, policy):
    """items: [(suite, Scenario)] -> per-suite counts + FN events."""
    tcb = SecurityTCB(policy=policy)
    counts: dict[str, dict[str, int]] = {}
    fns = []
    for suite, sc in items:
        c = counts.setdefault(suite, dict(tp=0, fp=0, tn=0, fn=0))
        tcb.begin_task(sc.principal, sc.task, role=sc.role)
        for st in sc.steps:
            if st.tool not in tcb._tools:  # noqa: SLF001
                tcb.register_tool(st.tool, lambda a: {})
            r = tcb.invoke(st.tool, st.args, data_channel=st.data_channel, data_trust=st.data_trust)
            blocked = not r.decision.allowed
            if st.expect_block:
                c["tp" if blocked else "fn"] += 1
                if not blocked:
                    fns.append((sc.case_id, st))
            else:
                c["fp" if blocked else "tn"] += 1
    return counts, fns, tcb


def learn(policy, fns):
    t = SecurityTCB(policy=policy)
    for cid, st in fns:
        t.report_missed_attack(st.tool, st.args, note=f"fn:{cid}", data=st.data_channel)


def learn_verified(policy, train, train_fns, min_support: int = 2):
    """Same FNs as `learn`, but each rule is verified against TRAIN benign steps only."""
    corpus = []
    for _, sc in train:
        ident = authenticate_task(sc.principal, sc.task, policy, role_override=sc.role)
        corpus += [
            (ident, ToolRequest(st.tool, st.args, st.data_channel, st.data_trust))
            for st in sc.steps if not st.expect_block
        ]
    up = PolicyUpdater(policy, corpus)
    up.learn_batch(
        [(ToolRequest(st.tool, st.args, st.data_channel, TrustLevel.EXTERNAL), f"fn:{cid}") for cid, st in train_fns],
        min_support=min_support,
    )
    return up.summary()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--suites", nargs="*", default=list(SUITE_LOADERS), help="e.g. internal")
    ap.add_argument("-v", "--verbose", action="store_true", help="per-call TCB logs")
    args = ap.parse_args()
    if args.verbose:
        logging.basicConfig(level=logging.INFO, format="%(levelname)-5s %(message)s")
    pool = []
    for name in args.suites:
        loader = SUITE_LOADERS[name]
        for sc in loader():
            pool.append((name, sc, group_key(name, sc)))
    print(f"pool: {len(pool)} scenarios, {len({g for *_, g in pool})} groups")
    print(f"{'suite':20}{'scenarios':>10}{'groups':>8}{'attack steps':>14}{'benign steps':>14}")
    for name in args.suites:
        sc = [s for n, s, _ in pool if n == name]
        steps = [st for s in sc for st in s.steps]
        na = sum(st.expect_block for st in steps)
        print(f"{name:20}{len(sc):10}{len({g for n, _, g in pool if n == name}):8}{na:14}{len(steps) - na:14}")

    agg: dict[str, dict[str, list]] = {}
    vstats: list[dict] = []
    for salt in SALTS:
        train = [(n, s) for n, s, g in pool if is_train(g, salt)]
        test = [(n, s) for n, s, g in pool if not is_train(g, salt)]
        # sanity: groups must not overlap
        assert not ({g for n, s, g in pool if is_train(g, salt)} & {g for n, s, g in pool if not is_train(g, salt)})

        pol = base_policy()
        c0, _, _ = score(test, copy.deepcopy(pol))  # control: no learning
        _, train_fns, _ = score(train, pol)
        pol_v = copy.deepcopy(pol)
        learn(pol, train_fns)
        c1, _, _ = score(test, pol)  # snippet-absorb, learned on TRAIN only
        vs = learn_verified(pol_v, train, train_fns)
        c2, _, _ = score(test, pol_v)  # verified updates, learned on TRAIN only
        vstats.append(vs)
        for suite in c0:
            a = agg.setdefault(suite, {"before": [], "after": [], "verified": []})
            a["before"].append(c0[suite])
            a["after"].append(c1[suite])
            a["verified"].append(c2[suite])

    def tot(rows):
        return {k: sum(r[k] for r in rows) for k in ("tp", "fp", "tn", "fn")}

    report = {}
    print(f"\n70/30 grouped split, {len(SALTS)} salts, TEST-only, pooled over salts\n")
    print(f"{'suite':20}{'attacks':>8}  {'TPR before':>22}  {'TPR after':>22}  {'FPR after':>20}")
    macro_b, macro_a = [], []
    for suite, a in agg.items():
        b, f, v = tot(a["before"]), tot(a["after"]), tot(a["verified"])
        na = b["tp"] + b["fn"]
        nb = f["fp"] + f["tn"]
        tb, ta = (b["tp"] / na if na else float("nan")), (f["tp"] / na if na else float("nan"))
        lb, ub = wilson(b["tp"], na)
        la, ua = wilson(f["tp"], na)
        fpr = f["fp"] / nb if nb else float("nan")
        lf, uf = wilson(f["fp"], nb)
        if na:
            macro_b.append(tb)
            macro_a.append(ta)
        tv = v["tp"] / na if na else float("nan")
        fv = v["fp"] / (v["fp"] + v["tn"]) if v["fp"] + v["tn"] else float("nan")
        per_salt = [r["tp"] / (r["tp"] + r["fn"]) for r in a["after"] if r["tp"] + r["fn"]]
        report[suite] = dict(
            attack_steps=na, benign_steps=nb, tpr_before=tb, tpr_after=ta,
            tpr_after_ci=[la, ua], fpr_after=fpr, fpr_ci=[lf, uf],
            tpr_after_per_salt=per_salt, tpr_verified=tv, fpr_verified=fv,
        )
        print(
            f"{suite:20}{na:8}  {tb:6.1%} [{lb:5.1%},{ub:5.1%}]  "
            f"{ta:6.1%} [{la:5.1%},{ua:5.1%}]  "
            f"{fpr:6.1%} [{lf:5.1%},{uf:5.1%}] n={nb}  | verified TPR {tv:6.1%} FPR {fv:6.1%}"
        )
    allb = tot([r for a in agg.values() for r in a["before"]])
    alla = tot([r for a in agg.values() for r in a["after"]])
    n_att, n_ben = alla["tp"] + alla["fn"], alla["fp"] + alla["tn"]
    la, ua = wilson(alla["tp"], n_att)
    lf, uf = wilson(alla["fp"], n_ben)
    print(f"{'ALL (pooled)':20}{n_att:8}  {allb['tp']/n_att:6.1%}{'':16}{alla['tp']/n_att:6.1%} [{la:5.1%},{ua:5.1%}]  "
          f"{alla['fp']/n_ben:6.1%} [{lf:5.1%},{uf:5.1%}] n={n_ben}")
    report["_all_pooled"] = dict(tpr_before=allb["tp"] / n_att, tpr_after=alla["tp"] / n_att, fpr_after=alla["fp"] / n_ben)
    allv = tot([r for a in agg.values() for r in a["verified"]])
    report["_all_pooled"].update(tpr_verified=allv["tp"] / n_att, fpr_verified=allv["fp"] / (allv["fp"] + allv["tn"]))
    print(f"verified updates (pooled): TPR {allv['tp']/n_att:.1%}  FPR {allv['fp']/(allv['fp']+allv['tn']):.1%}  "
          f"rules accepted/proposed per salt: {[(x['accepted'], x['proposed']) for x in vstats]}")
    mb, ma = sum(macro_b) / len(macro_b), sum(macro_a) / len(macro_a)
    report["_macro"] = {"tpr_before": mb, "tpr_after": ma}
    print(f"\nmacro-avg TPR (each suite weighted equally): {mb:.1%} -> {ma:.1%}")
    out = ROOT / "results" / "offline" / ("split_metrics.json" if len(args.suites) > 1 else f"split_{args.suites[0]}.json")
    out.write_text(json.dumps(report, indent=2))
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
