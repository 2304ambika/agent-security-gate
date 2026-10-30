#!/usr/bin/env python3
"""Leveled synthetic MAS data: no-learning vs flat vs curriculum (vs prior-art arms).

Train: TRAIN families x TRAIN domains.  Test: iid (train families, new domains, new seed) and
ood (held-out families x held-out domains). Learning never sees test rows. External suites are an
out-of-distribution check. Run: make synth
"""

from __future__ import annotations

import argparse
import copy
import json
import statistics as st
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
for p in ("src", "benchmarks/data", "benchmarks/runners"):
    sys.path.insert(0, str(ROOT / p))

import synth_mas as S  # noqa: E402
from agent_security_gate.rule_induction import Ex, RuleInducer  # noqa: E402
from external_adapters import SUITE_LOADERS  # noqa: E402
from run_split_bench import base_policy, learn, learn_verified, score  # noqa: E402

EXT_OOD = ("lakera_l2", "a3s_hard", "coding_agent", "internal")


def _level(sc) -> str:
    return sc.family.split("|")[0]


def _kind(sc) -> str:
    return sc.family.split("|")[3]


def evaluate(policy, scenarios) -> dict[str, dict]:
    """Per-level TPR plus FPR on benign and hard negatives."""
    items = [(f"{_level(sc)}|{_kind(sc)}", sc) for sc in scenarios]
    counts, _, _ = score(items, copy.deepcopy(policy))
    out: dict[str, dict] = {}
    for key, c in counts.items():
        out[key] = {"tpr": c["tp"] / (c["tp"] + c["fn"]) if c["tp"] + c["fn"] else None,
                    "fpr": c["fp"] / (c["fp"] + c["tn"]) if c["fp"] + c["tn"] else None}
    return out


def _ex(sc) -> Ex:
    st = sc.steps[0]
    return Ex(sc.task, st.data_channel or "", sc.family.split("|")[1], st.tool, st.args)


def _examples(scs):
    return [_ex(sc) for sc in scs if sc.is_attack]


def _benign(scs):
    return [_ex(sc)._replace(group="") for sc in scs if not sc.is_attack]


def _nobreadth(scs):
    return [s for s in scs if _kind(s) != "hard_breadth"]


def arm_rules(train, levels, *, space: str, curriculum: bool, prune=True, fp_budget=0, min_support=3, min_groups=2):
    """Benign regression corpus = all benign rows in `train` (benign traffic exists from day one);
    levels only order the *attack* data."""
    pol = base_policy()
    ind = RuleInducer(pol, _benign(train), space=space, fp_budget=fp_budget, min_support=min_support, min_groups=min_groups)
    for stage in ([[lv] for lv in levels] if curriculum else [list(levels)]):
        ind.learn(_examples([s for s in train if _level(s) in stage]))
    if prune:
        ind.prune()
    return pol, ind.summary()


def run_seed(seed: int, levels, n_per: int) -> dict:
    train_all = S.suite(levels, S.TRAIN_FAMILIES, S.TRAIN_DOMAINS, n_per, seed, breadth_per=6)
    train = _nobreadth(train_all)
    tests = {
        "iid": S.suite(levels, S.TRAIN_FAMILIES, S.HELD_DOMAINS, n_per, seed + 1000, hard_split="train", breadth_per=6),
        "ood": S.suite(levels, S.HELD_FAMILIES, S.HELD_DOMAINS, n_per, seed + 2000, hard_split="held", breadth_per=6),
    }
    base = base_policy()
    pols: dict[str, tuple] = {"none": (base, {})}
    # prior art: verbatim snippet / verified regex learning from base FNs on the same train data
    items = [("train", s) for s in train]
    _, fns, _ = score(items, copy.deepcopy(base))
    snip = copy.deepcopy(base)
    learn(snip, fns)
    ver = copy.deepcopy(base)
    pols["snippet"] = (snip, {"fns": len(fns)})
    pols["verified_regex"] = (ver, learn_verified(ver, items, fns))
    for space, corp, tr in (("text", "narrow", train), ("text", "broad", train_all), ("slot", "broad", train_all), ("both", "broad", train_all)):
        for curr in (False, True):
            pols[f"{space}/{corp}/{'curr' if curr else 'flat'}"] = arm_rules(tr, levels, space=space, curriculum=curr)
    pols["both/broad/curr-noprune"] = arm_rules(train_all, levels, space="both", curriculum=True, prune=False)
    # ablation: no benign breadth for the structural learner, and no pruning for slot-only
    pols["slot/narrow/flat"] = arm_rules(train, levels, space="slot", curriculum=False)
    pols["both/broad/reverse"] = arm_rules(train_all, tuple(reversed(levels)), space="both", curriculum=True)
    res = {"arms": {}}
    ext = {n: [(n, s) for s in SUITE_LOADERS[n]()] for n in EXT_OOD}
    for arm, (pol, info) in pols.items():
        r = {"info": info, "rules": sorted("+".join(x) for x in pol.content.learned_rules) + sorted("slot:" + ".".join(x) for x in pol.content.grounded_slots)}
        for split, scs in tests.items():
            r[split] = evaluate(pol, scs)
        fam_items = [(sc.family.split("|")[1], sc) for sc in tests["ood"] if sc.is_attack]
        r["ood_family"] = {f: c["tp"] / (c["tp"] + c["fn"]) for f, c in score(fam_items, copy.deepcopy(pol))[0].items()}
        r["ext"] = {}
        for n, its in ext.items():
            c = score(its, copy.deepcopy(pol))[0][n]
            a, b = c["tp"] + c["fn"], c["fp"] + c["tn"]
            r["ext"][n] = {"tpr": c["tp"] / a if a else None, "fpr": c["fp"] / b if b else None}
        res["arms"][arm] = r
    return res


def mean(vals):
    vals = [v for v in vals if v is not None]
    return st.mean(vals) if vals else None


def hw(vals):
    """95% half-width of the mean across seeds (normal approx; use >= 20 seeds)."""
    v = [x for x in vals if x is not None]
    return 1.96 * st.stdev(v) / len(v) ** 0.5 if len(v) > 1 else None


def aggregate(runs):
    agg: dict = {}
    for arm in runs[0]["arms"]:
        a = agg.setdefault(arm, {"rules_n": mean([len(r["arms"][arm]["rules"]) for r in runs])})
        for split in ("iid", "ood"):
            keys = runs[0]["arms"][arm][split].keys()
            a[split] = {k: {m: mean([r["arms"][arm][split][k][m] for r in runs]) for m in ("tpr", "fpr")} for k in keys}
        a["hw"] = {split: {k: {m: hw([r["arms"][arm][split][k][m] for r in runs]) for m in ("tpr", "fpr")}
                           for k in runs[0]["arms"][arm][split]} for split in ("iid", "ood")}
        fams = runs[0]["arms"][arm]["ood_family"].keys()
        a["ood_family"] = {f: mean([r["arms"][arm]["ood_family"][f] for r in runs]) for f in fams}
        a["ext"] = {n: {m: mean([r["arms"][arm]["ext"][n][m] for r in runs]) for m in ("tpr", "fpr")} for n in EXT_OOD}
    return agg


def fmt(x):
    return "  - " if x is None else f"{x:4.0%}"


def report(agg, levels):
    for split in ("iid", "ood"):
        print(f"\n== {split} TPR by level (ASR = 1-TPR) | FPR benign / hard-negative ==")
        print(f"{'arm':20}" + "".join(f"{lv:>6}" for lv in levels) + "   FPR benign  hard_dir  hard_edu derived  quote breadth")
        for arm, a in agg.items():
            row = a[split]
            tpr = "".join(f"{fmt(row[f'{lv}|attack']['tpr']):>6}" for lv in levels)
            fb = mean([row[f"{lv}|benign"]["fpr"] for lv in levels])
            hd, he = (row.get(f"{levels[0]}|hard_dir", {}).get("fpr"), row.get(f"{levels[0]}|hard_edu", {}).get("fpr"))
            br = row.get(f"{levels[0]}|hard_breadth", {}).get("fpr")
            hv = row.get(f"{levels[0]}|hard_derived", {}).get("fpr")
            hq = row.get(f"{levels[0]}|hard_quote", {}).get("fpr")
            print(f"{arm:20}{tpr}   {fmt(fb):>10}  {fmt(hd):>8}  {fmt(he):>8}  {fmt(hv):>7} {fmt(hq):>6} {fmt(br):>7}")
    print("\n== ood TPR by attack family (all levels pooled) ==")
    fams = list(next(iter(agg.values()))["ood_family"])
    print(f"{'arm':20}" + "".join(f"{f:>11}" for f in fams))
    for arm, a in agg.items():
        print(f"{arm:20}" + "".join(f"{fmt(a['ood_family'][f]):>11}" for f in fams))
    print("\n== external OOD (TPR / FPR) ==")
    print(f"{'arm':20}" + "".join(f"{n:>22}" for n in EXT_OOD))
    for arm, a in agg.items():
        print(f"{arm:20}" + "".join(f"{fmt(a['ext'][n]['tpr']) + ' /' + fmt(a['ext'][n]['fpr']):>22}" for n in EXT_OOD))


def headline(agg, levels):
    """Mean +- 95% half-width across seeds, OOD split (held-out families and domains)."""
    pm = lambda m, h: "  -  " if m is None else (f"{m:4.0%}" + (f"±{h*100:.0f}" if h else ""))  # noqa: E731
    print(f"\n== headline: OOD TPR per level, mean±95% over seeds ==")
    print(f"{'arm':26}" + "".join(f"{lv:>9}" for lv in levels) + f"{'benign FPR':>12}{'hard_dir':>10}{'breadth':>10}")
    for arm, a in agg.items():
        row, h = a["ood"], a["hw"]["ood"]
        cells = "".join(f"{pm(row[f'{lv}|attack']['tpr'], h[f'{lv}|attack']['tpr']):>9}" for lv in levels)
        def f(k):
            r = row.get(f"{levels[0]}|{k}", {}); e = h.get(f"{levels[0]}|{k}", {})
            return pm(r.get("fpr"), e.get("fpr"))
        fb = mean([row[f"{lv}|benign"]["fpr"] for lv in levels])
        print(f"{arm:26}{cells}{pm(fb, None):>12}{f('hard_dir'):>10}{f('hard_breadth'):>10}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--seeds", type=int, default=5)
    ap.add_argument("--n", type=int, default=12)
    ap.add_argument("--levels", nargs="*", default=list(S.LEVELS))
    ap.add_argument("--out", default=str(ROOT / "results" / "offline" / "synth_curriculum.json"))
    a = ap.parse_args()
    runs = [run_seed(s, tuple(a.levels), a.n) for s in range(a.seeds)]
    agg = aggregate(runs)
    report(agg, a.levels)
    headline(agg, a.levels)
    Path(a.out).write_text(json.dumps({"seeds": a.seeds, "n_per": a.n, "aggregate": agg,
                                       "rules_seed0": {k: v["rules"] for k, v in runs[0]["arms"].items()}}, indent=2))
    print(f"\nlearned seed0 both/broad/curr: {runs[0]['arms']['both/broad/curr']['rules']}")
    print(f"wrote {a.out}")


if __name__ == "__main__":
    main()
