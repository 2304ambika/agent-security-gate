"""Offline rule induction (idea 2, generalizing variant). Outside the TCB, deterministic, narrowing-only.

Same contract as policy_update.py: propose -> verify on a benign regression corpus -> accept -> ledger.
Two action spaces, both closed (no free-form code, nothing that can widen access):
  text rule  conjunction of word-class features that must co-occur in ONE sentence of untrusted text
  slot rule  (tool, arg): that argument must be grounded in the user's task when untrusted content is in context
A candidate is kept only if it covers >= min_support missed attacks from >= min_groups attack families and
blocks <= fp_budget benign calls the live policy currently allows. Greedy set cover (CN2/RIPPER-style).
"""

from __future__ import annotations

from dataclasses import replace
from itertools import combinations
from typing import Any, NamedTuple, Sequence

from .detectors import check_grounding, check_prompt_injection
from .features import FEATURES, extract, fires, ungrounded
from .policy import SecurityPolicy, TrustLevel
from .policy_update import VersionRecord


class Ex(NamedTuple):
    task: str
    text: str  # untrusted content in the acting agent's context
    group: str = ""  # attack family id ("" for benign)
    tool: str = ""
    args: dict[str, Any] | None = None


Cand = tuple[str, tuple[str, ...]]  # ("rule", features) | ("slot", (tool, arg))


def _rules(min_len: int, max_len: int) -> list[Cand]:
    return [("rule", tuple(sorted(c))) for k in range(min_len, max_len + 1) for c in combinations(FEATURES, k)]


class RuleInducer:
    def __init__(
        self,
        policy: SecurityPolicy,
        benign: Sequence[Ex] = (),
        *,
        space: str = "both",  # text | slot | both
        fp_budget: int = 0,
        min_support: int = 3,
        min_groups: int = 2,
        min_len: int = 2,  # single word classes are too broad to verify on a small benign corpus
        max_len: int = 3,
    ) -> None:
        self.policy, self.benign, self.space = policy, list(benign), space
        self.fp_budget, self.min_support, self.min_groups = fp_budget, min_support, min_groups
        self.ledger: list[VersionRecord] = []
        self._rules = _rules(min_len, max_len) if space in ("text", "both") else []
        self._head = 0
        self._seen: list[Any] = []  # signatures of every attack that was a false negative when first seen

    def add_benign(self, more: Sequence[Ex]) -> None:
        self.benign += list(more)

    def _blocked(self, e: Ex) -> bool:
        c = self.policy.content
        if check_prompt_injection(e.text, TrustLevel.EXTERNAL, c, e.task):
            return True
        return bool(e.args and check_grounding(e.tool, e.args, e.task, e.text, TrustLevel.EXTERNAL, c))

    def _sig(self, e: Ex) -> tuple[list[frozenset[str]], frozenset[tuple[str, str]]]:
        viol = frozenset(
            (e.tool, a) for a, v in (e.args or {}).items() if isinstance(v, str) and ungrounded(v, e.task, e.text, e.tool)
        ) if self.space in ("slot", "both") else frozenset()
        return extract(e.text, e.task), viol

    @staticmethod
    def _hit(cand: Cand, sig) -> bool:
        kind, val = cand
        return fires(sig[0], val) if kind == "rule" else val in sig[1]

    def learn(self, attacks: Sequence[Ex]) -> list[VersionRecord]:
        """Learn from attacks the live policy still allows (false negatives)."""
        start = len(self.ledger)
        fns = [(self._sig(e), e.group) for e in attacks if not self._blocked(e)]
        self._seen += [sig for sig, _ in fns]
        allowed = [self._sig(e) for e in self.benign if not self._blocked(e)]
        slots: list[Cand] = sorted({("slot", s) for sig, _ in fns for s in sig[1]})
        rejected: set[Cand] = set()
        have = {("rule", r) for r in self.policy.content.learned_rules} | {("slot", s) for s in self.policy.content.grounded_slots}
        while fns:
            best: tuple[tuple[float, float], Cand, int] | None = None
            for cand in self._rules + slots:
                if cand in rejected or cand in have:
                    continue
                cov = [g for sig, g in fns if self._hit(cand, sig)]
                if len(cov) < self.min_support or len(set(cov)) < self.min_groups:
                    continue
                cost = 0.5 if cand[0] == "slot" else len(cand[1])  # structural slot rules win ties
                key = (len(cov), -cost)
                if best is None or key > best[0]:
                    best = (key, cand, len(cov))
            if best is None:
                break
            _, cand, cov_n = best
            fp = sum(1 for sig in allowed if self._hit(cand, sig))
            ok = fp <= self.fp_budget
            self.ledger.append(VersionRecord(
                version=len(self.ledger) + 1, parent=self._head, kind=f"{cand[0]}_rule",
                value=f"{cand[0]}:" + "+".join(cand[1]), evidence=f"covers {cov_n} FN", accepted=ok,
                reason="ok" if ok else f"regresses {fp} benign case(s)", regressions=fp))
            if not ok:
                rejected.add(cand)
                continue
            if cand[0] == "rule":
                self.policy.with_learned_rule(cand[1])
            else:
                self.policy.with_grounded_slot((cand[1][0], cand[1][1]))
            have.add(cand)
            self._head = self.ledger[-1].version
            fns = [(sig, g) for sig, g in fns if not self._hit(cand, sig)]
            if fp:
                allowed = [sig for sig in allowed if not self._hit(cand, sig)]
        return self.ledger[start:]

    def prune(self) -> list[VersionRecord]:
        """Retire accepted rules that no longer cover any attack the others miss (minimal policy, fewer FP routes).

        Order matters under a curriculum: an early broad text rule can be made redundant by a later structural
        slot rule; without this step it stays and keeps blocking benign text."""
        start = len(self.ledger)
        c = self.policy.content
        elems: list[Cand] = [("rule", r) for r in c.learned_rules] + [("slot", s) for s in c.grounded_slots]

        def covered(es):
            return {i for i, sig in enumerate(self._seen) if any(self._hit(e, sig) for e in es)}

        full = covered(elems)
        for e in sorted(elems, key=lambda e: (len(covered([e])), -len(e[1]))):  # least useful first
            rest = [x for x in elems if x != e]
            if covered(rest) == full:
                elems = rest
                self.policy.content = replace(
                    self.policy.content,
                    learned_rules=frozenset(v for k, v in elems if k == "rule"),
                    grounded_slots=frozenset((v[0], v[1]) for k, v in elems if k == "slot"))
                self.ledger.append(VersionRecord(len(self.ledger) + 1, self._head, "prune", "+".join(e[1]), "redundant", True, "ok"))
                self._head = self.ledger[-1].version
        return self.ledger[start:]

    def summary(self) -> dict[str, int]:
        prop = [r for r in self.ledger if r.kind != "prune"]
        acc = [r for r in prop if r.accepted]
        return {"proposed": len(prop), "accepted": len(acc), "rejected_regression": len(prop) - len(acc),
                "pruned": len(self.ledger) - len(prop)}
