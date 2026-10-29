"""Verified, monotone policy updates (idea 2). Still deterministic, still outside the model.

propose -> verify on a benign regression corpus -> activate -> ledger (rollback-able)

Only narrowing rules are ever generated: blocked hosts and injection patterns. Allowlists,
roles and TCB invariants are never touched; relaxing requests are queued for a human.
Design follows the gate-evolution loops in HARD / VEPA / Progent (see docs), kept small.
"""

from __future__ import annotations

import copy
import json
import re
import time
from dataclasses import asdict, dataclass, field, replace
from pathlib import Path
from typing import Callable, Sequence

from .detectors import _views
from .learning import _hosts_from_text
from .policy import SecurityPolicy, TrustLevel
from .reference_monitor import Decision, ReferenceMonitor, ToolRequest
from .roles import TaskIdentity

BenignCase = tuple[TaskIdentity, ToolRequest]
Teacher = Callable[[TaskIdentity, ToolRequest], "bool | None"]  # True=attack, False=benign, None=unknown

_WORD = re.compile(r"[A-Za-z][A-Za-z0-9_]{4,}")
_STOP = frozenset(
    "about after again before being could every first other should their there these "
    "thing those through under until using which while would please window".split()
)


@dataclass
class VersionRecord:
    version: int
    parent: int | None
    kind: str  # block_host | injection_pattern | rollback
    value: str
    evidence: str
    accepted: bool
    reason: str
    regressions: int = 0
    ts: float = field(default_factory=time.time)


def _distinctive(w: str) -> bool:
    return "_" in w or w.isupper() or any(c.isdigit() for c in w)


def _all_of(words: Sequence[str]) -> str:
    """Order-insensitive, case-insensitive: every word must occur (survives re-ordering)."""
    return "(?is)\\A" + "".join(rf"(?=.*\b{re.escape(w)}\b)" for w in words)


class PolicyUpdater:
    def __init__(
        self,
        policy: SecurityPolicy,
        benign_corpus: Sequence[BenignCase] = (),
        *,
        fp_budget: int = 0,
        min_words: int = 2,
    ) -> None:
        self.policy = policy
        self.corpus = list(benign_corpus)
        self.fp_budget = fp_budget
        self.min_words = min_words
        self.ledger: list[VersionRecord] = []
        self.expansion_requests: list[tuple[str, str]] = []  # never auto-applied
        self.unlearnable = 0
        self._rejected: set[str] = set()  # patterns already refused; skip re-verification
        self._head = 0
        self._snap: dict[int, tuple[frozenset, frozenset]] = {0: self._state()}
        self._vocab = self._benign_vocab()
        self._allowed: list[int] | None = None  # corpus indices the live policy allows (cache)
        self._view_cache: dict[int, list[str]] = {}

    # ---- verification -------------------------------------------------
    def _state(self) -> tuple[frozenset, frozenset]:
        return self.policy.network.blocked_hosts, self.policy.content.extra_injection_patterns

    def _benign_vocab(self) -> set[str]:
        text = " ".join(
            " ".join([str(v) for v in r.args.values()] + [r.data_channel or ""])
            for _, r in self.corpus
        )
        return {w.lower() for w in _WORD.findall(text)}

    def _regressions(self, candidate: SecurityPolicy) -> int:
        """Benign requests the live policy allows but the candidate would block."""
        if self._allowed is None:
            live = ReferenceMonitor(self.policy)
            self._allowed = [i for i, (ident, req) in enumerate(self.corpus) if live.check(ident, req).allowed]
        after = ReferenceMonitor(candidate)
        return sum(1 for i in self._allowed if not after.check(*self.corpus[i]).allowed)

    def _pattern_regressions(self, pat: str) -> int:
        """A new injection pattern can only add findings via the injection scan: test just that."""
        if self._allowed is None:
            self._regressions(self.policy)  # fills the allowed-index cache
        n = 0
        for i in self._allowed or []:
            _, req = self.corpus[i]
            if req.data_channel and req.data_trust == TrustLevel.EXTERNAL:
                if i not in self._view_cache:
                    self._view_cache[i] = _views(req.data_channel)
                if any(re.search(pat, v, re.I) for v in self._view_cache[i]):
                    n += 1
        return n

    def _host_regressions(self, host: str) -> int:
        """A new blocked host only matters to calls that mention it in their arguments."""
        if self._allowed is None:
            self._regressions(self.policy)
        return sum(
            1 for i in self._allowed or []
            if host in " ".join(str(v) for v in self.corpus[i][1].args.values()).lower()
        )

    def _try(
        self, kind: str, value: str, evidence: str, mutate: Callable[[SecurityPolicy], None],
        pattern: str | None = None, host: str | None = None,
    ) -> bool:
        if pattern is not None:
            reg = self._pattern_regressions(pattern)
        elif host is not None:
            reg = self._host_regressions(host)
        else:
            cand = copy.deepcopy(self.policy)
            mutate(cand)
            reg = self._regressions(cand)
        ok = reg <= self.fp_budget
        rec = VersionRecord(
            version=len(self.ledger) + 1,
            parent=self._head,
            kind=kind,
            value=value[:200],
            evidence=evidence,
            accepted=ok,
            reason="ok" if ok else f"regresses {reg} benign case(s)",
            regressions=reg,
        )
        self.ledger.append(rec)
        if ok:
            mutate(self.policy)
            self._head = rec.version
            self._snap[rec.version] = self._state()
            if reg:  # budget > 0: some benign calls are now blocked, so the allowed-set changed
                self._allowed = None
        return ok

    # ---- proposals ----------------------------------------------------
    def candidates(self, text: str) -> list[str]:
        """Most general first; each candidate matches `text` itself."""
        words: dict[str, str] = {}
        for w in _WORD.findall(text):
            lw = w.lower()
            if lw not in _STOP and lw not in self._vocab:
                words.setdefault(lw, w)
        ranked = sorted(words.values(), key=lambda w: (not _distinctive(w), -len(w)))[:4]
        out: list[str] = []
        if ranked and _distinctive(ranked[0]):
            out.append(_all_of(ranked[:1]))
        for k in range(max(self.min_words, 2), len(ranked) + 1):
            out.append(_all_of(ranked[:k]))
        first = next((ln.strip() for ln in text.splitlines() if ln.strip()), "")[:80]
        if len(first) >= 8:
            out.append(re.escape(first))  # verbatim fallback = old behaviour
        return list(dict.fromkeys(p for p in out if re.search(p, text, re.I)))

    def learn_batch(self, batch: Sequence[tuple[ToolRequest, str]], min_support: int = 2) -> None:
        """Learn from many FNs at once; an injection pattern must match >= min_support FN texts.

        Single-example rules memorize one phrasing; requiring support from a second, different
        FN text is the cheap guard against that. Hosts need no support (a host is an exact fact).
        """
        pool = [r.data_channel for r, _ in batch if r.data_channel and r.data_trust == TrustLevel.EXTERNAL]
        for req, ev in batch:
            self.learn_from_fn(req, ev, support_pool=pool, min_support=min_support)

    def learn_from_fn(
        self, req: ToolRequest, evidence: str, *, support_pool: Sequence[str] = (), min_support: int = 1
    ) -> list[VersionRecord]:
        """A confirmed false negative: add at most one host rule per host and one pattern."""
        start = len(self.ledger)
        blobs = [str(v) for v in req.args.values() if isinstance(v, str)] + [req.data_channel or ""]
        allowed = set(self.policy.network.allowed_hosts)
        learned = False
        for h in sorted(_hosts_from_text("\n".join(blobs))):
            if h in allowed or h in self.policy.network.blocked_hosts:
                continue
            learned |= self._try("block_host", h, evidence, lambda p, h=h: p.with_blocked_host(h), host=h)
        if req.data_channel and req.data_trust == TrustLevel.EXTERNAL:
            for pat in self.candidates(req.data_channel):
                if pat in self.policy.content.extra_injection_patterns:
                    learned = True
                    break
                if pat in self._rejected:
                    continue
                if min_support > 1 and sum(1 for t in support_pool if re.search(pat, t, re.I)) < min_support:
                    continue  # too specific: matches a single FN text only
                if self._try("injection_pattern", pat, evidence, lambda p, pat=pat: p.with_learned_injection_pattern(pat), pattern=pat):
                    learned = True
                    break
                self._rejected.add(pat)
        if not learned:
            self.unlearnable += 1  # structural miss: needs a new detector, not a rule
        return self.ledger[start:]

    # ---- continuous harness ------------------------------------------
    def review(
        self, queue: list[tuple[TaskIdentity, ToolRequest, Decision]], teacher: Teacher
    ) -> dict[str, int]:
        """Drain the TCB audit queue with a trusted labeller (human, offline judge, effect checker)."""
        stats = {"fn_learned": 0, "fp_flagged": 0, "unlabelled": 0}
        for ident, req, dec in queue:
            label = teacher(ident, req)
            if label is None:
                stats["unlabelled"] += 1
            elif label and dec.allowed:
                self.learn_from_fn(req, f"review:{req.tool}")
                stats["fn_learned"] += 1
            elif not label and not dec.allowed:
                self.expansion_requests.append((req.tool, dec.reason))  # human decides
                stats["fp_flagged"] += 1
        queue.clear()
        return stats

    # ---- versioning ---------------------------------------------------
    def rollback(self, version: int) -> None:
        hosts, pats = self._snap[version]
        self.policy.network = replace(self.policy.network, blocked_hosts=hosts)
        self.policy.content = replace(self.policy.content, extra_injection_patterns=pats)
        self.ledger.append(
            VersionRecord(len(self.ledger) + 1, self._head, "rollback", str(version), "operator", True, "ok")
        )
        self._head = version
        self._allowed = None

    def save(self, path: str | Path) -> None:
        Path(path).write_text(json.dumps([asdict(r) for r in self.ledger], indent=2))

    def summary(self) -> dict[str, int]:
        acc = [r for r in self.ledger if r.accepted and r.kind != "rollback"]
        return {
            "proposed": len([r for r in self.ledger if r.kind != "rollback"]),
            "accepted": len(acc),
            "rejected_regression": len([r for r in self.ledger if not r.accepted]),
            "unlearnable_fn": self.unlearnable,
            "expansion_requests": len(self.expansion_requests),
        }
