"""Policy improvisation from confirmed false negatives (still deterministic)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from .policy import SecurityPolicy
from .reference_monitor import Decision, ToolRequest

_HOST_RE = re.compile(
    r"(?i)\b((?:[a-z0-9-]+\.)+[a-z]{2,})(?:[:/]\S*)?"
)
_URL_RE = re.compile(r"(?i)https?://[^\s\"'<>]+")


def _norm_host(raw: str) -> str | None:
    h = raw.strip().lower()
    if "://" in h:
        h = urlparse(h).hostname or ""
    h = h.split("/")[0].split(":")[0]
    if not h or h in {"localhost", "127.0.0.1"} or "." not in h:
        return None
    return h


def _hosts_from_text(text: str) -> set[str]:
    found: set[str] = set()
    for m in _URL_RE.finditer(text):
        h = _norm_host(m.group(0))
        if h:
            found.add(h)
    for m in _HOST_RE.finditer(text):
        h = _norm_host(m.group(1))
        if h:
            found.add(h)
    return found


def _pattern_snippets(data: str) -> list[str]:
    """Distinctive substrings to promote after a confirmed FN."""
    out: list[str] = []
    lines = [ln.strip() for ln in data.splitlines() if ln.strip()]
    if lines:
        out.append(lines[0][:80])
    # Also keep short imperative-looking fragments
    for ln in lines[:4]:
        if len(ln) >= 12 and ln not in out:
            out.append(ln[:80])
    return out


@dataclass
class LearningStore:
    """Append-only lessons that harden the policy without leaving the TCB."""

    confirmed_attacks: list[str] = field(default_factory=list)
    learned_patterns: list[str] = field(default_factory=list)
    learned_hosts: list[str] = field(default_factory=list)

    def absorb_false_negative(
        self,
        policy: SecurityPolicy,
        req: ToolRequest,
        note: str,
    ) -> None:
        """Trusted teacher (bench label / human): promote hosts + data snippets."""
        self.confirmed_attacks.append(note)
        blobs = [str(v) for v in req.args.values() if isinstance(v, str)]
        if req.data_channel:
            blobs.append(req.data_channel)
        text = "\n".join(blobs)

        allowed = set(policy.network.allowed_hosts)
        for h in _hosts_from_text(text):
            # Do not revoke currently allowlisted destinations from one FN
            if h in allowed:
                continue
            policy.with_blocked_host(h)
            if h not in self.learned_hosts:
                self.learned_hosts.append(h)

        if req.data_channel:
            for snippet in _pattern_snippets(req.data_channel):
                if len(snippet) < 8:
                    continue
                pat = re.escape(snippet)
                if pat in self.learned_patterns:
                    continue
                policy.with_learned_injection_pattern(pat)
                self.learned_patterns.append(pat)

    def should_recheck(self, decision: Decision) -> bool:
        return not decision.allowed
