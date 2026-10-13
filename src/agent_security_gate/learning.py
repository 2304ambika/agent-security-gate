"""Policy improvisation from confirmed incidents (still deterministic)."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from .policy import SecurityPolicy
from .reference_monitor import Decision, ToolRequest


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
        """Called when an attack slipped through — promote new rules."""
        self.confirmed_attacks.append(note)
        host = None
        for key in ("url", "host", "hostname", "target", "domain"):
            if key in req.args and isinstance(req.args[key], str):
                host = req.args[key]
                break
        cmd = str(req.args.get("command") or "")
        m = re.search(r"(?i)([a-z0-9.-]+\.(?:attacker|evil|badcdn)[a-z0-9.-]*)", cmd)
        if m:
            host = m.group(1)
        if host:
            h = host.lower().split("/")[-1]
            if "://" in host:
                from urllib.parse import urlparse

                h = (urlparse(host).hostname or h).lower()
            policy.with_blocked_host(h)
            self.learned_hosts.append(h)

        if req.data_channel:
            # extract a short distinctive phrase as a learned pattern
            snippet = req.data_channel.strip().split("\n")[0][:60]
            if snippet and len(snippet) >= 8:
                pat = re.escape(snippet)
                policy.with_learned_injection_pattern(pat)
                self.learned_patterns.append(pat)

    def should_recheck(self, decision: Decision) -> bool:
        return not decision.allowed
