"""Reference monitor: complete mediation of every tool request."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from .detectors import (
    Finding,
    check_network,
    check_prompt_injection,
    check_secret_in_args,
    check_sensitive_paths,
    check_tcb_invariants,
)
from .policy import SecurityPolicy, TrustLevel
from .roles import TaskIdentity, tool_allowed


@dataclass(frozen=True)
class ToolRequest:
    tool: str
    args: dict[str, Any]
    # Provenance of any content that influenced this call
    data_channel: str | None = None  # raw external text if any
    data_trust: TrustLevel = TrustLevel.USER


@dataclass(frozen=True)
class Decision:
    allowed: bool
    findings: tuple[Finding, ...]
    latency_ms: float
    reason: str


@dataclass
class AuditEntry:
    tool: str
    allowed: bool
    reason: str
    findings: tuple[Finding, ...]
    latency_ms: float
    ts: float = field(default_factory=time.time)


class ReferenceMonitor:
    """Deterministic approve/deny gate — lives inside the TCB."""

    def __init__(self, policy: SecurityPolicy) -> None:
        self.policy = policy
        self.audit: list[AuditEntry] = []
        self.calls_seen = 0
        self.calls_bypassed = 0  # should stay 0 if runtime is correct

    def check(self, identity: TaskIdentity, req: ToolRequest) -> Decision:
        t0 = time.perf_counter()
        self.calls_seen += 1
        findings: list[Finding] = []

        if not tool_allowed(identity, req.tool, self.policy):
            findings.append(
                Finding(
                    "rbac",
                    "block",
                    f"role '{identity.role}' lacks capability for tool '{req.tool}'",
                )
            )

        findings.extend(check_network(req.tool, req.args, self.policy.network))
        findings.extend(check_secret_in_args(req.args))
        findings.extend(check_sensitive_paths(req.tool, req.args, self.policy))
        findings.extend(
            check_tcb_invariants(
                req.tool,
                req.args,
                req.data_channel,
                req.data_trust,
                self.policy.content,
            )
        )

        if req.data_channel:
            findings.extend(
                check_prompt_injection(
                    req.data_channel, req.data_trust, self.policy.content
                )
            )

        blocks = [f for f in findings if f.severity == "block"]
        allowed = len(blocks) == 0
        reason = "ok" if allowed else "; ".join(f.reason for f in blocks)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        decision = Decision(
            allowed=allowed,
            findings=tuple(findings),
            latency_ms=latency_ms,
            reason=reason,
        )
        self.audit.append(
            AuditEntry(
                tool=req.tool,
                allowed=allowed,
                reason=reason,
                findings=decision.findings,
                latency_ms=latency_ms,
            )
        )
        return decision

    def mark_bypass(self) -> None:
        """Runtime must call this if a tool ran without check — for metrics."""
        self.calls_bypassed += 1
