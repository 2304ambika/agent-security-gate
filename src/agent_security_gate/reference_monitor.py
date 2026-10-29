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
from .session import SessionState, risk_tier, session_findings


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
    tier: str = "high"
    deep_scan: bool = True  # False = injection scan deferred (adaptive mode, low-risk call)


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
        self.deep_scans = 0
        self.deep_scans_deferred = 0

    def check(
        self,
        identity: TaskIdentity,
        req: ToolRequest,
        session: SessionState | None = None,
        adaptive: bool = False,
    ) -> Decision:
        """Stateless when session is None. With a session: provenance is tracked here
        (not by the caller), and adaptive=True defers the injection scan on low-risk calls
        to the next effect boundary (the ingested text stays in the session)."""
        t0 = time.perf_counter()
        self.calls_seen += 1
        findings: list[Finding] = []
        tier, ctx, trust = "high", req.data_channel, req.data_trust
        if session is not None:
            tier = "high" if session.suspicious else risk_tier(req.tool, self.policy)
            if req.data_channel and req.data_trust == TrustLevel.EXTERNAL:
                session.ingest("caller", req.data_channel)
            elif not req.data_channel and session.ambient:
                ctx, trust = session.ambient_text(), TrustLevel.EXTERNAL
        deep = not (adaptive and tier == "low")

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
                ctx,
                trust,
                self.policy.content,
            )
        )

        if ctx and deep:
            self.deep_scans += 1
            inj = check_prompt_injection(ctx, trust, self.policy.content)
            findings.extend(inj)
            if inj and session is not None:
                session.suspicious = True
        elif ctx:
            self.deep_scans_deferred += 1
        if session is not None:
            findings.extend(session_findings(session, req.tool, req.args, self.policy))
            session.history.append((req.tool, tier))

        blocks = [f for f in findings if f.severity == "block"]
        allowed = len(blocks) == 0
        reason = "ok" if allowed else "; ".join(f.reason for f in blocks)
        latency_ms = (time.perf_counter() - t0) * 1000.0
        decision = Decision(
            allowed=allowed,
            findings=tuple(findings),
            latency_ms=latency_ms,
            reason=reason,
            tier=tier,
            deep_scan=deep,
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
