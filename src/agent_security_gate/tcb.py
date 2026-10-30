"""Trusted Computing Base: only path from untrusted agent → tools."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Callable

from .learning import LearningStore
from .policy import SecurityPolicy, TrustLevel, default_policy
from .reference_monitor import Decision, ReferenceMonitor, ToolRequest
from .roles import TaskIdentity, authenticate_task, privilege_surface
from .session import INGEST_TOOLS, SessionState


ToolHandler = Callable[[dict[str, Any]], Any]

log = logging.getLogger("agent_security_gate")


def _short(v: Any, n: int = 160) -> str:
    s = repr(v)
    return s if len(s) <= n else s[:n] + "..."


@dataclass
class ToolResult:
    ok: bool
    decision: Decision
    output: Any = None
    error: str | None = None
    redacted: int = 0  # ungrounded links/addresses removed from free-text arguments before execution


class SecurityTCB:
    """
    Complete mediation: agents never hold raw tool handles.
    Every call: authN/task-role → reference monitor → (optional) tool.
    """

    def __init__(
        self,
        policy: SecurityPolicy | None = None,
        tools: dict[str, ToolHandler] | None = None,
        learn_online: bool = False,
        session_tracking: bool = False,
        adaptive: bool = False,
    ) -> None:
        self.learn_online = learn_online
        self.session_tracking = session_tracking
        self.adaptive = adaptive
        self.session: SessionState | None = None
        # (identity, request, decision) awaiting a trusted label; see PolicyUpdater.review
        self.audit_queue: list[tuple[TaskIdentity, ToolRequest, Decision]] = []
        self.policy = policy or default_policy()
        self.monitor = ReferenceMonitor(self.policy)
        self.learning = LearningStore()
        self._tools: dict[str, ToolHandler] = tools or {}
        self.identity: TaskIdentity | None = None
        self._seq = 0

    def begin_task(self, principal: str, task: str, *, role: str | None = None) -> TaskIdentity:
        self.identity = authenticate_task(principal, task, self.policy, role_override=role)
        self.session = SessionState(task_text=task) if self.session_tracking else None
        log.info(
            "TASK principal=%s task=%r role=%s caps=%s",
            principal, task, self.identity.role, sorted(self.identity.capabilities),
        )
        return self.identity

    def register_tool(self, name: str, handler: ToolHandler) -> None:
        self._tools[name] = handler

    def invoke(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        data_channel: str | None = None,
        data_trust: TrustLevel = TrustLevel.USER,
        expect_allow: bool | None = None,
    ) -> ToolResult:
        """expect_allow: what policy *should* do; logged against the actual decision."""
        if self.identity is None:
            raise RuntimeError("begin_task() required before tool use")
        self._seq += 1
        n = self._seq
        log.info("[#%d] INPUT   tool=%s args=%s", n, tool, _short(args))
        if data_channel:
            log.info(
                "[#%d] INPUT   data_trust=%s data_channel=%s",
                n, data_trust.value, _short(data_channel),
            )
        req = ToolRequest(
            tool=tool,
            args=args,
            data_channel=data_channel,
            data_trust=data_trust,
        )
        decision = self.monitor.check(
            self.identity, req, session=self.session, adaptive=self.adaptive
        )
        if len(self.audit_queue) < 1000:
            self.audit_queue.append((self.identity, req, decision))
        for f in decision.findings:
            log.info(
                "[#%d] FINDING %s severity=%s reason=%s",
                n, f.detector, f.severity, f.reason,
            )
        verdict = "ALLOW" if decision.allowed else "DENY"
        log.info(
            "[#%d] DECISION %s (%.2fms) reason=%s", n, verdict, decision.latency_ms, decision.reason
        )
        if expect_allow is not None:
            match = expect_allow == decision.allowed
            log.log(
                logging.INFO if match else logging.ERROR,
                "[#%d] EXPECTED %s ACTUAL %s -> %s",
                n, "ALLOW" if expect_allow else "DENY", verdict,
                "MATCH" if match else "MISMATCH",
            )
        if self.learn_online and expect_allow is False and decision.allowed:
            # False negative caught by the teacher label: withhold execution, harden policy.
            self.report_missed_attack(
                tool, args, note=f"online-fn:#{n}:{tool}", data=data_channel
            )
            log.warning("[#%d] HARNESS FN intercepted, tool NOT executed; policy updated", n)
            return ToolResult(
                ok=False, decision=decision, error="intercepted: false negative, policy updated"
            )
        if not decision.allowed:
            log.info("[#%d] HARNESS tool NOT executed (blocked by monitor)", n)
            return ToolResult(ok=False, decision=decision, error=decision.reason)
        redacted = 0
        slots = [a for t, a in self.policy.content.redact_slots if t == tool and isinstance(args.get(a), str)]
        ctx = data_channel if data_trust == TrustLevel.EXTERNAL and data_channel else (self.session.ambient_text() if self.session else "")
        if slots and ctx:
            from .features import redact_ungrounded

            args = dict(args)
            for a in slots:
                args[a], n = redact_ungrounded(args[a], self.identity.task, ctx, tool)
                redacted += n
        handler = self._tools.get(tool)
        if handler is None:
            log.info("[#%d] HARNESS tool NOT executed (not registered)", n)
            return ToolResult(
                ok=False,
                decision=decision,
                error=f"tool '{tool}' not registered",
            )
        try:
            out = handler(args)
        except Exception as e:  # noqa: BLE001 — sandbox boundary
            log.info("[#%d] HARNESS tool executed, raised %s", n, _short(e))
            return ToolResult(ok=False, decision=decision, error=str(e))
        log.info("[#%d] HARNESS tool executed, output=%s", n, _short(out))
        if self.session is not None:
            self.session.observe_output(tool, out, ingest=tool in INGEST_TOOLS)
        return ToolResult(ok=True, decision=decision, output=out, redacted=redacted)

    def report_missed_attack(self, tool: str, args: dict[str, Any], note: str, data: str | None = None) -> None:
        """Feedback loop: harden policy after a confirmed false negative."""
        req = ToolRequest(tool=tool, args=args, data_channel=data, data_trust=TrustLevel.EXTERNAL)
        self.learning.absorb_false_negative(self.policy, req, note)

    def privilege_count(self) -> int:
        if self.identity is None:
            return 0
        return len(privilege_surface(self.identity, self.policy))

    def unrestricted_tool_count(self) -> int:
        return len(self.policy.tool_roles)
