"""Trusted Computing Base: only path from untrusted agent → tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from .learning import LearningStore
from .policy import SecurityPolicy, TrustLevel, default_policy
from .reference_monitor import Decision, ReferenceMonitor, ToolRequest
from .roles import TaskIdentity, authenticate_task, privilege_surface


ToolHandler = Callable[[dict[str, Any]], Any]


@dataclass
class ToolResult:
    ok: bool
    decision: Decision
    output: Any = None
    error: str | None = None


class SecurityTCB:
    """
    Complete mediation: agents never hold raw tool handles.
    Every call: authN/task-role → reference monitor → (optional) tool.
    """

    def __init__(
        self,
        policy: SecurityPolicy | None = None,
        tools: dict[str, ToolHandler] | None = None,
    ) -> None:
        self.policy = policy or default_policy()
        self.monitor = ReferenceMonitor(self.policy)
        self.learning = LearningStore()
        self._tools: dict[str, ToolHandler] = tools or {}
        self.identity: TaskIdentity | None = None

    def begin_task(self, principal: str, task: str, *, role: str | None = None) -> TaskIdentity:
        self.identity = authenticate_task(principal, task, self.policy, role_override=role)
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
    ) -> ToolResult:
        if self.identity is None:
            raise RuntimeError("begin_task() required before tool use")
        req = ToolRequest(
            tool=tool,
            args=args,
            data_channel=data_channel,
            data_trust=data_trust,
        )
        decision = self.monitor.check(self.identity, req)
        if not decision.allowed:
            return ToolResult(ok=False, decision=decision, error=decision.reason)
        handler = self._tools.get(tool)
        if handler is None:
            return ToolResult(
                ok=False,
                decision=decision,
                error=f"tool '{tool}' not registered",
            )
        try:
            out = handler(args)
        except Exception as e:  # noqa: BLE001 — sandbox boundary
            return ToolResult(ok=False, decision=decision, error=str(e))
        return ToolResult(ok=True, decision=decision, output=out)

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
