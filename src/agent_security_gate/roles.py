"""Task-scoped role / capability derivation (idea 3, minimal)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Set

from .policy import SecurityPolicy

_TASK_HINTS: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r"\b(shell|terminal|run command|execute)\b", re.I), "coder"),
    (re.compile(r"\b(deploy|ops|ping|dns|network diagnose)\b", re.I), "ops"),
    (re.compile(r"\b(read|summarize|explain|review)\b", re.I), "reader"),
    (re.compile(r"\b(fetch|browse|search|arxiv|web)\b", re.I), "researcher"),
]


@dataclass(frozen=True)
class TaskIdentity:
    """AuthN-lite: who asked + derived role for this task."""

    principal: str
    task: str
    role: str
    capabilities: frozenset[str]


def derive_role(task: str) -> str:
    for pat, role in _TASK_HINTS:
        if pat.search(task):
            return role
    return "reader"


def authenticate_task(
    principal: str,
    task: str,
    policy: SecurityPolicy,
    *,
    role_override: str | None = None,
) -> TaskIdentity:
    role = role_override or derive_role(task)
    caps = frozenset(policy.role_capabilities.get(role, set()))
    return TaskIdentity(principal=principal, task=task, role=role, capabilities=caps)


def tool_allowed(identity: TaskIdentity, tool: str, policy: SecurityPolicy) -> bool:
    required = policy.tool_roles.get(tool)
    if required is None:
        return not policy.deny_by_default
    return required in identity.capabilities


def privilege_surface(identity: TaskIdentity, policy: SecurityPolicy) -> Set[str]:
    return {t for t, need in policy.tool_roles.items() if need in identity.capabilities}
