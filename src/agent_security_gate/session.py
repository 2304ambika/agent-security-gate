"""History-aware gating state: TCB-side provenance, taint, and risk tiers.

The caller no longer has to label provenance. Whatever an ingest tool returned is
tracked here as EXTERNAL, and later effect-capable calls are checked against it
(idea 1: gate the calls where a breach can happen, using what the session has seen).
"""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field
from urllib.parse import unquote

from .detectors import Finding
from .policy import SecurityPolicy

# Tools whose output is untrusted data entering the agent's context.
INGEST_TOOLS = frozenset(
    {"http_fetch", "browser_navigate", "read_file", "mcp_invoke", "agent_message"}
)
# Capabilities that change the world (not read-only).
EFFECT_CAPS = frozenset(
    {
        "comms", "shell", "memory_write", "filesystem_write", "filesystem_delete",
        "browser_write", "a2a", "network_expose", "clipboard", "admin", "mcp",
    }
)
# Tools that can carry data out of the process.
EGRESS_TOOLS = frozenset(
    {
        "http_fetch", "browser_navigate", "browser_submit", "send_email",
        "dns_lookup", "ping", "mcp_invoke", "agent_message", "shell_exec",
    }
)
_MAX_AMBIENT = 20_000

_URL = re.compile(r"(?i)https?://[^\s\"'<>)\]]+")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_HOST = re.compile(
    r"(?i)\b(?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|ai|co|xyz|ru|cn|test|sh|app)\b"
)
_PATH = re.compile(r"(?<![\w:/.])(?:~|\.{0,2})/(?:[\w.-]+/)+[\w.-]+")
_WINPATH = re.compile(r"(?i)\b[a-z]:[\\/](?:[\w.-]+[\\/])+[\w.-]+")
_SECRET = re.compile(
    r"(?i)(sk-[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}"
    r"|(?:api[_-]?key|secret|password|token)\s*[=:]\s*[^\s\"']{8,}"
    r"|-----BEGIN [A-Z ]*PRIVATE KEY-----[^-]{8,})"
)


def risk_tier(tool: str, policy: SecurityPolicy) -> str:
    """'high' when the call can change state or move data out; unknown tools are high."""
    cap = policy.tool_roles.get(tool)
    if cap is None or cap in EFFECT_CAPS:
        return "high"
    return "high" if tool in {"dns_lookup", "ping", "browser_submit", "send_email"} else "low"


def _norm_email(e: str) -> str:
    local, _, dom = e.lower().partition("@")
    return f"{local.split('+')[0]}@{dom}"


def _squash(t: str) -> str:
    return re.sub(r"[^a-z0-9]", "", t.lower())


def _forms(frag: str) -> list[str]:
    """Raw + common encodings of a secret fragment, plus 10-char windows (partial leaks)."""
    b = frag.encode()
    out = {frag, base64.b64encode(b).decode(), base64.urlsafe_b64encode(b).decode().rstrip("="), b.hex(), frag[::-1]}
    w = max(10, len(frag) // 2)
    out |= {frag[i : i + w] for i in range(0, max(1, len(frag) - w + 1))}
    return [f.lower() for f in out if len(f) >= 8]


@dataclass
class SessionState:
    task_text: str = ""
    ambient: list[tuple[str, str]] = field(default_factory=list)  # (source, text)
    secret_fragments: set[str] = field(default_factory=set)
    suspicious: bool = False  # instruction-like text seen in untrusted content
    history: list[tuple[str, str]] = field(default_factory=list)  # (tool, tier)

    def ingest(self, source: str, text: str) -> None:
        if not text:
            return
        self.ambient.append((source, text))
        while sum(len(t) for _, t in self.ambient) > _MAX_AMBIENT and len(self.ambient) > 1:
            self.ambient.pop(0)

    def ambient_text(self) -> str:
        return "\n".join(t for _, t in self.ambient)

    def observe_output(self, tool: str, output: object, ingest: bool) -> None:
        text = str(output)
        if ingest:
            self.ingest(tool, text)
        for m in _SECRET.finditer(text):
            s = m.group(0)
            self.secret_fragments.add(s)
            val = re.split(r"[=:]\s*", s, maxsplit=1)[-1]
            if len(val) >= 8:
                self.secret_fragments.add(val)

    def tainted_tokens(self, policy: SecurityPolicy) -> set[str]:
        """Identifiers (URLs, e-mails, hosts, paths) from untrusted content that the user task did not name.

        E-mails are stored normalized (lower-case, +tag removed); paths use '/' and lower-case.
        """
        text = unquote(self.ambient_text())
        toks = {m.group(0).rstrip(".,;)").lower() for m in _URL.finditer(text)}
        toks |= {_norm_email(m.group(0)) for m in _EMAIL.finditer(text)}
        toks |= {m.group(0).lower() for m in _HOST.finditer(text)}
        toks |= {m.group(0).lower() for m in _PATH.finditer(text)}
        toks |= {m.group(0).lower().replace("\\", "/") for m in _WINPATH.finditer(text)}
        task = unquote(self.task_text).lower().replace("\\", "/")
        task_emails = {_norm_email(m.group(0)) for m in _EMAIL.finditer(task)}
        allowed = policy.network.allowed_hosts
        keep = set()
        for t in toks:
            if t in task or t in task_emails:
                continue
            if "@" in t or t.startswith(("/", "~", ".")) or re.match(r"[a-z]:/", t):
                keep.add(t)  # recipients and paths are never exempted by the host allowlist
                continue
            host = re.sub(r"^https?://", "", t).split("/")[0]
            if host in allowed or any(host.endswith("." + a) for a in allowed):
                continue
            keep.add(t)
        return keep


def session_findings(
    s: SessionState, tool: str, args: dict, policy: SecurityPolicy
) -> list[Finding]:
    out: list[Finding] = []
    raw = " ".join(str(v) for v in args.values())
    blob = unquote(raw).lower().replace("\\", "/")
    squashed = _squash(blob)

    # H3: secret seen earlier in this session must not leave via any egress route (any encoding).
    if s.secret_fragments and tool in EGRESS_TOOLS:
        for frag in s.secret_fragments:
            sq = _squash(frag)
            if any(f in blob for f in _forms(frag)) or (len(sq) >= 8 and sq in squashed):
                out.append(Finding("secret_taint", "block", "value read earlier from a secret source reaches an egress call"))
                break

    cap = policy.tool_roles.get(tool)
    if cap not in EFFECT_CAPS and tool not in {"send_email", "browser_submit"}:
        return out

    # H4: untrusted content in this session carried instruction-like text -> quarantine effects.
    if s.suspicious:
        out.append(Finding("session_quarantine", "block", "session ingested instruction-like untrusted content; effect-capable call needs re-authorization"))

    # H2: identifier in an effect argument came from untrusted content, not from the user task.
    arg_emails = {_norm_email(m.group(0)) for m in _EMAIL.finditer(blob)}
    for tok in s.tainted_tokens(policy):
        if tok in blob or tok in arg_emails:
            out.append(Finding("taint_flow", "block", "argument value derived from untrusted content (absent from user task)", tok[:60]))
            break
    return out
