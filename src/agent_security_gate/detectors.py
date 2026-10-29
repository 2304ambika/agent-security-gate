"""Deterministic detectors — TCB must not rely on an LLM (paper §2.3)."""

from __future__ import annotations

import base64
import re
import unicodedata
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

from .policy import ContentPolicy, NetworkPolicy, SecurityPolicy, TrustLevel

_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|rules?)\b"),
    re.compile(r"(?i)\bignore\s+all\s+prior\s+(rules?|instructions?)\b"),
    re.compile(r"(?i)\bdisregard\s+(your|the)\s+(system|safety)\s+(prompt|rules?)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer|god|jailbreak)\s+mode\b"),
    re.compile(
        r"(?i)\b(exfiltrat|send|leak|upload|export)\b.{0,60}\b(api[_ ]?key|password|secret|\.env|system prompt)\b"
    ),
    re.compile(r"(?i)\bread\s+.{0,20}\.env\b"),
    re.compile(r"(?i)\bping\b.{0,80}\b(attacker|exfil|evil)\b"),
    re.compile(r"(?i)</?\s*system\s*>"),
    re.compile(r"(?i)\[INST\]|<<\s*SYS\s*>>"),
    re.compile(r"(?i)\[SYSTEM\s+OVERRIDE\]|disable\s+all\s+safety\s+checks"),
    re.compile(r"(?i)\b(call|invoke|run)\s+the\s+(deploy|shell|admin)\s+tool\b"),
    re.compile(r"(?i)\bprint\s+(all\s+)?environment\s+variables\b"),
    re.compile(r"(?i)\bskip\s+(the\s+)?approval\b"),
    re.compile(r"(?i)\bNOTE\s+TO\s+AGENT\b"),
    re.compile(r"(?i)\b(always|from now on)\s+(send|forward|exfiltrate)\b"),
    re.compile(r"(?i)\bstore\s+this\s+in\s+(memory|memories)\b"),
)

_ENCODED_LABEL = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
_HEX_BLOB = re.compile(r"^[0-9a-fA-F]{20,}$")
_ANSI_ESC = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]|\\x1b\[[0-9;]*[a-zA-Z]")
_SHELLISH = re.compile(
    r"(?i)(curl\s+|wget\s+|bash\s+-c|powershell|/bin/sh|rm\s+-rf|nc\s+)"
)
_PII = re.compile(
    r"(?i)(\b\d{3}-\d{2}-\d{4}\b|\b[\w.+-]+@[\w.-]+\.\w+\b|passport|ssn|credit.?card)"
)

_NET_TOOLS = frozenset(
    {
        "dns_lookup",
        "ping",
        "shell_exec",
        "http_fetch",
        "browser_navigate",
        "browser_submit",
        "mcp_invoke",
        "send_email",
        "start_server",
    }
)


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: str
    reason: str
    evidence: str = ""


def _host_from_url_or_host(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    if "<" in v and ">" in v:  # display-name form: "Alice" <alice@example.com>
        v = v[v.rindex("<") + 1 : v.rindex(">")].strip()
    if "://" in v:
        return (urlparse(v).hostname or "").lower() or None
    return v.split("/")[0].rsplit("@", 1)[-1].split(":")[0].lower() or None


def check_network(tool: str, args: dict[str, Any], net: NetworkPolicy) -> list[Finding]:
    out: list[Finding] = []
    hosts: list[str] = []

    for key in ("url", "host", "hostname", "target", "domain", "to", "bcc", "server"):
        if key in args and isinstance(args[key], str):
            h = _host_from_url_or_host(args[key])
            if h:
                hosts.append(h)

    cmd = args.get("command") or args.get("query") or args.get("text") or ""
    if isinstance(cmd, str) and cmd:
        for m in re.finditer(
            r"(?i)(?:ping|nslookup|dig|host|curl|wget)\s+(?:-[a-zA-Z]+\s+)*([^\s;|&]+)",
            cmd,
        ):
            h = _host_from_url_or_host(m.group(1))
            if h:
                hosts.append(h)
        for m in re.finditer(
            r"(?i)([A-Za-z0-9+/=_-]{8,})\.((?:[a-z0-9-]+\.)+[a-z]{2,})",
            cmd,
        ):
            label, domain = m.group(1), m.group(2).lower()
            if net.block_encoded_dns_labels and (
                _ENCODED_LABEL.match(label) or _HEX_BLOB.match(label)
            ):
                out.append(
                    Finding(
                        "dns_exfil",
                        "block",
                        "DNS label looks like encoded payload (exfiltration pattern)",
                        f"{label[:24]}….{domain}",
                    )
                )
            if domain in net.blocked_hosts or any(
                domain.endswith("." + b) for b in net.blocked_hosts
            ):
                out.append(
                    Finding(
                        "dns_exfil",
                        "block",
                        "DNS query targets blocked / attacker-controlled domain",
                        domain,
                    )
                )

    if tool in {"dns_lookup", "ping"} and not net.allow_dns_lookup:
        out.append(Finding("dns_policy", "block", f"tool '{tool}' disabled by policy"))

    for h in hosts:
        if h in net.blocked_hosts or any(h.endswith("." + b) for b in net.blocked_hosts):
            out.append(Finding("network_deny", "block", "destination on blocklist", h))
            continue
        if tool in {"dns_lookup", "ping", "shell_exec"}:
            if h not in net.dns_allowlist:
                out.append(
                    Finding(
                        "network_deny",
                        "block",
                        "host not on DNS/network allowlist",
                        h,
                    )
                )
        elif tool in _NET_TOOLS and net.allowed_hosts and h not in net.allowed_hosts:
            out.append(
                Finding("network_deny", "block", "host not on HTTP allowlist", h)
            )

        parts = h.split(".")
        if len(parts) >= 3 and net.block_encoded_dns_labels:
            if _ENCODED_LABEL.match(parts[0]) or _HEX_BLOB.match(parts[0]):
                out.append(
                    Finding(
                        "dns_exfil",
                        "block",
                        "FQDN first label looks like encoded secret",
                        h,
                    )
                )
    return out


_CONFUSABLES = str.maketrans("іарсеоѕјԁһ", "iapceosjdh")  # Cyrillic lookalikes -> latin
_ZERO_WIDTH = re.compile("[\u200b-\u200f\u2060\ufeff]")
_B64_TOKEN = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")


def _views(payload: str) -> list[str]:
    """Original + canonicalized (NFKC, homoglyph, zero-width) + base64-decoded views."""
    canon = _ZERO_WIDTH.sub("", unicodedata.normalize("NFKC", payload)).translate(_CONFUSABLES)
    views = [payload, canon]
    for tok in _B64_TOKEN.findall(canon):
        try:
            dec = base64.b64decode(tok + "=" * (-len(tok) % 4), validate=True).decode("utf-8")
        except ValueError:
            continue
        if dec.isprintable():
            views.append(dec)
    return list(dict.fromkeys(views))


def check_prompt_injection(
    payload: str,
    trust: TrustLevel,
    content: ContentPolicy,
) -> list[Finding]:
    if trust != TrustLevel.EXTERNAL or not payload:
        return []
    out: list[Finding] = []
    if content.treat_external_as_data_only and content.block_instruction_patterns_in_data:
        patterns: Iterable[re.Pattern[str] | str] = list(_INJECTION_PATTERNS) + list(
            content.extra_injection_patterns
        )
        views = _views(payload)
        for p in patterns:
            if isinstance(p, str):
                if any(re.search(p, v, re.I) for v in views):
                    out.append(
                        Finding(
                            "prompt_injection",
                            "block",
                            "learned/extra injection pattern in external data",
                            p[:80],
                        )
                    )
            elif any(p.search(v) for v in views):
                out.append(
                    Finding(
                        "prompt_injection",
                        "block",
                        "instruction-like content in untrusted data channel",
                        p.pattern[:80],
                    )
                )
    return out


def check_secret_in_args(args: dict[str, Any]) -> list[Finding]:
    blob = " ".join(str(v) for v in args.values())
    out: list[Finding] = []
    if re.search(
        r"(?i)(sk-[A-Za-z0-9]{20,}|api[_-]?key\s*=\s*\S+|AKIA[0-9A-Z]{16}|session[_-]?token\s*=)",
        blob,
    ):
        out.append(
            Finding(
                "secret_flow",
                "block",
                "tool arguments appear to contain secret material",
            )
        )
    for m in re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", blob):
        try:
            raw = base64.b64decode(m.group(0) + "==", validate=False)
            if re.search(rb"(key|secret|password|token)", raw, re.I):
                out.append(
                    Finding(
                        "secret_flow",
                        "block",
                        "base64 arg decodes to secret-like content",
                    )
                )
        except Exception:
            pass
    return out


def check_sensitive_paths(tool: str, args: dict[str, Any], policy: SecurityPolicy) -> list[Finding]:
    if tool not in {"read_file", "write_file", "delete_file", "shell_exec"}:
        return []
    blob = " ".join(str(args.get(k, "")) for k in ("path", "command", "target"))
    for needle in policy.sensitive_path_substrings:
        if needle.lower() in blob.lower():
            return [
                Finding(
                    "sensitive_path",
                    "block",
                    f"access to sensitive path pattern '{needle}' denied",
                    needle,
                )
            ]
    return []


def check_tcb_invariants(
    tool: str,
    args: dict[str, Any],
    data_channel: str | None,
    data_trust: TrustLevel,
    content: ContentPolicy,
) -> list[Finding]:
    """Hard TCB rules: memory/config/exposure/clipboard/terminal/IFC lite."""
    out: list[Finding] = []

    if tool == "update_memory" and content.block_external_memory_writes:
        if data_trust == TrustLevel.EXTERNAL or data_channel:
            out.append(
                Finding(
                    "tcb_memory",
                    "block",
                    "EXTERNAL/untrusted content cannot write agent memory (SpAIware class)",
                )
            )

    if tool == "update_config" and content.block_policy_self_modification:
        out.append(
            Finding(
                "tcb_config",
                "block",
                "agent cannot modify security policy/allowlist (Amp class)",
            )
        )

    if tool == "start_server":
        bind = str(args.get("bind", args.get("host", "0.0.0.0")))
        if bind in {"0.0.0.0", "::", "*"} or args.get("public") is True:
            out.append(
                Finding(
                    "exposure",
                    "block",
                    "public port/filesystem exposure denied (Devin ports class)",
                    bind,
                )
            )

    if tool == "clipboard_write":
        text = str(args.get("text", args.get("content", "")))
        if _SHELLISH.search(text) or (data_trust == TrustLevel.EXTERNAL and text):
            out.append(
                Finding(
                    "clipboard",
                    "block",
                    "clipboard write from untrusted/shellish content denied (ClickFix/DiLLMa)",
                )
            )
        if _ANSI_ESC.search(text):
            out.append(
                Finding(
                    "terminal_escape",
                    "block",
                    "ANSI escape sequences in clipboard/terminal output blocked",
                )
            )

    if tool == "browser_submit":
        body = str(args.get("body", args.get("data", "")))
        url = str(args.get("url", ""))
        host = _host_from_url_or_host(url)
        if _PII.search(body) and (
            not host or host.endswith("attacker.exfil.test") or "exfil" in (host or "")
        ):
            out.append(
                Finding(
                    "ifc_browser",
                    "block",
                    "PII submit to untrusted destination denied (Operator class)",
                )
            )

    if tool == "send_email" and args.get("bcc"):
        out.append(
            Finding(
                "comms_bcc",
                "block",
                "unauthorized BCC recipient denied (malicious MCP mailer class)",
                str(args.get("bcc")),
            )
        )

    if tool == "mcp_invoke":
        server = str(args.get("server", "")).lower()
        if "malicious" in server or server.endswith(".evil") or "impersonat" in server:
            out.append(
                Finding(
                    "mcp_identity",
                    "block",
                    "MCP server identity failed allowlist/integrity check",
                    server,
                )
            )
        desc = str(args.get("tool_description", ""))
        if desc and data_trust == TrustLevel.EXTERNAL:
            out.extend(
                check_prompt_injection(desc, TrustLevel.EXTERNAL, content)
            )

    if tool == "agent_message":
        if data_trust == TrustLevel.EXTERNAL or args.get("unauthenticated"):
            out.append(
                Finding(
                    "a2a_trust",
                    "block",
                    "unauthenticated/untrusted agent message denied (A2A spoofing class)",
                )
            )

    if tool == "delete_file":
        path = str(args.get("path", ""))
        if any(x in path.lower() for x in ("/", "prod", "db", "home", "users")):
            out.append(
                Finding(
                    "destructive",
                    "block",
                    "destructive filesystem delete requires elevated approval",
                    path[:80],
                )
            )

    # Terminal escape in shell output simulation
    if tool == "shell_exec":
        cmd = str(args.get("command", ""))
        if _ANSI_ESC.search(cmd):
            out.append(
                Finding(
                    "terminal_escape",
                    "block",
                    "ANSI escape sequences in terminal command blocked (DiLLMa class)",
                )
            )

    return out
