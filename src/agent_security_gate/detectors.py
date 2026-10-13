"""Deterministic detectors — TCB must not rely on an LLM (paper §2.3)."""

from __future__ import annotations

import base64
import re
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlparse

from .policy import ContentPolicy, NetworkPolicy, TrustLevel

# Classic indirect-injection / tool-misuse cues in untrusted data
_INJECTION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bignore\s+(all\s+)?(previous|prior|above)\s+instructions?\b"),
    re.compile(r"(?i)\bdisregard\s+(your|the)\s+(system|safety)\s+(prompt|rules?)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(in\s+)?(developer|god|jailbreak)\s+mode\b"),
    re.compile(r"(?i)\b(exfiltrat|send|leak|upload)\b.{0,40}\b(api[_ ]?key|password|secret|\.env)\b"),
    re.compile(r"(?i)\bread\s+.{0,20}\.env\b"),
    re.compile(r"(?i)\bping\b.{0,80}\b(attacker|exfil|evil)\b"),
    re.compile(r"(?i)</?\s*system\s*>"),
    re.compile(r"(?i)\[INST\]|<<\s*SYS\s*>>"),
)

_ENCODED_LABEL = re.compile(r"^[A-Za-z0-9+/=_-]{16,}$")
_HEX_BLOB = re.compile(r"^[0-9a-fA-F]{20,}$")


@dataclass(frozen=True)
class Finding:
    detector: str
    severity: str  # info | warn | block
    reason: str
    evidence: str = ""


def _host_from_url_or_host(value: str) -> str | None:
    v = value.strip()
    if not v:
        return None
    if "://" in v:
        return (urlparse(v).hostname or "").lower() or None
    # bare host or host:port
    return v.split("/")[0].split(":")[0].lower() or None


def check_network(tool: str, args: dict[str, Any], net: NetworkPolicy) -> list[Finding]:
    out: list[Finding] = []
    hosts: list[str] = []

    for key in ("url", "host", "hostname", "target", "domain"):
        if key in args and isinstance(args[key], str):
            h = _host_from_url_or_host(args[key])
            if h:
                hosts.append(h)

    # shell / ping / dns often bury the host in a command string
    cmd = args.get("command") or args.get("query") or ""
    if isinstance(cmd, str) and cmd:
        for m in re.finditer(
            r"(?i)(?:ping|nslookup|dig|host|curl|wget)\s+(?:-[a-zA-Z]+\s+)*([^\s;|&]+)",
            cmd,
        ):
            h = _host_from_url_or_host(m.group(1))
            if h:
                hosts.append(h)
        # subdomain exfil: SECRET.evil.com
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
        if net.allowed_hosts and h not in net.allowed_hosts:
            # DNS tools: also require dns allowlist
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
            elif h not in net.allowed_hosts:
                out.append(
                    Finding(
                        "network_deny",
                        "block",
                        "host not on HTTP allowlist",
                        h,
                    )
                )

        # Encoded first label of FQDN
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
        for p in patterns:
            if isinstance(p, str):
                if re.search(p, payload, re.I):
                    out.append(
                        Finding(
                            "prompt_injection",
                            "block",
                            "learned/extra injection pattern in external data",
                            p[:80],
                        )
                    )
            elif p.search(payload):
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
    """Block tool args that already embed obvious secrets (IFC lite)."""
    blob = " ".join(str(v) for v in args.values())
    out: list[Finding] = []
    if re.search(r"(?i)(sk-[A-Za-z0-9]{20,}|api[_-]?key\s*=\s*\S+|AKIA[0-9A-Z]{16})", blob):
        out.append(
            Finding(
                "secret_flow",
                "block",
                "tool arguments appear to contain secret material",
            )
        )
    # base64-looking chunks longer than 40 in args going to network tools
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
