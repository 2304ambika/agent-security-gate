"""Declarative security policy consulted by the reference monitor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Set


class TrustLevel(str, Enum):
    SYSTEM = "system"  # developer/system prompts — TCB-adjacent
    USER = "user"  # authenticated user instructions
    EXTERNAL = "external"  # web/tool/file data — never executable as policy


@dataclass(frozen=True)
class NetworkPolicy:
    """Outbound network constraints (DNS / HTTPS destinations)."""

    allowed_hosts: FrozenSet[str] = frozenset()
    blocked_hosts: FrozenSet[str] = frozenset()
    allow_dns_lookup: bool = False
    # Hosts that may appear in DNS queries (exfil via subdomain is blocked separately)
    dns_allowlist: FrozenSet[str] = frozenset({"localhost", "127.0.0.1"})
    max_dns_label_len: int = 63
    # Reject DNS labels that look like base64/hex payloads
    block_encoded_dns_labels: bool = True


@dataclass(frozen=True)
class ContentPolicy:
    """Instruction / data separation + injection heuristics."""

    treat_external_as_data_only: bool = True
    block_instruction_patterns_in_data: bool = True
    # Soft-learnable: patterns promoted after confirmed attacks
    extra_injection_patterns: FrozenSet[str] = frozenset()


@dataclass
class SecurityPolicy:
    """Mutable top-level policy; learning layer may append patterns/hosts."""

    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    content: ContentPolicy = field(default_factory=ContentPolicy)
    # tool_name -> required role
    tool_roles: dict[str, str] = field(
        default_factory=lambda: {
            "http_fetch": "network_read",
            "shell_exec": "shell",
            "read_file": "filesystem_read",
            "write_file": "filesystem_write",
            "dns_lookup": "dns",
            "ping": "network_probe",
            "send_email": "comms",
        }
    )
    # role -> granted capability tags
    role_capabilities: dict[str, Set[str]] = field(
        default_factory=lambda: {
            "researcher": {"network_read", "filesystem_read"},
            "coder": {"filesystem_read", "filesystem_write", "shell"},
            "ops": {"network_read", "network_probe", "dns", "shell", "filesystem_read"},
            "reader": {"filesystem_read"},
        }
    )
    deny_by_default: bool = True

    def with_learned_injection_pattern(self, pattern: str) -> None:
        pats = set(self.content.extra_injection_patterns)
        pats.add(pattern)
        self.content = ContentPolicy(
            treat_external_as_data_only=self.content.treat_external_as_data_only,
            block_instruction_patterns_in_data=self.content.block_instruction_patterns_in_data,
            extra_injection_patterns=frozenset(pats),
        )

    def with_blocked_host(self, host: str) -> None:
        blocked = set(self.network.blocked_hosts)
        blocked.add(host.lower())
        self.network = NetworkPolicy(
            allowed_hosts=self.network.allowed_hosts,
            blocked_hosts=frozenset(blocked),
            allow_dns_lookup=self.network.allow_dns_lookup,
            dns_allowlist=self.network.dns_allowlist,
            max_dns_label_len=self.network.max_dns_label_len,
            block_encoded_dns_labels=self.network.block_encoded_dns_labels,
        )


def default_policy(*, task_role: str = "researcher") -> SecurityPolicy:
    """Baseline least-privilege policy for demos/benchmarks."""
    return SecurityPolicy(
        network=NetworkPolicy(
            allowed_hosts=frozenset(
                {
                    "api.github.com",
                    "docs.python.org",
                    "arxiv.org",
                    "example.com",
                }
            ),
            blocked_hosts=frozenset(
                {
                    "evil.exfil.attacker.com",
                    "collector.badcdn.net",
                }
            ),
            allow_dns_lookup=True,
            dns_allowlist=frozenset(
                {
                    "localhost",
                    "127.0.0.1",
                    "api.github.com",
                    "docs.python.org",
                    "arxiv.org",
                    "example.com",
                }
            ),
        ),
        content=ContentPolicy(),
    )
