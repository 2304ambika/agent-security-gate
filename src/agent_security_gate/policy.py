"""Declarative security policy consulted by the reference monitor."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import FrozenSet, Set


class TrustLevel(str, Enum):
    SYSTEM = "system"
    USER = "user"
    EXTERNAL = "external"


@dataclass(frozen=True)
class NetworkPolicy:
    allowed_hosts: FrozenSet[str] = frozenset()
    blocked_hosts: FrozenSet[str] = frozenset()
    allow_dns_lookup: bool = False
    dns_allowlist: FrozenSet[str] = frozenset({"localhost", "127.0.0.1"})
    max_dns_label_len: int = 63
    block_encoded_dns_labels: bool = True


@dataclass(frozen=True)
class ContentPolicy:
    treat_external_as_data_only: bool = True
    block_instruction_patterns_in_data: bool = True
    extra_injection_patterns: FrozenSet[str] = frozenset()
    # TCB-adjacent stores must not accept EXTERNAL provenance
    block_external_memory_writes: bool = True
    # Agent must not mutate its own enforcement config
    block_policy_self_modification: bool = True


@dataclass
class SecurityPolicy:
    network: NetworkPolicy = field(default_factory=NetworkPolicy)
    content: ContentPolicy = field(default_factory=ContentPolicy)
    tool_roles: dict[str, str] = field(
        default_factory=lambda: {
            "http_fetch": "network_read",
            "shell_exec": "shell",
            "read_file": "filesystem_read",
            "write_file": "filesystem_write",
            "delete_file": "filesystem_delete",
            "dns_lookup": "dns",
            "ping": "network_probe",
            "send_email": "comms",
            "update_memory": "memory_write",
            "update_config": "admin",
            "start_server": "network_expose",
            "browser_navigate": "browser",
            "browser_submit": "browser_write",
            "clipboard_write": "clipboard",
            "mcp_invoke": "mcp",
            "agent_message": "a2a",
        }
    )
    role_capabilities: dict[str, Set[str]] = field(
        default_factory=lambda: {
            # Intentionally no: admin, network_expose, memory_write, filesystem_delete,
            # clipboard, browser_write, a2a — least privilege for common tasks
            "researcher": {"network_read", "filesystem_read", "browser"},
            "coder": {"filesystem_read", "filesystem_write", "shell", "mcp"},
            "ops": {
                "network_read",
                "network_probe",
                "dns",
                "shell",
                "filesystem_read",
            },
            "reader": {"filesystem_read"},
            "browser_agent": {"browser", "network_read"},
            "mailer": {"comms", "network_read"},
        }
    )
    deny_by_default: bool = True
    # Paths that require secrets_read (never granted above)
    sensitive_path_substrings: FrozenSet[str] = frozenset(
        {".env", "id_rsa", "credentials.json", "secrets/", ".aws/", "prod_db"}
    )

    def with_learned_injection_pattern(self, pattern: str) -> None:
        pats = set(self.content.extra_injection_patterns)
        pats.add(pattern)
        self.content = ContentPolicy(
            treat_external_as_data_only=self.content.treat_external_as_data_only,
            block_instruction_patterns_in_data=self.content.block_instruction_patterns_in_data,
            extra_injection_patterns=frozenset(pats),
            block_external_memory_writes=self.content.block_external_memory_writes,
            block_policy_self_modification=self.content.block_policy_self_modification,
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
                    "attacker.exfil.test",
                    "malicious-mcp.example",
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
