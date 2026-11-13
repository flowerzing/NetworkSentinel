"""Centralized safety policy for active network operations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from ipaddress import IPv4Address
from math import isfinite

from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import (
    AuthorizationError,
    PolicyViolation,
    ValidationError,
)
from netsentinel.domain.models import AuthorizationRecord, ScanScope


@dataclass(frozen=True, slots=True)
class SafetyLimits:
    """Conservative bounds applied before an operation can start."""

    max_scope_hosts: int = 256
    max_ports: int = 1024
    max_concurrency: int = 16
    max_rate_per_second: float = 25.0

    def __post_init__(self) -> None:
        """Reject unsafe limits before they can reach an active adapter."""
        if self.max_scope_hosts < 1:
            raise ValueError("max_scope_hosts must be positive")
        if self.max_ports < 1:
            raise ValueError("max_ports must be positive")
        if self.max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")
        if not isfinite(self.max_rate_per_second) or self.max_rate_per_second <= 0:
            raise ValueError("max_rate_per_second must be finite and positive")


@dataclass(frozen=True, slots=True)
class SafetyPolicy:
    """Validate authorization, target locality, and resource limits."""

    limits: SafetyLimits = SafetyLimits()
    allow_public_targets: bool = False

    def validate_scope(self, scope: ScanScope) -> None:
        """Reject empty, oversized, or unsafe targets before network I/O."""
        try:
            hosts = scope.hosts(limit=self.limits.max_scope_hosts)
        except ValidationError as exc:
            raise PolicyViolation(str(exc)) from exc
        if not hosts:
            raise PolicyViolation("The authorized scope contains no usable hosts")
        if len(hosts) > self.limits.max_scope_hosts:
            raise PolicyViolation(
                f"Scope contains {len(hosts)} hosts; limit is "
                f"{self.limits.max_scope_hosts}"
            )
        if not self.allow_public_targets and any(
            not _is_local_address(address) for address in hosts
        ):
            raise PolicyViolation(
                "Public targets are disabled by the default safety policy"
            )

    def validate_ports(self, ports: tuple[int, ...]) -> None:
        """Validate a normalized port selection."""
        if not ports:
            raise PolicyViolation("At least one port must be selected")
        if len(ports) > self.limits.max_ports:
            raise PolicyViolation(
                f"Port selection contains {len(ports)} ports; limit is "
                f"{self.limits.max_ports}"
            )
        if any(not 1 <= port <= 65535 for port in ports):
            raise PolicyViolation("Port selection contains an invalid port")

    def validate_authorization(
        self,
        *,
        authorization: AuthorizationRecord | None,
        operation: OperationType,
        scope: ScanScope,
        at: datetime | None = None,
    ) -> None:
        """Require active, matching, explicit authorization for an operation."""
        self.validate_scope(scope)
        if authorization is None:
            raise AuthorizationError(
                "An explicit authorization confirmation is required before starting"
            )
        if authorization.operation is not operation:
            raise AuthorizationError("Authorization does not cover this operation")
        if not authorization.is_active(at):
            raise AuthorizationError("Authorization is expired or not active")
        if not authorization.scope.contains(scope):
            raise AuthorizationError("Requested scope exceeds the authorized scope")


def _is_local_address(address: IPv4Address) -> bool:
    """Return whether an address is safe under the default local-only policy."""
    return (
        (address.is_private or address.is_link_local)
        and not address.is_loopback
        and not address.is_unspecified
        and not address.is_multicast
    )
