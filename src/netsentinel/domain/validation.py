"""Pure validation and normalization helpers for user-provided scope data."""

from __future__ import annotations

from collections.abc import Iterable
from ipaddress import IPv4Address, IPv4Network, ip_address, ip_network

from netsentinel.domain.errors import ValidationError
from netsentinel.domain.models import ScanScope


def parse_ipv4_target(value: str) -> IPv4Address | IPv4Network:
    """Parse one IPv4 address or CIDR network without DNS resolution."""
    candidate = value.strip()
    if not candidate:
        raise ValidationError("Target cannot be empty")

    try:
        if "/" in candidate:
            network = ip_network(candidate, strict=False)
            if not isinstance(network, IPv4Network):
                raise ValidationError("Only IPv4 targets are supported by discovery")
            return network
        address = ip_address(candidate)
        if not isinstance(address, IPv4Address):
            raise ValidationError("Only IPv4 targets are supported by discovery")
        return address
    except ValueError as exc:
        raise ValidationError(f"Invalid IPv4 target: {value!r}") from exc


def parse_scope(
    targets: Iterable[str],
    exclusions: Iterable[str] = (),
    *,
    max_hosts: int = 256,
) -> ScanScope:
    """Normalize scope strings and reject oversized host expansion."""
    if max_hosts < 1:
        raise ValidationError("The maximum host limit must be positive")
    normalized_targets = _deduplicate(parse_ipv4_target(value) for value in targets)
    if not normalized_targets:
        raise ValidationError("At least one scan target is required")

    normalized_exclusions = _deduplicate(
        parse_ipv4_target(value) for value in exclusions
    )
    scope = ScanScope(
        targets=tuple(normalized_targets),
        exclusions=tuple(normalized_exclusions),
    )
    if not _exclusions_are_inside(scope):
        raise ValidationError("Every exclusion must be inside a target")
    if not scope.hosts(limit=max_hosts):
        raise ValidationError("The scope contains no hosts after exclusions")
    return scope


def parse_ports(value: str) -> tuple[int, ...]:
    """Parse comma-separated ports and inclusive ranges into sorted unique ports."""
    ports: set[int] = set()
    fields = [field.strip() for field in value.split(",") if field.strip()]
    if not fields:
        raise ValidationError("At least one port is required")

    for field in fields:
        if "-" in field:
            parts = [part.strip() for part in field.split("-")]
            if len(parts) != 2 or not all(parts):
                raise ValidationError(f"Invalid port range: {field!r}")
            start, end = _parse_port(parts[0]), _parse_port(parts[1])
            if start > end:
                raise ValidationError(f"Port range is reversed: {field!r}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(field))

    return tuple(sorted(ports))


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValidationError(f"Invalid port: {value!r}") from exc
    if not 1 <= port <= 65535:
        raise ValidationError(f"Port must be between 1 and 65535: {port}")
    return port


def _deduplicate(
    values: Iterable[IPv4Address | IPv4Network],
) -> list[IPv4Address | IPv4Network]:
    """Preserve input order while removing exact duplicate targets."""
    result: list[IPv4Address | IPv4Network] = []
    seen: set[IPv4Address | IPv4Network] = set()
    for value in values:
        if value not in seen:
            result.append(value)
            seen.add(value)
    return result


def _exclusions_are_inside(scope: ScanScope) -> bool:
    for exclusion in scope.exclusions:
        if isinstance(exclusion, IPv4Address):
            if not any(_target_contains(target, exclusion) for target in scope.targets):
                return False
            continue
        if not any(
            isinstance(target, IPv4Network) and exclusion.subnet_of(target)
            for target in scope.targets
        ):
            return False
    return True


def _target_contains(
    target: IPv4Address | IPv4Network,
    address: IPv4Address,
) -> bool:
    """Return whether one normalized target contains a concrete address."""
    return target == address if isinstance(target, IPv4Address) else address in target
