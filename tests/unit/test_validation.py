"""Unit tests for pure scope and port normalization."""

from ipaddress import IPv4Address

import pytest

from netsentinel.domain.errors import ValidationError
from netsentinel.domain.validation import parse_ports, parse_scope


def test_scope_normalizes_duplicate_targets_and_exclusions() -> None:
    scope = parse_scope(
        ["192.168.1.10", "192.168.1.0/30", "192.168.1.10"],
        ["192.168.1.1", "192.168.1.1"],
    )

    assert len(scope.targets) == 2
    assert set(scope.hosts()) == {
        IPv4Address("192.168.1.2"),
        IPv4Address("192.168.1.10"),
    }
    assert len(scope.exclusions) == 1


def test_scope_rejects_empty_or_fully_excluded_targets() -> None:
    with pytest.raises(ValidationError, match="At least one"):
        parse_scope([])
    with pytest.raises(ValidationError, match="no hosts"):
        parse_scope(["192.168.1.10"], ["192.168.1.10"])


def test_scope_rejects_exclusion_outside_target() -> None:
    with pytest.raises(ValidationError, match="inside"):
        parse_scope(["192.168.1.0/30"], ["10.0.0.1"])


def test_scope_rejects_oversized_network_without_expanding_it() -> None:
    with pytest.raises(ValidationError, match="expansion limit"):
        parse_scope(["10.0.0.0/8"])


def test_fully_excluded_large_network_is_rejected_without_iteration() -> None:
    with pytest.raises(ValidationError, match="no hosts"):
        parse_scope(["10.0.0.0/8"], ["10.0.0.0/8"])


def test_ports_expand_ranges_and_deduplicate() -> None:
    assert parse_ports("80, 443, 8000-8002, 443") == (80, 443, 8000, 8001, 8002)


@pytest.mark.parametrize("value", ["0", "65536", "80-79", "abc", "80-"])
def test_ports_reject_invalid_values(value: str) -> None:
    with pytest.raises(ValidationError):
        parse_ports(value)
