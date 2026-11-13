"""Unit tests for worker cancellation and rate controls."""

import pytest

from netsentinel.application.control import CancellationToken, RateLimiter
from netsentinel.application.policies import SafetyLimits
from netsentinel.domain.errors import OperationCancelled


def test_cancellation_token_is_idempotent() -> None:
    token = CancellationToken()
    assert not token.is_cancelled
    token.cancel()
    token.cancel()
    assert token.is_cancelled
    with pytest.raises(OperationCancelled):
        token.raise_if_cancelled()


def test_rate_limiter_honors_a_cancelled_token() -> None:
    token = CancellationToken()
    token.cancel()
    with pytest.raises(OperationCancelled):
        RateLimiter(25).wait(token)


@pytest.mark.parametrize(
    "field, value",
    [
        ("max_scope_hosts", 0),
        ("max_ports", 0),
        ("max_concurrency", 0),
        ("max_rate_per_second", 0),
    ],
)
def test_safety_limits_reject_invalid_values(field: str, value: int) -> None:
    with pytest.raises(ValueError):
        SafetyLimits(**{field: value})
