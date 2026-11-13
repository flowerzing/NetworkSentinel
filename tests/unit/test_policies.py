"""Unit tests for authorization and default safety policy."""

from datetime import UTC, datetime, timedelta

import pytest

from netsentinel.application.authorization import AuthorizationService
from netsentinel.application.policies import SafetyPolicy
from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import (
    AuthorizationError,
    PolicyViolation,
    ValidationError,
)
from netsentinel.domain.validation import parse_scope

UTC = UTC


def test_local_scope_can_be_confirmed() -> None:
    now = datetime.now(UTC)
    scope = parse_scope(["192.168.10.0/30"])
    record = AuthorizationService(SafetyPolicy()).confirm(
        operator="operator",
        operation=OperationType.DISCOVERY,
        scope=scope,
        reason="Authorized lab inventory",
        confirmed_at=now,
        expires_at=now + timedelta(minutes=10),
    )

    assert record.operation is OperationType.DISCOVERY
    assert record.is_active(now + timedelta(minutes=1))


def test_default_policy_rejects_public_scope() -> None:
    scope = parse_scope(["8.8.8.8"])

    with pytest.raises(PolicyViolation, match="Public targets"):
        SafetyPolicy().validate_scope(scope)


def test_authorization_must_match_operation_and_scope() -> None:
    now = datetime.now(UTC)
    authorized = parse_scope(["192.168.10.0/29"])
    requested = parse_scope(["192.168.10.1"])
    record = AuthorizationService(SafetyPolicy()).confirm(
        operator="operator",
        operation=OperationType.DISCOVERY,
        scope=authorized,
        reason="Authorized lab inventory",
        confirmed_at=now,
        expires_at=now + timedelta(minutes=10),
    )
    policy = SafetyPolicy()

    policy.validate_authorization(
        authorization=record,
        operation=OperationType.DISCOVERY,
        scope=requested,
        at=now + timedelta(seconds=1),
    )
    with pytest.raises(AuthorizationError, match="does not cover"):
        policy.validate_authorization(
            authorization=record,
            operation=OperationType.PORT_SCAN,
            scope=requested,
            at=now + timedelta(seconds=1),
        )


def test_authorization_expiry_and_required_fields() -> None:
    now = datetime.now(UTC)
    scope = parse_scope(["192.168.10.1"])
    service = AuthorizationService(SafetyPolicy())

    with pytest.raises(ValidationError, match="Operator"):
        service.confirm(
            operator=" ",
            operation=OperationType.DISCOVERY,
            scope=scope,
            reason="reason",
            confirmed_at=now,
            expires_at=now + timedelta(minutes=1),
        )

    record = service.confirm(
        operator="operator",
        operation=OperationType.DISCOVERY,
        scope=scope,
        reason="reason",
        confirmed_at=now,
        expires_at=now + timedelta(minutes=1),
    )
    with pytest.raises(AuthorizationError, match="expired"):
        SafetyPolicy().validate_authorization(
            authorization=record,
            operation=OperationType.DISCOVERY,
            scope=scope,
            at=now + timedelta(minutes=2),
        )
