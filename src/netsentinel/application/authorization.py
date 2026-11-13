"""Authorization confirmation service."""

from __future__ import annotations

from datetime import UTC, datetime

from netsentinel.application.policies import SafetyPolicy
from netsentinel.domain.enums import OperationType
from netsentinel.domain.errors import ValidationError
from netsentinel.domain.models import AuthorizationRecord, ScanScope


class AuthorizationService:
    """Create confirmations only after validating their requested scope."""

    def __init__(self, policy: SafetyPolicy) -> None:
        self._policy = policy

    def confirm(
        self,
        *,
        operator: str,
        operation: OperationType,
        scope: ScanScope,
        reason: str,
        expires_at: datetime,
        confirmed_at: datetime | None = None,
    ) -> AuthorizationRecord:
        """Create a time-bounded confirmation for a safe, non-empty request."""
        if not operator.strip():
            raise ValidationError("Operator identity is required")
        if not reason.strip():
            raise ValidationError("A reason for the authorized operation is required")
        confirmed = confirmed_at or datetime.now(UTC)
        if confirmed.tzinfo is None or confirmed.utcoffset() is None:
            raise ValidationError("Authorization confirmation must include a timezone")
        if expires_at.tzinfo is None or expires_at.utcoffset() is None:
            raise ValidationError("Authorization expiry must include a timezone")
        if expires_at <= confirmed:
            raise ValidationError("Authorization expiry must be in the future")
        self._policy.validate_scope(scope)
        return AuthorizationRecord.create(
            operator=operator,
            operation=operation,
            scope=scope,
            reason=reason,
            expires_at=expires_at,
            confirmed_at=confirmed,
        )
