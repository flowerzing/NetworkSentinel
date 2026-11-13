"""Domain exceptions with user-safe messages."""


class NetSentinelError(Exception):
    """Base class for expected NetSentinel errors."""


class ValidationError(NetSentinelError):
    """Raised when user-provided data cannot be normalized safely."""


class AuthorizationError(NetSentinelError):
    """Raised when an operation lacks valid explicit authorization."""


class PolicyViolation(NetSentinelError):
    """Raised when a request exceeds a configured safety limit."""


class OperationCancelled(NetSentinelError):
    """Raised when a worker reaches a cooperative cancellation checkpoint."""


class CapabilityError(NetSentinelError):
    """Raised when an optional operating-system capability is unavailable."""
