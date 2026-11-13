"""Typed events exchanged by future background workers and the UI."""

from dataclasses import dataclass
from uuid import UUID


@dataclass(frozen=True, slots=True)
class ProgressEvent:
    """Progress update that does not expose worker implementation details."""

    job_id: UUID
    completed: int
    total: int
    message: str


@dataclass(frozen=True, slots=True)
class JobErrorEvent:
    """Expected worker failure suitable for a user-facing error message."""

    job_id: UUID
    message: str
    recoverable: bool = False
