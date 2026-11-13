"""Thread-scoped SQLite connection factory."""

from __future__ import annotations

import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from netsentinel.infrastructure.database.migrations import apply_migrations


class SQLiteDatabase:
    """Create short-lived SQLite connections with consistent pragmas.

    A connection is never shared between worker threads. Callers should use
    :meth:`connection` for one logical unit of work and let the context manager
    close it immediately afterward.
    """

    def __init__(self, path: Path, timeout_seconds: float = 5.0) -> None:
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        self.path = path
        self.timeout_seconds = timeout_seconds

    def initialize(self) -> None:
        """Create the database directory and apply pending migrations."""
        with self.connection() as connection:
            apply_migrations(connection)

    @contextmanager
    def connection(self) -> Iterator[sqlite3.Connection]:
        """Yield a configured connection and close it after the operation."""
        self.path.parent.mkdir(parents=True, exist_ok=True)
        connection = sqlite3.connect(
            self.path,
            timeout=self.timeout_seconds,
            check_same_thread=True,
        )
        connection.row_factory = sqlite3.Row
        try:
            connection.execute("PRAGMA foreign_keys = ON")
            connection.execute("PRAGMA busy_timeout = 5000")
            connection.execute("PRAGMA journal_mode = WAL")
            connection.execute("PRAGMA synchronous = NORMAL")
            yield connection
        except Exception:
            connection.rollback()
            raise
        else:
            connection.commit()
        finally:
            connection.close()
