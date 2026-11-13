"""Versioned SQLite schema migrations."""

from __future__ import annotations

import sqlite3

_MIGRATIONS: tuple[tuple[int, str], ...] = (
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS authorization_records (
            record_id TEXT PRIMARY KEY,
            operator TEXT NOT NULL,
            operation TEXT NOT NULL,
            reason TEXT NOT NULL,
            scope_json TEXT NOT NULL,
            confirmed_at TEXT NOT NULL,
            expires_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS jobs (
            job_id TEXT PRIMARY KEY,
            operation TEXT NOT NULL,
            state TEXT NOT NULL,
            authorization_id TEXT NOT NULL
                REFERENCES authorization_records(record_id),
            created_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assets (
            asset_id TEXT PRIMARY KEY,
            ip_address TEXT NOT NULL UNIQUE,
            mac_address TEXT,
            hostname TEXT,
            vendor TEXT,
            first_seen TEXT NOT NULL,
            last_seen TEXT NOT NULL,
            status TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS port_observations (
            observation_id TEXT PRIMARY KEY,
            job_id TEXT REFERENCES jobs(job_id) ON DELETE SET NULL,
            address TEXT NOT NULL,
            port INTEGER NOT NULL CHECK (port BETWEEN 1 AND 65535),
            protocol TEXT NOT NULL,
            state TEXT NOT NULL,
            service TEXT,
            version TEXT,
            source TEXT NOT NULL,
            observed_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS assessment_findings (
            finding_id TEXT PRIMARY KEY,
            job_id TEXT REFERENCES jobs(job_id) ON DELETE SET NULL,
            rule_id TEXT NOT NULL,
            severity TEXT NOT NULL,
            title TEXT NOT NULL,
            explanation TEXT NOT NULL,
            recommendation TEXT NOT NULL,
            confidence REAL NOT NULL CHECK (confidence BETWEEN 0 AND 1),
            evidence_ids_json TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS audit_events (
            event_id TEXT PRIMARY KEY,
            action TEXT NOT NULL,
            occurred_at TEXT NOT NULL,
            operator TEXT NOT NULL,
            operation TEXT,
            authorization_id TEXT
                REFERENCES authorization_records(record_id),
            details_json TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_jobs_created_at
            ON jobs(created_at);
        CREATE INDEX IF NOT EXISTS idx_assets_last_seen
            ON assets(last_seen);
        CREATE INDEX IF NOT EXISTS idx_ports_job_id
            ON port_observations(job_id);
        CREATE INDEX IF NOT EXISTS idx_findings_job_id
            ON assessment_findings(job_id);
        CREATE INDEX IF NOT EXISTS idx_audit_occurred_at
            ON audit_events(occurred_at);
        """,
    ),
)


def apply_migrations(connection: sqlite3.Connection) -> None:
    """Apply each schema migration exactly once."""
    connection.execute(
        "CREATE TABLE IF NOT EXISTS schema_version "
        "(version INTEGER NOT NULL)"
    )
    connection.execute(
        "INSERT INTO schema_version(version) "
        "SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM schema_version)"
    )
    current = int(
        connection.execute("SELECT version FROM schema_version").fetchone()[0]
    )
    latest = _MIGRATIONS[-1][0] if _MIGRATIONS else 0
    if current > latest:
        raise RuntimeError(
            f"Database version {current} is newer than supported version {latest}"
        )

    for version, script in _MIGRATIONS:
        if version <= current:
            continue
        connection.executescript(script)
        connection.execute("UPDATE schema_version SET version = ?", (version,))
        current = version
