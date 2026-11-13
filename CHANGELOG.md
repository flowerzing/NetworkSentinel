# Changelog

All notable changes to NetSentinel will be documented in this file.

The project is currently in pre-release development. Dates and entries are added
when a stage is completed and verified.

## [Unreleased]

### Added

- Initial project architecture and development tooling.
- Python 3.12+ packaging metadata with development commands.
- A minimal Qt application shell and configuration check command.
- Immutable domain models for scopes, authorizations, jobs, observations,
  findings, and audit events.
- Bounded IPv4/CIDR and port parsing with oversized-scope protection.
- Explicit authorization and conservative local-only safety policies.
- Cooperative cancellation and reusable operation rate limiting.
- Unit tests for the dependency-free domain and safety layer.
- Versioned SQLite migrations with WAL, foreign keys, busy timeout, and indexes.
- Parameterized repositories for authorizations, jobs, assets, observations,
  findings, and audit events.
- A configurable SQLite database path under the application data directory.
- An authorized discovery service with adapter contracts, normalization, deduplication,
  persistence orchestration, and audit events.
- Scapy/Npcap capability diagnostics and a bounded local ARP adapter.
- Optional discovery response-time persistence for inventory records.
- A bounded TCP Connect scan service with port-state normalization, cancellation,
  progress events, rate limiting, job persistence, and audit events.
- Runtime configuration for scope, port, concurrency, rate, and connection timeout
  limits.

### Not yet implemented

- Discovery and port-scan controls wired into the desktop UI.
- Nmap service and version detection.
- Network monitoring, inventory, assessments, and reports.
