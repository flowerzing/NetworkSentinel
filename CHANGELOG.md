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

### Not yet implemented

- Authorized network discovery.
- TCP port scanning and Nmap service detection.
- Network monitoring, inventory, assessments, and reports.
