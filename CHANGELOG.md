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
- Optional Nmap service/version detection with fixed arguments, XML parsing,
  cancellation, process timeouts, output bounds, and no shell execution.
- Reusable PySide6 workers and a worker manager with queued execution,
  cancellation, progress, result, error, and lifecycle signals.
- Desktop Network Discovery and TCP Port Scanner panels with validated forms,
  explicit authorization confirmation, progress, cancellation, and actionable
  worker status messages.
- GUI tests covering active panel construction, authorization gating, and a fake
  discovery operation executed through the worker manager.
- A read-only psutil Network Monitor with interface metadata, cumulative
  counters, calculated byte rates, configurable timer refreshes, and a Qt table.
- Monitoring tests using fake providers and a rendered Qt snapshot without real
  network traffic.
- A Device Inventory panel with search, refresh, and CSV/JSON export.
- An evidence-based Security Assessment panel with deterministic rules:
  open ports without service info, insecure service detection, outdated version
  heuristics, unusual high ports, and high open port count.
- Assessment findings persist with evidence links and are exportable to CSV and
  JSON with versioned envelopes.
- A Reports module generating assessment snapshots with assets, port
  observations, and findings; exportable to JSON, CSV, and PDF (via reportlab).
- A Dashboard panel with key metrics: device count, open ports, findings,
  and critical severity count; auto-refreshes after inventory and assessment.
- Live traffic charts in Network Monitor using pyqtgraph showing aggregated
  send/receive rates over time.
- Windows packaging with PyInstaller producing a single-file GUI executable (~76 MB) with all dependencies bundled.

### Not yet implemented

- Opt-in integration tests for Windows/Npcap/Nmap (marked for manual validation).
