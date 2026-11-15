# NetSentinel Development TODO

## Completed

- [x] Define the layered project architecture.
- [x] Create the Python package layout.
- [x] Add packaging, linting, type-checking, and test configuration.
- [x] Add the initial Qt application shell.
- [x] Add the English project README and safety scope.

## Next stage

- [x] Add Windows packaging and opt-in integration tests.

## Completed in the current stage

- [x] Add immutable domain models and operation/severity enums.
- [x] Add bounded IPv4/CIDR and port normalization.
- [x] Add explicit authorization records and local-only safety policy defaults.
- [x] Add cooperative cancellation and reusable rate limiting.
- [x] Add unit tests for validation, policy, authorization, and worker controls.
- [x] Add versioned SQLite migrations and parameterized repositories.
- [x] Persist authorizations, jobs, assets, port observations, findings, and audit events.
- [x] Add authorized discovery orchestration with normalized records and audit events.
- [x] Add Scapy/Npcap capability diagnostics and a bounded ARP adapter.
- [x] Store optional discovery response times in the device inventory.
- [x] Add the bounded TCP Connect scanner and normalized port observations.
- [x] Add scanner progress, cancellation, rate limiting, job persistence, and audit events.
- [x] Add environment-backed limits for ports, concurrency, rate, and timeout.
- [x] Add optional Nmap service/version detection with a safe subprocess boundary.
- [x] Add reusable Qt workers with progress, result, error, cancellation, and lifecycle signals.
- [x] Wire authorized Discovery and TCP Port Scanner controls into the desktop UI.
- [x] Require explicit scope confirmation and persist UI-created authorizations.
- [x] Add GUI tests for panel construction, authorization gating, and fake discovery workers.
- [x] Add psutil-based local Network Monitor with timer controls and rate calculation.
- [x] Add monitoring tests with fake providers and a rendered Qt snapshot.
- [x] Add Device Inventory with search, refresh, and CSV/JSON export.
- [x] Add evidence-based Security Assessment with deterministic rules and CSV/JSON export.
- [x] Add Reports module with JSON, CSV, and PDF export.
- [x] Add Dashboard panel with key metrics auto-refreshing from inventory/assessment.
- [x] Add live traffic charts in Network Monitor using pyqtgraph.
- [x] Add Windows packaging with PyInstaller (single-file GUI executable, ~76 MB).

## Planned modules

- [x] Network Discovery with Scapy and Npcap capability diagnostics.
- [x] TCP Connect port scanner with bounded concurrency and progress reporting.
- [x] Optional Nmap service/version adapter using a safe subprocess boundary.
- [x] Network Monitor using Windows-compatible interface statistics.
- [x] Device Inventory with CSV and JSON export.
- [x] Evidence-based Security Assessment.
- [x] JSON, CSV, and PDF reports.
- [x] Dashboard and module-specific PySide6 views (Dashboard, live charts).
- [x] Windows packaging with PyInstaller (single-file GUI executable, ~76 MB).

## Known limitations

- The desktop starts authorized Discovery and TCP Connect operations plus a
  read-only local monitor with live traffic charts. Discovery requires Scapy/Npcap
  and suitable Windows permissions.
- The default test suite uses fake adapters and generates no network traffic.
- Nmap service detection is implemented as an optional library adapter but is not
  wired into the desktop UI yet.
