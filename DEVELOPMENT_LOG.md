# Development Log

This log records verified project milestones. Dates for earlier milestones are not
reconstructed from memory; their authoritative timestamps remain in Git history.

## Verified milestones

- **Repository bootstrap** — Commit `0153a67` (`Initialize NetSentinel repository`).
  Created the Python package layout, development tooling, MIT license, README,
  Qt shell, and configuration bootstrap.
- **Safety and scope foundations** — Commit `fc78ef3`
  (`Add scope validation and safety policies`). Added bounded IPv4 scope and port
  validation, explicit authorization, local-only defaults, cancellation, and rate
  limiting.
- **SQLite persistence** — Commit `a10c420`
  (`Add SQLite persistence and audit storage`). Added versioned migrations, WAL,
  parameterized repositories, inventory persistence, and audit storage.

## 2026-11-13

- Implemented the first Network Discovery application service.
- Added a typed discovery adapter contract and normalized discovery records.
- Added duplicate-address merging, authorized-scope enforcement, cancellation
  checkpoints, and discovery audit events.
- Added Scapy/Npcap capability diagnostics without generating traffic during the
  check.
- Added a bounded Scapy ARP adapter that operates only on concrete hosts supplied
  by the already-authorized scope.
- Added SQLite migration version 2 for optional discovery response times.
- Added fake-adapter tests for normalization, persistence, authorization ordering,
  out-of-scope evidence, and invalid evidence.
- Updated README, CHANGELOG, and TODO to reflect the verified capability boundary.
- Implemented the bounded TCP Connect scanner service and socket adapter.
- Added conservative open, closed, and filtered state mapping from `connect_ex`.
- Added bounded worker scheduling, rate limiting, cancellation checkpoints,
  progress events, job lifecycle persistence, and audit events.
- Extended configuration with environment-backed port, concurrency, rate, and
  timeout limits.
- Added fake-probe tests for concurrency orchestration, progress, cancellation,
  authorization ordering, normalization, and persistence.
- Implemented optional Nmap service/version detection with fixed argument vectors,
  executable diagnostics, XML parsing, output limits, cancellation, and process
  timeouts.
- Added fake-process and controlled-XML tests that verify no shell execution and
  no Nmap process start after cancellation.
- Added reusable Qt workers and a manager for queued execution, progress, errors,
  cancellation, duplicate-job rejection, and lifecycle cleanup.
- Verification: `pytest` — 52 passed; `ruff check .` — passed; `mypy src` — passed.

## Next work

- Wire authorized discovery and scan controls into the desktop UI.
- Add the first end-to-end GUI test for an authorized background operation.
- Keep desktop controls disabled until the corresponding integration tests and
  authorization flow are complete.
