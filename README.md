# NetSentinel

NetSentinel is a Windows-first desktop application for defensive network
visibility and authorized security auditing. It is being developed as a
modular Python portfolio project with a PySide6 interface, SQLite persistence,
Scapy/Npcap discovery, optional Nmap service detection, and evidence-based
reporting.

> **Development status:** NetSentinel currently provides its project shell,
> domain safety layer, SQLite persistence, and the first authorized discovery
> service. Scapy/Npcap capability diagnostics and a bounded ARP adapter are
> implemented as library components, but discovery controls are not yet wired
> into the desktop UI. The current build does **not** inspect ports, capture
> packets, or claim to implement any security assessment.

## Project goals

The project will provide a clear workflow for authorized operators:

1. Define and confirm an explicit target scope.
2. Run bounded discovery and TCP checks without blocking the interface.
3. Normalize results into a persistent device and service inventory.
4. Produce security observations only when supported by collected evidence.
5. Export reproducible JSON, CSV, and PDF reports.

NetSentinel will not include exploitation, credential attacks, brute force,
denial-of-service behavior, or unrestricted target expansion.

## Planned features

- **Network Discovery:** authorized local IPv4 discovery through Scapy and
  Npcap, including IP, MAC, OUI/vendor, hostname, latency, and state where
  available.
- **Port Scanner:** bounded TCP Connect checks with custom ports, common port
  profiles, timeouts, progress, cancellation, and optional Nmap service/version
  detection.
- **Network Monitor:** Windows-compatible interface enumeration and traffic
  counters with periodic updates and real-time charts.
- **Device Inventory:** persistent first/last-seen records, search, filtering,
  and CSV/JSON export.
- **Security Assessment:** deterministic, evidence-linked observations,
  recommendations, severity, confidence, and an explicitly heuristic risk
  score.
- **Reports:** versioned JSON and CSV exports plus PDF reports containing scope,
  timestamps, assets, ports, findings, and limitations.
- **Desktop UI:** dark PySide6 interface with navigation for Dashboard,
  Discovery, Port Scanner, Monitor, Inventory, Assessment, Reports, Settings,
  and About.

Features are added stage by stage. The checklist in [TODO.md](TODO.md) is the
source of truth for what is complete.

## Technology stack

- Python 3.12+
- PySide6
- SQLite via Python's standard-library `sqlite3`
- Scapy with Npcap on Windows for authorized local discovery
- Nmap executable for optional service and version detection
- `psutil` for interface statistics
- `pyqtgraph` for charts
- ReportLab for PDF generation
- pytest, pytest-qt, Ruff, and mypy for development quality checks

## Repository structure

```text
NetSentinel/
├── main.py
├── pyproject.toml
├── README.md
├── LICENSE
├── CHANGELOG.md
├── TODO.md
├── src/netsentinel/
│   ├── domain/          # Framework-independent models and policies
│   ├── application/     # Use cases and orchestration
│   ├── infrastructure/  # SQLite, OS, Scapy, Nmap, and logging adapters
│   ├── reporting/       # Export and report rendering
│   └── ui/              # PySide6 windows, views, and workers
├── tests/
├── assets/
└── data/                # Local runtime data, ignored by Git
```

## Requirements

- Windows 10 or Windows 11 for the primary supported environment.
- Python 3.12 or newer.
- Npcap for Scapy packet operations. Some operations may require suitable
  permissions depending on the selected interface and Windows configuration.
- Nmap installed separately and available on `PATH` or configured explicitly
  when service/version detection is enabled.
- A network scope that the operator is authorized to audit.

Npcap and Nmap are external tools with their own licensing and installation
requirements. NetSentinel does not bundle them in this repository.

## Installation

Create a virtual environment and install the project with development tools:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -e ".[dev]"
```

Check the local Python configuration without starting the GUI:

```powershell
python -m netsentinel --check-config
```

Start the current application shell:

```powershell
python -m netsentinel
```

The discovery adapter is available to application code only after the
authorization and safety-policy checks. The desktop controls for discovery and
all other scanner modules are intentionally withheld until their respective
integration, dependency, and test stages are complete.

## Development checks

Run the checks from the activated virtual environment:

```powershell
python -m pytest
ruff check .
mypy src
```

The default test suite will use fake adapters and local temporary data. It will
not scan arbitrary hosts, require Npcap, or launch Nmap. Windows/Npcap/Nmap
integration tests will be explicitly marked and opt-in.

## Configuration

Runtime configuration is read from a typed configuration object and
validated before a job starts. The current bootstrap supports these settings:

- SQLite database location and report output directory.
- Nmap executable path.
- Selected network interface.
- Timeout, retry, rate, concurrency, and maximum scope limits.
- Logging level and retention settings.

The database path can be overridden with `NETSENTINEL_DATABASE_PATH`.
Credentials and secrets will not be stored in the project configuration.

## Responsible use

NetSentinel is for defensive auditing of networks and systems where the
operator has explicit authorization. Before any active feature runs, the
application will display the normalized scope and require confirmation. Every
active operation will be bounded by policy and recorded in an audit trail.

Do not use NetSentinel to scan systems or networks without permission. The
authors are not responsible for misuse, service disruption, privacy violations,
or legal consequences caused by operating the software outside an authorized
scope.

## Documentation and contributions

The project follows a staged development process. Review [TODO.md](TODO.md) for
current work and [CHANGELOG.md](CHANGELOG.md) for verified changes. Contributions
should preserve the domain/infrastructure/UI boundaries, add tests for new
behavior, document Windows prerequisites, and avoid introducing unsafe active
operations.

Please do not submit real scan data, credentials, packet captures, or other
sensitive artifacts in issues or pull requests.

## License

NetSentinel is released under the [MIT License](LICENSE). External dependencies
remain subject to their respective licenses.
