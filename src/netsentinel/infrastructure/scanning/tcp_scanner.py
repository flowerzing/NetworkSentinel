"""Bounded TCP Connect scanner implemented with standard-library sockets."""

from __future__ import annotations

import errno
import socket
from collections.abc import Callable, Iterator
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import UTC, datetime
from ipaddress import IPv4Address
from uuid import UUID

from netsentinel.application.control import CancellationToken, RateLimiter
from netsentinel.application.events import ProgressEvent
from netsentinel.application.port_scanning import ProgressCallback
from netsentinel.domain.enums import EvidenceSource
from netsentinel.domain.models import PortObservation

type ProbeFunction = Callable[[IPv4Address, int, float], str]


class TcpConnectScanner:
    """Scan a fixed host/port work set with bounded worker concurrency."""

    def __init__(self, probe: ProbeFunction | None = None) -> None:
        self._probe = probe or _probe_tcp

    def scan(
        self,
        hosts: tuple[IPv4Address, ...],
        ports: tuple[int, ...],
        *,
        timeout_seconds: float,
        max_concurrency: int,
        rate_limiter: RateLimiter,
        cancellation: CancellationToken,
        job_id: UUID,
        progress: ProgressCallback | None = None,
    ) -> tuple[PortObservation, ...]:
        """Probe every work item without creating more than bounded workers."""
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        if max_concurrency < 1:
            raise ValueError("max_concurrency must be positive")

        total = len(hosts) * len(ports)
        if total == 0:
            return ()

        tasks = ((address, port) for address in hosts for port in ports)
        pending: dict[Future[PortObservation], tuple[IPv4Address, int]] = {}
        results: list[PortObservation] = []
        completed = 0
        executor = ThreadPoolExecutor(max_workers=max_concurrency)
        try:
            _fill_pending(
                pending,
                tasks,
                executor,
                max_concurrency,
                self._probe,
                timeout_seconds,
                rate_limiter,
                cancellation,
                job_id,
            )
            while pending:
                cancellation.raise_if_cancelled()
                done, _ = wait(
                    tuple(pending),
                    timeout=0.1,
                    return_when=FIRST_COMPLETED,
                )
                if not done:
                    continue
                for future in done:
                    address, port = pending.pop(future)
                    observation = future.result()
                    results.append(observation)
                    completed += 1
                    if progress is not None:
                        progress(
                            ProgressEvent(
                                job_id=job_id,
                                completed=completed,
                                total=total,
                                message=(
                                    f"Checked {address}:{port} "
                                    f"({observation.state})"
                                ),
                            )
                        )
                _fill_pending(
                    pending,
                    tasks,
                    executor,
                    max_concurrency,
                    self._probe,
                    timeout_seconds,
                    rate_limiter,
                    cancellation,
                    job_id,
                )
        finally:
            for future in pending:
                future.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        return tuple(sorted(results, key=lambda item: (int(item.address), item.port)))


def _fill_pending(
    pending: dict[Future[PortObservation], tuple[IPv4Address, int]],
    tasks: Iterator[tuple[IPv4Address, int]],
    executor: ThreadPoolExecutor,
    max_concurrency: int,
    probe: ProbeFunction,
    timeout_seconds: float,
    rate_limiter: RateLimiter,
    cancellation: CancellationToken,
    job_id: UUID,
) -> None:
    """Keep only a bounded number of futures queued at a time."""
    while len(pending) < max_concurrency:
        cancellation.raise_if_cancelled()
        try:
            address, port = next(tasks)
        except StopIteration:
            return
        future = executor.submit(
            _run_probe,
            probe,
            address,
            port,
            timeout_seconds,
            rate_limiter,
            cancellation,
        )
        pending[future] = (address, port)


def _run_probe(
    probe: ProbeFunction,
    address: IPv4Address,
    port: int,
    timeout_seconds: float,
    rate_limiter: RateLimiter,
    cancellation: CancellationToken,
) -> PortObservation:
    rate_limiter.wait(cancellation)
    cancellation.raise_if_cancelled()
    state = probe(address, port, timeout_seconds)
    if state not in {"open", "closed", "filtered"}:
        raise ValueError(f"Probe returned an unsupported state: {state!r}")
    return PortObservation(
        address=address,
        port=port,
        protocol="tcp",
        state=state,
        source=EvidenceSource.SOCKET,
        observed_at=datetime.now(UTC),
    )


def _probe_tcp(address: IPv4Address, port: int, timeout_seconds: float) -> str:
    """Return an evidence-based TCP state from one connect_ex attempt."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
            connection.settimeout(timeout_seconds)
            result = connection.connect_ex((str(address), port))
    except OSError as exc:
        return _state_from_code(_error_code(exc))
    return _state_from_code(result)


def _error_code(error: OSError) -> int:
    return int(getattr(error, "winerror", None) or error.errno or 0)


def _state_from_code(code: int) -> str:
    """Map platform socket results to conservative scanner states."""
    if code == 0:
        return "open"
    if code in {
        errno.ECONNREFUSED,
        errno.ECONNRESET,
        10054,  # WSAECONNRESET
        10061,  # WSAECONNREFUSED
    }:
        return "closed"
    return "filtered"
