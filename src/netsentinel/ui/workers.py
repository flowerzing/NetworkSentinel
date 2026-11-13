"""Qt workers for running authorized application services off the GUI thread."""

from __future__ import annotations

from collections.abc import Callable
from threading import Lock
from typing import Any
from uuid import UUID

from PySide6.QtCore import QObject, QRunnable, QThreadPool, Signal

from netsentinel.application.control import CancellationToken
from netsentinel.application.events import JobErrorEvent, ProgressEvent
from netsentinel.domain.errors import OperationCancelled

WorkerFunction = Callable[
    [CancellationToken, Callable[[ProgressEvent], None]],
    object,
]


class WorkerSignals(QObject):
    """Signals emitted by a background worker and delivered to the GUI thread."""

    progress = Signal(object)
    result = Signal(object)
    error = Signal(object)
    cancelled = Signal(object)
    finished = Signal(object)


class Worker(QRunnable):
    """Run one application operation with cooperative cancellation."""

    def __init__(self, job_id: UUID, function: WorkerFunction) -> None:
        super().__init__()
        self.job_id = job_id
        self.signals = WorkerSignals()
        self._function = function
        self._cancellation = CancellationToken()

    @property
    def is_cancelled(self) -> bool:
        """Return whether cancellation has been requested for this worker."""
        return self._cancellation.is_cancelled

    def cancel(self) -> None:
        """Request cancellation without blocking the GUI thread."""
        self._cancellation.cancel()

    def run(self) -> None:
        """Execute the operation and translate expected failures into events."""
        try:
            result = self._function(self._cancellation, self.signals.progress.emit)
        except OperationCancelled:
            self.signals.cancelled.emit(self.job_id)
        except Exception as exc:
            message = str(exc).strip() or type(exc).__name__
            self.signals.error.emit(
                JobErrorEvent(
                    job_id=self.job_id,
                    message=message,
                    recoverable=True,
                )
            )
        else:
            self.signals.result.emit(result)
        finally:
            self.signals.finished.emit(self.job_id)


class WorkerManager(QObject):
    """Own active workers and expose safe start/cancel operations."""

    worker_started = Signal(object)
    worker_finished = Signal(object)

    def __init__(self, pool: QThreadPool | None = None) -> None:
        super().__init__()
        self._pool = pool or QThreadPool.globalInstance()
        self._workers: dict[UUID, Worker] = {}
        self._lock = Lock()

    @property
    def active_job_ids(self) -> tuple[UUID, ...]:
        """Return a stable snapshot of currently registered jobs."""
        with self._lock:
            return tuple(self._workers)

    def start(self, worker: Worker) -> None:
        """Register and enqueue one worker, rejecting duplicate job IDs."""
        with self._lock:
            if worker.job_id in self._workers:
                raise ValueError(f"A worker already exists for job {worker.job_id}")
            self._workers[worker.job_id] = worker
        worker.signals.finished.connect(self._on_worker_finished)
        self._pool.start(worker)
        self.worker_started.emit(worker.job_id)

    def cancel(self, job_id: UUID) -> bool:
        """Request cancellation and report whether the job was active."""
        with self._lock:
            worker = self._workers.get(job_id)
        if worker is None:
            return False
        worker.cancel()
        return True

    def _on_worker_finished(self, job_id: Any) -> None:
        if not isinstance(job_id, UUID):
            return
        with self._lock:
            self._workers.pop(job_id, None)
        self.worker_finished.emit(job_id)
