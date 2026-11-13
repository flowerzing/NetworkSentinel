"""Tests for Qt worker execution and cancellation plumbing."""

from threading import Event
from time import sleep
from uuid import uuid4

import pytest

from netsentinel.application.control import CancellationToken
from netsentinel.application.events import ProgressEvent
from netsentinel.ui.workers import Worker, WorkerManager


def test_worker_translates_success_and_progress_events() -> None:
    job_id = uuid4()
    results = []
    progress = []
    finished = []

    def operation(token: CancellationToken, emit) -> object:
        emit(ProgressEvent(job_id, 1, 1, "done"))
        return "result"

    worker = Worker(job_id, operation)
    worker.signals.result.connect(results.append)
    worker.signals.progress.connect(progress.append)
    worker.signals.finished.connect(finished.append)
    worker.run()

    assert results == ["result"]
    assert progress[0].job_id == job_id
    assert finished == [job_id]


def test_worker_translates_expected_error() -> None:
    errors = []
    finished = []
    worker = Worker(uuid4(), lambda token, emit: _raise_runtime_error())
    worker.signals.error.connect(errors.append)
    worker.signals.finished.connect(finished.append)
    worker.run()

    assert len(errors) == 1
    assert errors[0].message == "controlled failure"
    assert errors[0].recoverable is True
    assert finished == [worker.job_id]


def test_worker_translates_cancellation() -> None:
    cancelled = []
    errors = []
    worker = Worker(uuid4(), _cancelled_operation)
    worker.signals.cancelled.connect(cancelled.append)
    worker.signals.error.connect(errors.append)
    worker.cancel()
    worker.run()

    assert cancelled == [worker.job_id]
    assert errors == []


def test_worker_manager_runs_off_gui_thread_and_releases_job(qtbot) -> None:
    manager = WorkerManager()
    job_id = uuid4()
    results = []
    worker = Worker(job_id, lambda token, emit: "background result")
    worker.signals.result.connect(results.append)

    with qtbot.waitSignal(manager.worker_finished, timeout=3000) as blocker:
        manager.start(worker)

    assert blocker.args == [job_id]
    assert results == ["background result"]
    assert manager.active_job_ids == ()


def test_worker_manager_can_cancel_an_active_job(qtbot) -> None:
    manager = WorkerManager()
    job_id = uuid4()
    started = Event()

    def operation(token: CancellationToken, emit) -> object:
        started.set()
        while not token.is_cancelled:
            sleep(0.01)
        token.raise_if_cancelled()
        return None

    worker = Worker(job_id, operation)
    with qtbot.waitSignal(manager.worker_finished, timeout=3000):
        manager.start(worker)
        qtbot.waitUntil(started.is_set, timeout=1000)
        assert manager.cancel(job_id) is True

    assert manager.cancel(job_id) is False
    assert manager.active_job_ids == ()


def test_worker_manager_rejects_duplicate_job_ids(qtbot) -> None:
    manager = WorkerManager()
    job_id = uuid4()
    started = Event()
    release = Event()

    def operation(token: CancellationToken, emit) -> object:
        started.set()
        release.wait(1)
        return None

    worker = Worker(job_id, operation)
    manager.start(worker)
    qtbot.waitUntil(started.is_set, timeout=1000)
    with pytest.raises(ValueError, match="already exists"):
        manager.start(worker)
    with qtbot.waitSignal(manager.worker_finished, timeout=3000):
        release.set()


def _raise_runtime_error() -> object:
    raise RuntimeError("controlled failure")


def _cancelled_operation(token: CancellationToken, emit) -> object:
    token.raise_if_cancelled()
    raise AssertionError("cancelled operation should not continue")
