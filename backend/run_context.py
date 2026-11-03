"""Which simulation run (if any) the current thread is executing.

The runner sets this once; `record_event` and the investigation service read it, so every event and investigation a run
creates is tagged with its run id without changing the ingestion function signatures.
"""
from contextlib import contextmanager
from contextvars import ContextVar

_current: ContextVar[int | None] = ContextVar("simulation_run_id", default=None)


def current_run_id() -> int | None:
    return _current.get()


@contextmanager
def in_run(run_id: int):
    token = _current.set(run_id)
    try:
        yield
    finally:
        _current.reset(token)
