"""Conftest for goodhart tests — ensures an event loop is available for run_async."""
import asyncio
import pytest

from learner.learner import _reset_storage


@pytest.fixture(autouse=True)
def _ensure_event_loop():
    """Ensure asyncio.get_event_loop() works in Python 3.10+."""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)


@pytest.fixture(autouse=True)
def _reset_learner_module_state():
    """Reset module-level learner storage path between tests."""
    _reset_storage()
    yield
    _reset_storage()
