"""Conftest for goodhart reporter tests — ensures an event loop exists."""
import asyncio
import pytest


@pytest.fixture(autouse=True)
def _ensure_event_loop():
    """Ensure there is a running event loop for asyncio.get_event_loop()."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    yield
