"""Test conftest — ensure event loop is available for sync tests using asyncio."""
import asyncio
import sys

import pytest


@pytest.fixture(autouse=True)
def _ensure_event_loop():
    """Ensure asyncio.get_event_loop() works in sync test contexts (Python 3.12+)."""
    try:
        asyncio.get_event_loop()
    except RuntimeError:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
