"""Conftest for goodhart config tests — restores CWD between tests."""
import os
import pytest


@pytest.fixture(autouse=True)
def _restore_cwd():
    """Save and restore CWD around each test to prevent cross-test pollution."""
    saved = os.getcwd()
    yield
    try:
        os.chdir(saved)
    except (FileNotFoundError, OSError):
        # CWD was deleted during test; restore to a known-good directory
        os.chdir(os.path.dirname(os.path.abspath(__file__)))
