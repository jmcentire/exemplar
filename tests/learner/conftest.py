"""Test conftest for learner — resets module-level state between tests."""
import pytest


@pytest.fixture(autouse=True)
def _reset_learner_module_state(tmp_path):
    """Reset module-level learner storage path between tests.

    Sets _storage_path to a fresh tmp dir so tests don't see any
    leftover state from the working directory or prior tests.
    """
    from learner.learner import _reset_storage
    import learner.learner as _mod

    # Point at a clean, empty tmp directory so that functions
    # expecting no state.json actually find none.
    _mod._storage_path = str(tmp_path / ".exemplar" / "learner")
    yield
    _reset_storage()
