"""Root conftest — configure import paths for tests."""
import importlib
import sys
import types
from pathlib import Path

# Add src/ to sys.path so `config.config` works
_src = str(Path(__file__).parent / "src")
if _src not in sys.path:
    sys.path.insert(0, _src)

# Make `exemplar.*` resolve to packages in src/
_exemplar = types.ModuleType("exemplar")
_exemplar.__path__ = []  # mark as package
sys.modules.setdefault("exemplar", _exemplar)

_PKG_NAMES = [
    "config", "governance", "intake", "circuit",
    "assessor", "learner", "schemas", "mcp_server", "cli", "reporter",
    "reviewers",
]

for _name in _PKG_NAMES:
    try:
        _pkg = importlib.import_module(_name)
        setattr(_exemplar, _name, _pkg)
        sys.modules.setdefault(f"exemplar.{_name}", _pkg)
    except Exception:
        pass
