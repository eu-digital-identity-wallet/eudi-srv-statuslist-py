"""Test helpers to override the configuration in every app module.

Each module does ``from app.config import CONFIGURATION``, so a test that
needs a specific configuration must rebind the name in all of them.
"""

from __future__ import annotations

import importlib
import pkgutil
from functools import lru_cache
from types import ModuleType
from typing import Any, Tuple

import app


@lru_cache(maxsize=1)
def configuration_modules() -> Tuple[ModuleType, ...]:
    """Returns every ``app`` module that has a ``CONFIGURATION`` attribute.

    Returns:
        The modules (imported once and cached).
    """
    modules = [app] + [
        importlib.import_module(m.name) for m in pkgutil.walk_packages(app.__path__, "app.")
    ]
    return tuple(m for m in modules if hasattr(m, "CONFIGURATION"))


def set_configuration(monkeypatch: Any, config: Any) -> Any:
    """Replaces ``CONFIGURATION`` in every app module for the current test.

    Args:
        monkeypatch: pytest ``monkeypatch`` fixture.
        config: Replacement configuration.

    Returns:
        ``config``.
    """
    for module in configuration_modules():
        monkeypatch.setattr(module, "CONFIGURATION", config)
    return config
