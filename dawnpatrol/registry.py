"""Plugin discovery.

Every plugin folder works identically: import each module in the package,
collect concrete subclasses of the folder's base class, and enable those whose
declared environment variables are all present.

Enablement is env-driven rather than list-driven on purpose. Adding a source
means dropping in one file and setting its variables - there is no registry to
edit and no chance of a plugin existing but never being wired up.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import os
import pkgutil
from types import ModuleType
from typing import TypeVar

from .errors import PluginError

log = logging.getLogger(__name__)

T = TypeVar("T")

SKIP_PREFIXES = ("_",)
SKIP_NAMES = {"TEMPLATE", "base"}


def _iter_modules(package: ModuleType) -> list[str]:
    names = []
    for _finder, name, _ispkg in pkgutil.iter_modules(package.__path__):
        if name.startswith(SKIP_PREFIXES) or name in SKIP_NAMES:
            continue
        names.append(name)
    return sorted(names)


def load_modules(package: ModuleType) -> list[str]:
    """Import every plugin module. A broken plugin never kills the run."""
    loaded = []
    for name in _iter_modules(package):
        full = f"{package.__name__}.{name}"
        try:
            importlib.import_module(full)
            loaded.append(full)
        except Exception as exc:  # noqa: BLE001 - a bad plugin must not be fatal
            log.error("plugin %s failed to import: %s", full, exc)
    return loaded


def _concrete_subclasses(base: type[T], package_name: str | None = None) -> list[type[T]]:
    """Concrete subclasses of ``base``, optionally restricted to one package.

    The package filter matters: ``__subclasses__`` sees every subclass loaded
    anywhere in the process, so without it a subclass defined in a test, a
    notebook, or a consumer's own code would silently register itself as a live
    plugin.
    """
    found: dict[str, type[T]] = {}
    stack = list(base.__subclasses__())
    while stack:
        cls = stack.pop()
        stack.extend(cls.__subclasses__())
        if inspect.isabstract(cls):
            continue
        if package_name and not cls.__module__.startswith(package_name + "."):
            continue
        name = getattr(cls, "name", "")
        if not name:
            log.warning("plugin class %s has no name attribute; skipped", cls.__qualname__)
            continue
        if name in found and found[name] is not cls:
            raise PluginError(
                f"duplicate plugin name {name!r}: {found[name].__module__} and {cls.__module__}"
            )
        found[name] = cls
    return [found[k] for k in sorted(found)]


def discover(package: ModuleType, base: type[T], *,
             scoped: bool = True) -> list[type[T]]:
    """Import every module in ``package`` and return its plugin classes."""
    load_modules(package)
    return _concrete_subclasses(base, package.__name__ if scoped else None)


def env_satisfied(requires: set[str] | frozenset[str]) -> tuple[bool, list[str]]:
    """A variable counts as present if it or its ``_FILE`` twin is set."""
    missing = [
        var for var in sorted(requires)
        if not os.environ.get(var) and not os.environ.get(f"{var}_FILE")
    ]
    return (not missing), missing
