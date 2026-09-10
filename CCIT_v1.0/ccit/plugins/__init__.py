"""
CCIT Plugin System
Plugins are Python modules placed in this directory.
Each plugin must define a `CCITPlugin` class with:
    - name: str
    - description: str
    - version: str
    - def run(self, context: dict) -> dict
"""

import importlib
import importlib.util
import os
from typing import Any


def load_plugins() -> list[Any]:
    """Discover and load all plugin modules from this directory."""
    plugins = []
    plugin_dir = os.path.dirname(__file__)
    for fname in sorted(os.listdir(plugin_dir)):
        if fname.startswith("_") or not fname.endswith(".py"):
            continue
        module_name = fname[:-3]
        spec = importlib.util.spec_from_file_location(
            f"plugins.{module_name}",
            os.path.join(plugin_dir, fname),
        )
        if spec and spec.loader:
            try:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                if hasattr(module, "CCITPlugin"):
                    plugins.append(module.CCITPlugin())
            except Exception as exc:
                print(f"[PLUGIN] Failed to load {module_name}: {exc}")
    return plugins
