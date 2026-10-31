"""Top-level entry point for PyInstaller and direct invocation."""
import sys
from pathlib import Path

_runtime_dir = str(Path(__file__).parent.resolve())
if _runtime_dir not in sys.path:
    sys.path.insert(0, _runtime_dir)

from hider.cli import app

if __name__ == "__main__":
    app()
