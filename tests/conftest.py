from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src"
HASS_SUBMODULE = ROOT / "jablotron100-api-HASS"

for path in (HASS_SUBMODULE, ROOT, SRC):
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
