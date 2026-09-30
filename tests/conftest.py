from __future__ import annotations

import json
from pathlib import Path

FIXTURES = Path(__file__).parent / "fixtures"


def load_fixture(name: str):
    """Return the parsed JSON body of tests/fixtures/<name>."""
    return json.loads((FIXTURES / name).read_text())


def load_fixture_text(name: str) -> str:
    """Return the raw text of tests/fixtures/<name>."""
    return (FIXTURES / name).read_text()
