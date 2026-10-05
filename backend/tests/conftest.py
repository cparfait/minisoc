import os
import sys
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
RULES_DIR = Path(__file__).parent.parent / "rules"

sys.path.insert(0, str(Path(__file__).parent))
os.environ.setdefault("MINISOC_MASTER_KEY", "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8")
os.environ.setdefault("MINISOC_RULES_DIR", str(RULES_DIR))


@pytest.fixture
def sophos_lines() -> list[str]:
    return (FIXTURES / "sophos.log").read_text(encoding="utf-8").splitlines()
