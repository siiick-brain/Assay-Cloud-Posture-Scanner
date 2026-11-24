from __future__ import annotations

import importlib.util
import sys
from pathlib import Path
from types import ModuleType

from cspm.contracts import RULE_IDS

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location("gen_rules_doc", ROOT / "scripts" / "gen_rules_doc.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules["gen_rules_doc"] = module
    spec.loader.exec_module(module)
    return module


def test_rules_doc_is_current() -> None:
    gen = _load()
    assert (ROOT / "docs" / "rules.md").read_text(encoding="utf-8") == gen.render(), (
        "run python scripts/gen_rules_doc.py"
    )
    assert gen.main(["--check"]) == 0


def test_rules_doc_lists_every_rule() -> None:
    text = _load().render()
    assert all(f"## {r.id}" in text for r in RULE_IDS)
