"""The taint gate is split into modules (audit 16) without changing behaviour or the start-up budget; each load
computes its own paths (tests reload it with different env)."""
import ast
import sys
from pathlib import Path

from test_taint_gate import HOOK, load_hook_module

HOOKS = HOOK.parent
MODULES = ("tg_core", "tg_lexer", "tg_classify", "tg_state", "tg_provenance", "tg_hooks")


def test_modules_exist_and_entry_is_thin():
    for m in MODULES:
        assert (HOOKS / (m + ".py")).exists(), m
    assert len(HOOK.read_text().splitlines()) <= 200


def test_functions_are_short_except_tokenize():
    long_ = []
    for p in [HOOK] + [HOOKS / (m + ".py") for m in MODULES]:
        for n in ast.walk(ast.parse(p.read_text())):
            if isinstance(n, ast.FunctionDef) and n.name != "tokenize" and n.end_lineno - n.lineno + 1 > 50:
                long_.append("%s:%s" % (p.name, n.name))
    assert long_ == []


def test_each_load_computes_its_own_paths(tmp_path):
    a = load_hook_module(SENTINEL_ATLAS=str(tmp_path / "one"))
    b = load_hook_module(SENTINEL_ATLAS=str(tmp_path / "two"))
    assert any(str(tmp_path / "one") in c for c in a.MONITOR_COMMANDS)
    assert any(str(tmp_path / "two") in c for c in b.MONITOR_COMMANDS)


def test_provenance_is_loaded_only_when_needed():
    sys.modules.pop("tg_provenance", None)
    load_hook_module()
    assert "tg_provenance" not in sys.modules
