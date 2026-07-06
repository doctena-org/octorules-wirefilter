"""The shipped ``octorules_wirefilter.pyi`` stub must exist, parse, and
describe functions the extension module actually exports."""

import ast
from pathlib import Path

import octorules_wirefilter

_STUB = Path(__file__).resolve().parent.parent / "octorules_wirefilter.pyi"


def _stub_functions() -> set[str]:
    tree = ast.parse(_STUB.read_text())
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef)}


def test_stub_exists_and_parses():
    assert _STUB.is_file()
    ast.parse(_STUB.read_text())


def test_stub_covers_the_public_api():
    assert {"parse_expression", "get_schema_info"} <= _stub_functions()


def test_stub_functions_exist_in_module():
    for name in _stub_functions():
        assert callable(getattr(octorules_wirefilter, name)), name
