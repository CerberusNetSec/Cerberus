"""Storage stays behind the contract in cerberus/storage.py.

A second backend (PostgreSQL and ClickHouse for clustering) has to implement
the Store operations and nothing else. That only holds while no other module
writes SQL or reaches past the contract to the SQLite connection helpers.
"""
import ast
import inspect
import re
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from cerberus.db import Database  # noqa: E402
from cerberus.storage import Store  # noqa: E402

PACKAGE = Path(__file__).resolve().parent.parent / "cerberus"
BACKENDS = {"db.py"}  # modules allowed to speak SQL
SQL = re.compile(r"^\s*(SELECT|INSERT|UPDATE|DELETE|CREATE|DROP|ALTER|PRAGMA)\s", re.I)
LOW_LEVEL = {"q", "aq", "x", "ax", "batch", "abatch", "write", "transaction", "_search"}


def contract_methods() -> list[str]:
    return sorted(name for name, value in vars(Store).items() if callable(value) and not name.startswith("__"))


def test_sqlite_backend_implements_every_operation():
    missing = [name for name in contract_methods()
               if getattr(Database, name) is getattr(Store, name)]
    assert missing == []
    # Same keyword names as the contract, so callers can rely on them.
    for name in contract_methods():
        declared = inspect.signature(getattr(Store, name))
        if list(declared.parameters) == ["_args", "_kwargs"]:
            continue  # declared without a signature
        implemented = inspect.signature(getattr(Database, name))
        assert list(implemented.parameters) == list(declared.parameters), name


def test_no_sql_or_connection_calls_outside_the_backend():
    found = []
    for path in sorted(PACKAGE.rglob("*.py")):
        if path.name in BACKENDS:
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Constant) and isinstance(node.value, str) and SQL.match(node.value):
                found.append(f"{path.name}:{node.lineno} SQL: {node.value[:40]!r}")
            if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                    and node.func.attr in LOW_LEVEL and isinstance(node.func.value, (ast.Name, ast.Attribute))):
                owner = ast.unparse(node.func.value)
                if owner.endswith("db"):
                    found.append(f"{path.name}:{node.lineno} {owner}.{node.func.attr}()")
    assert found == []
