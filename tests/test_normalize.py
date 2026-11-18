"""The case handlers, and that every lower-casing path goes through them."""

import ast
import pathlib

import pytest

from health_tech.lib.normalize import lower_case, lower_email, lower_name

SOURCE = pathlib.Path(__file__).parent.parent / "src" / "health_tech"


@pytest.mark.parametrize("handler", [lower_case, lower_email, lower_name])
@pytest.mark.parametrize(
    ("given", "stored"),
    [
        ("Sam@Example.COM", "sam@example.com"),
        ("McExample", "mcexample"),
        ("ÉLODIE", "élodie"),
        ("ØRSTED", "ørsted"),
        ("O'BRIEN-SMITH", "o'brien-smith"),
        ("张伟", "张伟"),
        ("already lower", "already lower"),
        ("", ""),
        (None, None),
    ],
)
def test_handlers_lower_case_every_script(handler, given, stored):
    assert handler(given) == stored


@pytest.mark.parametrize("handler", [lower_case, lower_email, lower_name])
def test_handlers_do_not_trim_or_otherwise_change_the_value(handler):
    assert handler("  A b  ") == "  a b  "


def test_lower_is_called_only_by_the_handlers():
    # A stray .lower() elsewhere would be a second, possibly different, lower-casing rule.
    callers = []
    for path in SOURCE.rglob("*.py"):
        for node in ast.walk(ast.parse(path.read_text())):
            if isinstance(node, ast.Attribute) and node.attr in ("lower", "casefold"):
                callers.append(f"{path.relative_to(SOURCE)}:{node.lineno}")

    # logger.py lower-cases the level name ("INFO" -> "info"), not data.
    assert [c for c in callers if not c.startswith("logger.py")] == ["lib/normalize.py:22"]
