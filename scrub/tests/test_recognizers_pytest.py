"""Wire the provided recogniser script into pytest.

The original ``test_recognizers.py`` is a standalone print-based harness (a
``CASES`` table + ``find_entities`` + a ``main()``). We keep that file untouched,
it is the foundation and still runs on its own, and simply import its data here so
the same 19 cases are collected and asserted by ``pytest`` alongside the
pseudonymisation tests.
"""

import pytest

from test_recognizers import CASES, find_entities


@pytest.mark.parametrize(
    "text,entity,should_find",
    [(text, entity, should_find) for _desc, text, entity, should_find in CASES],
    ids=[desc for desc, *_ in CASES],
)
def test_recognizer_case(text, entity, should_find):
    found = find_entities(text, entity)
    assert (entity in found) == should_find
