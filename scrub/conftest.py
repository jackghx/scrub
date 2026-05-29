"""pytest bootstrap.

Puts the package root (this directory) and the ``tests`` directory on
``sys.path`` so the flat imports used throughout the project work no matter
which directory ``pytest`` is launched from:

    from security_recognizers import get_security_recognizers   # package root
    from pseudonymizer import pseudonymize, restore             # package root
    from test_recognizers import CASES, find_entities           # tests/

This keeps the project runnable with a plain ``pytest`` and **no install step**,
in line with the local-first, zero-friction goal.
"""

import os
import sys

_HERE = os.path.dirname(os.path.abspath(__file__))

for _path in (_HERE, os.path.join(_HERE, "tests")):
    if _path not in sys.path:
        sys.path.insert(0, _path)
