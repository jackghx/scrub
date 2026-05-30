"""Scrub, the local-first security-artefact sanitiser.

This file makes ``scrub`` an importable package so the ``scrub`` console script
(``scrub.cli:main``) resolves after ``pip install -e .``. The modules inside this
package import each other *flat* (``from scrubber import Scrubber``); ``cli.py``
bootstraps ``sys.path`` with this directory so those imports work in every entry path
(console script, ``python -m``, pytest) without modifying the core modules.
"""

__version__ = "0.3.1"
