"""Hypothesis profiles for the property suite (§23.1 PT).

Registered in a conftest so the ``ci`` profile exists before the Hypothesis
pytest plugin resolves ``--hypothesis-profile=ci`` at configure time (this
conftest is an initial conftest on the path to ``tests/property/...`` args).
The ``ci`` profile raises the example budget to >=200 and disables the
per-example deadline + the function-scoped-``tmp_path`` health check (the tree
is only read, never mutated across examples).
"""

from __future__ import annotations

from hypothesis import HealthCheck, settings

settings.register_profile(
    "ci",
    max_examples=300,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
