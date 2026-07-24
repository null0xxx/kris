"""§23.1 PT: canonicalization is invariant to the input SPELLING.

A path's classification-relevant canonical form must not depend on how the
caller spelled it. Against a FIXED, fully-existing in-``tmp_path`` canonical
target (whose components include unicode + spaces), Hypothesis generates
adversarial-but-equivalent spellings — extra ``/``, ``.`` segments, an
existing-dir ``<dir>/../<dir>`` round-trip that provably cancels, and trailing
slashes — and asserts ``canonicalize(spelling) == canonicalize(canonical)``.

The ``<dir>/../<dir>`` round-trip only ever uses REAL directory components of
the target (never a symlink, never the final file), so the rewrite is a pure
path-equivalence that both sides resolve identically. Run with
``--hypothesis-profile=ci`` for >=200 examples (see ``tests/property/conftest``).
"""
# Unicode component names (greek/accented letters, spaces) are the POINT of this
# property test, so the ambiguous-confusable lint is intentionally suppressed.
# ruff: noqa: RUF001

from __future__ import annotations

from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from lsassist.policy.canonical import canonicalize


def _build_target(tmp_path: Path) -> Path:
    """A fixed, fully-existing target with unicode + space components.

    Idempotent across Hypothesis examples (tmp_path is reused): ``exist_ok`` +
    overwrite mean no per-example mutation of the tree's shape.
    """
    deep = tmp_path / "αlpha" / "sub dir" / "déep"
    deep.mkdir(parents=True, exist_ok=True)
    target = deep / "réal.txt"
    target.write_text("x", encoding="utf-8")
    return target


@st.composite
def _equivalent_spelling(draw: st.DrawFn, segs: list[str]) -> str:
    """Build a spelling equivalent to ``/<segs...>`` via equivalence-preserving
    rewrites (all resolve to the same realpath)."""
    out = ""
    for i, seg in enumerate(segs):
        is_last = i == len(segs) - 1
        out += draw(st.sampled_from(["/", "//", "/./", "/.//./"]))
        # A <dir>/../<dir> round-trip cancels ONLY for real, non-symlink dirs:
        # every non-final component of the target is exactly that.
        if not is_last and draw(st.booleans()):
            out += seg + "/../" + seg
        else:
            out += seg
    out += draw(st.sampled_from(["", "/", "/.", "/./", "//"]))
    return out


@settings(suppress_health_check=[HealthCheck.function_scoped_fixture], deadline=None)
@given(data=st.data())
def test_canonicalize_invariant_to_spelling(tmp_path: Path, data: st.DataObject) -> None:
    target = _build_target(tmp_path)
    segs = [s for s in str(target).split("/") if s]
    spelling = data.draw(_equivalent_spelling(segs))

    canonical = canonicalize(str(target))
    assert canonicalize(spelling) == canonical


def test_canonicalize_invariant_concrete_examples(tmp_path: Path) -> None:
    """Deterministic sanity anchors for the property above."""
    target = _build_target(tmp_path)
    base = str(target)
    canonical = canonicalize(base)

    assert canonicalize(base + "/") == canonical
    assert canonicalize(base.replace("/déep/", "/déep/./")) == canonical
    assert canonicalize(base.replace("/αlpha/", "/αlpha/../αlpha/")) == canonical
    assert canonicalize(base.replace("/sub dir/", "//sub dir//")) == canonical
