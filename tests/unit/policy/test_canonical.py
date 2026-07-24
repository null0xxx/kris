"""T2.02: the §7.5 canonicalization boundary + §7.4 hash primitives.

``canonical.py`` is the SOLE I/O-permitted module in ``policy/`` (realpath +
per-component lstat). These tests model lstat with REAL ``tmp_path`` dirs and
symlinks:

- symlink resolution (``canonicalize`` follows the link to its real target);
- dangling / missing component fails CLOSED (raises) unless ``allow_missing``
  (create-intent) AND only the FINAL component is missing with an existing
  parent;
- a missing INTERIOR component still fails even with ``allow_missing``;
- ``..`` traversal collapses; a non-absolute input raises; a non-directory
  parent (ENOTDIR) fails closed;
- ``env_digest`` is order-independent + value-sensitive;
- ``action_hash`` is deterministic, key-order independent, and changes when ANY
  binding field changes (the §7.4 token binding reused verbatim by T2.03).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from lsassist.policy.canonical import (
    ActionHashError,
    CanonicalizationError,
    action_hash,
    canonicalize,
    env_digest,
)

# ---------------------------------------------------------------------------
# canonicalize — symlink resolution
# ---------------------------------------------------------------------------


def test_canonicalize_resolves_symlink_to_real_target(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    target = real_dir / "file.txt"
    target.write_text("x", encoding="utf-8")
    link = tmp_path / "link.txt"
    link.symlink_to(target)

    assert canonicalize(str(link)) == canonicalize(str(target))
    assert canonicalize(str(link)) == os.path.realpath(str(target))


def test_canonicalize_resolves_interior_symlink_component(tmp_path: Path) -> None:
    real_dir = tmp_path / "real"
    real_dir.mkdir()
    (real_dir / "f").write_text("x", encoding="utf-8")
    link_dir = tmp_path / "ld"
    link_dir.symlink_to(real_dir)

    # /ld/f resolves through the symlinked dir to /real/f.
    assert canonicalize(str(link_dir / "f")) == canonicalize(str(real_dir / "f"))


# ---------------------------------------------------------------------------
# canonicalize — dangling / create-intent fail-closed semantics
# ---------------------------------------------------------------------------


def test_canonicalize_dangling_final_fails_closed(tmp_path: Path) -> None:
    missing = tmp_path / "nope.txt"  # parent exists, final component absent
    with pytest.raises(CanonicalizationError):
        canonicalize(str(missing))


def test_canonicalize_create_intent_final_missing_parent_exists_ok(tmp_path: Path) -> None:
    missing = tmp_path / "new.txt"  # parent (tmp_path) exists, final absent
    result = canonicalize(str(missing), allow_missing=True)
    assert result == os.path.join(str(canonicalize(str(tmp_path))), "new.txt")


def test_canonicalize_create_intent_missing_interior_still_fails(tmp_path: Path) -> None:
    # parent dir itself is missing -> NOT just the final component -> fail closed.
    deep = tmp_path / "nodir" / "child.txt"
    with pytest.raises(CanonicalizationError):
        canonicalize(str(deep), allow_missing=True)


def test_canonicalize_dangling_symlink_fails_closed(tmp_path: Path) -> None:
    link = tmp_path / "badlink"
    link.symlink_to(tmp_path / "does-not-exist")
    with pytest.raises(CanonicalizationError):
        canonicalize(str(link))


def test_canonicalize_final_symlink_loop_fails_closed(tmp_path: Path) -> None:
    # C2 regression: a self-referential final-component symlink (`ln -s a a`)
    # is returned UNRESOLVED by non-strict realpath and skipped by the lstat
    # walk; it must be rejected so no symlink survives into a CanonicalPath.
    loop = tmp_path / "a"
    loop.symlink_to("a")  # relative self-loop
    assert loop.is_symlink()
    with pytest.raises(CanonicalizationError):
        canonicalize(str(loop))


def test_canonicalize_notadir_parent_fails_closed(tmp_path: Path) -> None:
    # a regular file used as a parent directory -> ENOTDIR -> fail closed even
    # under create-intent (any OSError raises the typed error).
    afile = tmp_path / "file"
    afile.write_text("x", encoding="utf-8")
    with pytest.raises(CanonicalizationError):
        canonicalize(str(afile / "child"), allow_missing=True)


# ---------------------------------------------------------------------------
# canonicalize — .. collapse + absolute-input requirement
# ---------------------------------------------------------------------------


def test_canonicalize_dotdot_collapses(tmp_path: Path) -> None:
    (tmp_path / "a").mkdir()
    (tmp_path / "b").mkdir()
    (tmp_path / "b" / "f").write_text("x", encoding="utf-8")
    spelled = tmp_path / "a" / ".." / "b" / "f"
    assert canonicalize(str(spelled)) == canonicalize(str(tmp_path / "b" / "f"))


@pytest.mark.parametrize("bad", ["", ".", "relative/path", "a/b/c", "./x"])
def test_canonicalize_rejects_non_absolute(bad: str) -> None:
    with pytest.raises(CanonicalizationError):
        canonicalize(bad)


def test_canonicalize_root_is_stable() -> None:
    assert canonicalize("/") == "/"


# ---------------------------------------------------------------------------
# env_digest — deterministic, order-independent, value-sensitive
# ---------------------------------------------------------------------------


def test_env_digest_prefix_and_determinism() -> None:
    d = env_digest({"PATH": "/usr/bin", "LANG": "C"})
    assert d.startswith("sha256:")
    assert d == env_digest({"PATH": "/usr/bin", "LANG": "C"})


def test_env_digest_key_order_independent() -> None:
    assert env_digest({"A": "1", "B": "2"}) == env_digest({"B": "2", "A": "1"})


def test_env_digest_value_and_membership_sensitive() -> None:
    base = env_digest({"A": "1"})
    assert env_digest({"A": "2"}) != base
    assert env_digest({"A": "1", "B": "2"}) != base
    assert env_digest({}) != base


def test_env_digest_injective_no_delimiter_collision() -> None:
    # C1/S1 regression: a value containing "=\n" must NOT collide with two
    # separate keys — the naive "{k}={v}\n" join made these identical blobs.
    assert env_digest({"A": "1\nB=2"}) != env_digest({"A": "1", "B": "2"})
    assert env_digest({"A": "x=y"}) != env_digest({"A": "x", "y": ""})


# ---------------------------------------------------------------------------
# action_hash — deterministic, key-order independent, per-field sensitive
# ---------------------------------------------------------------------------


def test_action_hash_prefix_and_determinism() -> None:
    a = action_hash("proc.exec", {"argv": ["pytest", "-q"]}, ["/ws"], "/ws", "sha256:e")
    b = action_hash("proc.exec", {"argv": ["pytest", "-q"]}, ["/ws"], "/ws", "sha256:e")
    assert a == b
    assert a.startswith("sha256:")


def test_action_hash_args_key_order_independent() -> None:
    a = action_hash("t", {"a": 1, "b": 2}, [], "/c", "d")
    b = action_hash("t", {"b": 2, "a": 1}, [], "/c", "d")
    assert a == b


def test_action_hash_sensitive_to_every_field() -> None:
    base = action_hash("proc.exec", {"argv": ["x"]}, ["/ws"], "/ws", "sha256:e")
    assert action_hash("proc.spawn", {"argv": ["x"]}, ["/ws"], "/ws", "sha256:e") != base
    assert action_hash("proc.exec", {"argv": ["y"]}, ["/ws"], "/ws", "sha256:e") != base
    assert action_hash("proc.exec", {"argv": ["x"]}, ["/ws2"], "/ws", "sha256:e") != base
    assert action_hash("proc.exec", {"argv": ["x"]}, ["/ws"], "/ws2", "sha256:e") != base
    assert action_hash("proc.exec", {"argv": ["x"]}, ["/ws"], "/ws", "sha256:f") != base


def test_action_hash_non_serializable_value_raises_typed_error() -> None:
    # C3 regression: a non-JSON-native value (bytes) must fail CLOSED with the
    # typed error — NOT a raw TypeError, and NOT a silent coercion (which would
    # let b"x" and "x" collide into the same binding).
    with pytest.raises(ActionHashError):
        action_hash("proc.exec", {"argv": [b"x"]}, ["/ws"], "/ws", "sha256:e")
