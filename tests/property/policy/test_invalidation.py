"""§23.1 PT: recheck has NO "stale-but-valid" middle state (§7.5 step 3, I6).

Modelled entirely over a PURE fake ``FsView`` (no real I/O): each example builds
a pristine snapshot for a set of canonical paths, then applies an arbitrary
SEQUENCE of filesystem mutations (symlink retarget, parent rename+recreate,
atomic file-swap/rename-over, delete, and content/no-op non-events). The
properties assert the bijection between "did anything PATH/NODE-relevant
change?" and the verdict:

- single path: :func:`recheck` returns EXACTLY the verdict predicted by the
  first-failure priority
  ``exists -> re-resolves-to-self -> parent (dev,ino) -> node (dev,ino)``
  (pins the deterministic ordering, not merely non-VALID);
- many paths: the result is :data:`VALID` IFF every path is clean, else it is
  one of the invalid verdicts — there is no third "stale-but-valid" outcome;
- positive control: a content/no-op-only sequence is ALWAYS :data:`VALID`.

The atomic file-swap vector ("swap": SAME path + SAME parent, NEW node inode) is
INCLUDED — it is the C1 regression modelled at the pure level.

Run with ``--hypothesis-profile=ci`` for >=200 examples (see
``tests/property/conftest``).
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from hypothesis import given
from hypothesis import strategies as st

from lsassist.policy.recheck import (
    PathSnapshot,
    RecheckVerdict,
    recheck,
    snapshot_paths,
)


@dataclass
class _Entry:
    exists: bool
    realpath: str
    parent: tuple[int, int]
    node: tuple[int, int]


class _FakeFsView:
    """Pure in-memory ``FsView`` — mutated by the modelled fs operations."""

    def __init__(self, entries: dict[str, _Entry]) -> None:
        self.entries = entries

    def realpath(self, path: str) -> str:
        return self.entries[path].realpath

    def parent_ids(self, path: str) -> tuple[int, int]:
        return self.entries[path].parent

    def node_ids(self, path: str) -> tuple[int, int]:
        return self.entries[path].node

    def exists(self, path: str) -> bool:
        return self.entries[path].exists


# The modelled fs mutations: four are (path/node)-relevant invalidators, one
# ("content") is deliberately NOT (in-place content integrity is step 4's job).
_MUTATIONS = ("delete", "retarget", "reparent", "swap", "content")


def _apply(entry: _Entry, mutation: str, tag: int) -> _Entry:
    """Deterministically transform one path's state by ``mutation``.

    ``tag`` makes retarget/reparent/swap produce values PROVABLY distinct from
    the pristine canonical path / parent ids / node ids, so the ground-truth
    predicate below is unambiguous.
    """
    if mutation == "delete":
        return replace(entry, exists=False)
    if mutation == "retarget":
        # Final component became/retargeted a symlink: still present, but now
        # re-resolves to a DIFFERENT real path.
        return replace(entry, exists=True, realpath=f"/RETARGET/{tag}")
    if mutation == "reparent":
        # Parent dir renamed+recreated: fresh (dev, ino), path re-resolves fine.
        return replace(entry, exists=True, parent=(1000 + tag, 2000 + tag))
    if mutation == "swap":
        # Atomic rename-over: SAME path + SAME parent, but a NEW node inode.
        return replace(entry, exists=True, node=(5000 + tag, 6000 + tag))
    # "content": no path/node-relevant change whatsoever (no-op for recheck).
    return entry


def _predict_single(snapshot: PathSnapshot, entry: _Entry) -> RecheckVerdict:
    """The exact verdict the first-failure priority must yield for one path."""
    if not entry.exists:
        return RecheckVerdict.DANGLING
    if entry.realpath != snapshot.canonical_path:
        return RecheckVerdict.PATH_RETARGETED
    if entry.parent != (snapshot.parent_dev, snapshot.parent_ino):
        return RecheckVerdict.PARENT_SWAPPED
    if entry.node != (snapshot.node_dev, snapshot.node_ino):
        return RecheckVerdict.NODE_REPLACED
    return RecheckVerdict.VALID


@st.composite
def _single_path_scenario(
    draw: st.DrawFn,
) -> tuple[tuple[PathSnapshot, ...], _FakeFsView, RecheckVerdict]:
    canonical = "/ws/" + draw(st.sampled_from(["a", "b", "c/d", "deep/nested/x"]))
    parent = (draw(st.integers(1, 9)), draw(st.integers(1, 999)))
    node = (draw(st.integers(1, 9)), draw(st.integers(1, 999)))
    entry = _Entry(exists=True, realpath=canonical, parent=parent, node=node)
    fs = _FakeFsView({canonical: entry})
    snapshots = snapshot_paths([canonical], fs)

    mutations = draw(st.lists(st.sampled_from(_MUTATIONS), max_size=6))
    for i, mutation in enumerate(mutations):
        fs.entries[canonical] = _apply(fs.entries[canonical], mutation, tag=i)

    expected = _predict_single(snapshots[0], fs.entries[canonical])
    return snapshots, fs, expected


@given(scenario=_single_path_scenario())
def test_single_path_recheck_matches_first_failure_priority(
    scenario: tuple[tuple[PathSnapshot, ...], _FakeFsView, RecheckVerdict],
) -> None:
    snapshots, fs, expected = scenario
    assert recheck(snapshots, fs) is expected


@st.composite
def _multi_path_scenario(
    draw: st.DrawFn,
) -> tuple[tuple[PathSnapshot, ...], _FakeFsView, bool]:
    names = draw(
        st.lists(st.sampled_from(["a", "b", "c", "d", "e"]), min_size=1, max_size=5, unique=True)
    )
    entries: dict[str, _Entry] = {}
    for j, name in enumerate(names):
        canonical = "/ws/" + name
        entries[canonical] = _Entry(
            exists=True,
            realpath=canonical,
            parent=(1 + j, 100 + j),
            node=(1 + j, 500 + j),
        )
    fs = _FakeFsView(dict(entries))
    canonicals = list(entries.keys())
    snapshots = snapshot_paths(canonicals, fs)

    all_clean = True
    for i, canonical in enumerate(canonicals):
        mutation = draw(st.sampled_from((*_MUTATIONS, "noop")))
        if mutation not in ("content", "noop"):
            fs.entries[canonical] = _apply(fs.entries[canonical], mutation, tag=i)
            all_clean = False
    return snapshots, fs, all_clean


@given(scenario=_multi_path_scenario())
def test_multi_path_valid_iff_all_clean_no_middle_state(
    scenario: tuple[tuple[PathSnapshot, ...], _FakeFsView, bool],
) -> None:
    snapshots, fs, all_clean = scenario
    verdict = recheck(snapshots, fs)
    if all_clean:
        assert verdict is RecheckVerdict.VALID
    else:
        # Any path/node-relevant mutation ⇒ NON-VALID (an invalid verdict);
        # there is no third "stale-but-valid" state.
        assert verdict is not RecheckVerdict.VALID
        assert verdict in {
            RecheckVerdict.DANGLING,
            RecheckVerdict.PATH_RETARGETED,
            RecheckVerdict.PARENT_SWAPPED,
            RecheckVerdict.NODE_REPLACED,
        }


@given(
    names=st.lists(st.sampled_from(["a", "b", "c"]), min_size=1, max_size=3, unique=True),
    ops=st.lists(st.sampled_from(["content", "noop"]), max_size=6),
)
def test_content_and_noop_only_is_always_valid(names: list[str], ops: list[str]) -> None:
    """Positive control: no path/node-relevant mutation ever ⇒ always VALID."""
    entries = {
        "/ws/"
        + name: _Entry(
            exists=True, realpath="/ws/" + name, parent=(1 + j, 7 + j), node=(1 + j, 900 + j)
        )
        for j, name in enumerate(names)
    }
    fs = _FakeFsView(dict(entries))
    snapshots = snapshot_paths(list(entries.keys()), fs)
    # content/no-op events never touch existence / realpath / parent / node ids.
    assert recheck(snapshots, fs) is RecheckVerdict.VALID
