"""§4.3 loop detection: identical ``action_hash`` 3x consecutive → halt (T2.08).

SPEC §4.3, verbatim::

    Loop detection: `action_hash` (tool+normalized args+cwd) 3x consecutive
    identical → halt → REPORT with `loop_detected` evidence.

EXACT SEMANTICS (each choice is a place the rule could be read wrongly):

- **The key is the T2.02 ``action_hash``.** :func:`LoopTracker.observe` accepts
  ONLY a ``sha256:<64 lowercase hex>`` string, i.e. exactly what
  :func:`lsassist.policy.canonical.action_hash` produces over
  ``{tool, args_normalized, canonical_paths, cwd_real, env_digest}``. Anything
  else fails closed. Feeding, say, a bare tool name would collapse every read
  into "the same action" and halt a legitimate multi-file plan; feeding an
  un-normalized repr would make two identical actions look different and
  disable detection entirely. Both failure modes are silent, so the shape is
  checked rather than trusted.
- **Consecutive means consecutive.** Any different hash resets the streak to 1.
  ``A A B A A`` never halts — five actions, longest run 2. Only an unbroken run
  of ``threshold`` identical hashes trips it. A frequency counter ("A seen 3x
  in this task") would be a different, much more trigger-happy rule and would
  halt legitimate poll-then-act patterns.
- **3 means the THIRD occurrence.** ``A A`` is a retry (common and legitimate:
  a transient failure re-attempted). ``A A A`` is a loop.
- **Halting is ABSORBING.** Once ``halted`` is true it stays true, and
  ``last_hash``/``streak`` freeze at the tripping values; further
  :meth:`observe` calls are no-ops. The kernel is supposed to check
  :attr:`halted` before dispatching the next action, but a caller that forgets
  must not be able to erase the halt by observing something new — and the
  frozen ``last_hash`` is the ``loop_detected`` evidence the REPORT carries
  (§4.3), so it must survive until the report is written.

PURITY (§2.2, TCB): a frozen dataclass with copy-on-write transitions. No
clock, no I/O, no mutation, nothing nondeterministic — the same hash sequence
always yields the same verdict, which is what makes §14.5 replay exact.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace

from lsassist.contracts.enums import ExitReason

#: SPEC §4.3: three consecutive identical actions halt the loop.
LOOP_THRESHOLD = 3

#: The exact shape produced by :func:`lsassist.policy.canonical.action_hash`.
#: Lowercase hex only — the producer emits lowercase, so an uppercase digest
#: means the key came from somewhere else and would not compare equal to a
#: real ``action_hash`` for the same action.
_ACTION_HASH_RE = re.compile(r"^sha256:[0-9a-f]{64}$")


class LoopDetectionError(ValueError):
    """A loop-detection input was not usable (§4.3, fail-closed).

    Raised for a key that is not a ``policy.canonical.action_hash`` value, for
    a threshold below 2, or for a halt reason requested from a tracker that has
    not halted. Never degrades to a permissive default: a loop detector that
    quietly stops detecting is worse than one that stops the task.
    """


@dataclass(frozen=True)
class LoopTracker:
    """Consecutive-repeat tracker over ``action_hash`` values (§4.3).

    Immutable: :meth:`observe` returns a NEW tracker, so the kernel can keep a
    pre-dispatch snapshot (and the journal can replay one) without aliasing.

    :param threshold: consecutive identical actions required to halt. Defaults
        to the §4.3 value of 3 and is injectable only so the rule itself can be
        tested; below 2 it is meaningless (a threshold of 1 would halt on the
        first action ever observed) and is refused.
    """

    threshold: int = LOOP_THRESHOLD
    last_hash: str | None = None
    streak: int = 0
    halted: bool = False

    def __post_init__(self) -> None:
        if self.threshold < 2:
            raise LoopDetectionError(f"loop threshold must be >= 2, got {self.threshold}")

    def observe(self, action_hash: str) -> LoopTracker:
        """Record the next proposed action and return the updated tracker.

        Increments the streak when ``action_hash`` equals the previous one,
        otherwise restarts it at 1. Sets :attr:`halted` once the streak reaches
        :attr:`threshold`. Observing on an already-halted tracker is a no-op
        (the halt is absorbing — see the module docstring).
        """
        if not _ACTION_HASH_RE.match(action_hash):
            raise LoopDetectionError(
                "loop key must be a policy.canonical.action_hash "
                f"('sha256:<64 lowercase hex>'), got {action_hash!r}"
            )
        if self.halted:
            return self
        streak = self.streak + 1 if action_hash == self.last_hash else 1
        return replace(
            self,
            last_hash=action_hash,
            streak=streak,
            halted=streak >= self.threshold,
        )

    def exit_reason(self) -> ExitReason:
        """The §4.4 reason for a halted tracker: ``loop_detected``.

        Fails closed when the tracker has NOT halted — rendering a
        ``loop_detected`` REPORT for a task that never looped would attribute
        the wrong cause to whatever actually stopped it.
        """
        if not self.halted:
            raise LoopDetectionError("tracker has not halted; no loop_detected reason to report")
        return ExitReason.LOOP_DETECTED
