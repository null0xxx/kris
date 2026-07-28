"""The §6.3 dispatch pipeline, all nine steps.

SPEC §6.3: "1. Schema validate … 2. Normalize/canonicalize … 3. Policy classify
… 4. Approval … 5. Sandbox profile build … 6. Execute … 7. Observe … 8. Verify
… 9. Audit". Steps 1-4 end in a :class:`DispatchDecision` and touch nothing;
:func:`run` takes a PROCEED decision and carries out the tail. §6.5's result
assembly lives next door in :mod:`~lsassist.tools.result`, which is pure.

**NOTHING EXECUTES WITHOUT A DECISION TO EXECUTE.** :func:`run` refuses any
decision that is not PROCEED, and the argv it spawns comes from
:func:`~lsassist.sandbox.availability.compose_exec_argv` — the one sanctioned
exec-argv producer — and is re-checked for the §8.3 namespace flags before a
child exists. §8.3's "never fallback to unsandboxed exec" is therefore two
independent facts, not one promise: the receipt gate, and the argv CONTENT.

**THE RUNNER'S OBLIGATIONS (T2.06, recorded in ``sandbox/profiles.py``).**
:func:`spawn_capped` discharges them: ``env={}`` (``env=None`` hands the parent
environ to ``bwrap`` itself — ``--clearenv`` only protects what runs INSIDE it),
the argv LIST and never a shell string (§7.6 rule 8), ``start_new_session`` so
the timeout can ``SIGKILL`` the whole process GROUP, its OWN wall-clock deadline
(``prlimit --cpu`` is a CPU budget that fires early on threads and resets on
``fork`` — measured, see :mod:`~lsassist.sandbox.prlimit`), and stdin closed so a
tool that reads it cannot wait forever on the user's terminal.

**THIS IS THE FIRST TCB FILE IN ``tools/``** (``scripts/tcb-loc-manifest.txt``
lists ``tools/dispatcher.py`` as the §2.3 "dispatcher core"; the handlers around
it stay outside). It is also the first place where ``policy``, ``sandbox`` (via
``sandbox.env``), ``contracts`` and ``tools`` actually meet, so the rules about
who decides what matter more here than anywhere else so far.

**THE DISPATCHER DECIDES NOTHING ITSELF.**

* the permission CLASS comes from :func:`~lsassist.policy.rules.classify` — the
  single §7.2 authority. This module asks which rules FIRED
  (:func:`matched_rule_ids`) but only to fill the human-facing ``policy_note``;
  it never folds a class of its own. Two class computations would be two
  decision paths, which is exactly the failure mode I5/I6 exist to prevent.
* the CANONICAL FORM of a path comes from
  :func:`~lsassist.policy.canonical.canonicalize`, the sole §7.5 I/O boundary.
* the child ENVIRONMENT comes from :func:`~lsassist.sandbox.env.project_env`,
  which builds from scratch rather than filtering.
* a TOKEN is judged by :class:`~lsassist.policy.token.TokenService`, and the
  record it is judged against is rebuilt here from the CURRENT request, so an
  approval can only match the action it was granted for (§7.4 "Verify at exec:
  recompute normalization → compare action_hash").

**A WIRING BUG IS NOT A POLICY DECISION.** The kernel draws this line in
``machine.missing_measurements`` and it applies identically here: a
misconfigured dispatcher raises :class:`DispatchError`, while a request the
policy engine refuses returns a ``BLOCKED`` :class:`DispatchDecision`.
Collapsing them would let an install error be reported as "the model asked for
something forbidden". The one deliberate crossing is §6.3 step 1: malformed ARGS
are the MODEL's error, so they surface as a BLOCKED decision carrying
``malformed_tool_request`` and ``budget_refund=True`` — the model pays no budget
for its own schema violation.

**HARDEN-02's OBLIGATION IS DISCHARGED HERE.** ``PolicyContext``'s validator was
made pure, so it no longer resolves anything; this module resolves
``workspace_root`` and ``cwd`` through ``canonicalize`` before constructing the
context. §7.3's matcher is segment-aware and anchors its DENY subtrees on
``stores.home``, so an un-resolved workspace root would let two spellings of one
directory classify differently. The obligation's second half — "collapse a
leading ``//``" — turns out to be discharged by the same call; see
:func:`_canonical_root` for the measurement and why no extra loop lives here.

**WHICH ARGUMENTS ARE PATHS IS DECLARED, NOT GUESSED.** §6.2's manifest has no
per-argument path marker and this module does not invent one — the caller passes
``path_args``. That would be a hole if it were optional, so it is not: a manifest
declaring ``capabilities.fs != none`` with no declared path argument is refused
as a wiring bug. Guessing by argument name would be worse than either, because
the failure would be silent and would look like a working tool.
"""

from __future__ import annotations

import copy
import datetime
import hashlib
import os
import selectors
import signal
import subprocess
import time
import uuid
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from itertools import takewhile
from types import MappingProxyType
from typing import IO, Any, Final, cast, final

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from lsassist.audit.writer import AuditRefusedError, AuditWriteError, AuditWriter
from lsassist.contracts.approval import ApprovalClass, ApprovalRecord
from lsassist.contracts.enums import EvidenceType, PermissionClass
from lsassist.contracts.manifest import FsCapability, ProcCapability, Rollback, ToolManifest
from lsassist.contracts.policy_context import PolicyContext
from lsassist.contracts.sandbox_profile import Profile
from lsassist.contracts.tool_request import ToolRequest
from lsassist.contracts.tool_result import ToolError, ToolResult, ToolResultEvidence
from lsassist.policy.canonical import CanonicalizationError, action_hash, canonicalize, env_digest
from lsassist.policy.classes import rank
from lsassist.policy.recheck import (
    FsView,
    OsFsView,
    PathSnapshot,
    RecheckError,
    RecheckVerdict,
    recheck,
    snapshot_paths,
)
from lsassist.policy.rules import classify, r2, r4, r5, r6, r7, r8, r9
from lsassist.policy.stores import PolicyStores
from lsassist.policy.token import ApprovalToken, TokenService, TokenVerdict
from lsassist.sandbox.availability import (
    SANDBOX_UNAVAILABLE_REASON,
    SandboxAvailable,
    SandboxUnavailable,
    compose_exec_argv,
)
from lsassist.sandbox.availability import (
    # Aliased: `probe` is already the name of a §7.2 RULE probe in the loops
    # above, and a module-level import that shadows a local of a different kind
    # is a name collision waiting to be read wrong.
    probe as sandbox_probe,
)
from lsassist.sandbox.env import DEFAULT_PATH, EnvProjectionError, project_env
from lsassist.tools.result import (
    ExecObservation,
    OutputSink,
    ResultError,
    Verification,
    build_result,
    cap_result,
    sha256_digest,
)

__all__ = [
    "CLASS_APPROVAL_TERMS",
    "ENV_REBOUND",
    "MALFORMED_TOOL_REQUEST",
    "MALFORMED_TOOL_RESULT",
    "PATH_INVALIDATED",
    "REQUIRED_SANDBOX_FLAGS",
    "SANDBOX_UNAVAILABLE",
    "WORKSPACE_SCOPE",
    "ApprovalGrant",
    "Decision",
    "DispatchDecision",
    "DispatchEnvironment",
    "DispatchError",
    "ExecOutcome",
    "ExecRefused",
    "ExecutionNotJournalled",
    "MalformedToolRequest",
    "NormalizedRequest",
    "build_exec_argv",
    "dispatch",
    "matched_rule_ids",
    "normalize",
    "policy_note",
    "profile_for",
    "rollback_hint",
    "run",
    "spawn_capped",
    "validate_args",
]

#: §6.3 step 1's error kind. A ``ToolError.kind``, NOT a §4.4 ExitReason: the
#: model produced an ill-formed call, which is a tool-level result, not a reason
#: the whole task ended.
MALFORMED_TOOL_REQUEST: Final = "malformed_tool_request"

#: §8.3's reason code, re-exported by IDENTITY. A parallel spelling here would
#: let ``except``/audit handlers key on one string while the sandbox raised the
#: other — the same trap T3.08 avoided by re-exporting ``ProviderError`` itself.
SANDBOX_UNAVAILABLE: Final = SANDBOX_UNAVAILABLE_REASON

#: §7.5 step 3: a path stopped resolving to what was approved, BEFORE exec.
PATH_INVALIDATED: Final = "path_invalidated"

#: §7.4/§8.2: the child's environment would differ from the approved one.
ENV_REBOUND: Final = "env_rebound"

#: §8.2: a write target no V1 profile can expose read-write.
WORKSPACE_SCOPE: Final = "workspace_scope"

#: §6.3 step 8: the handler's ``result`` violates the manifest's output schema.
MALFORMED_TOOL_RESULT: Final = "malformed_tool_result"

#: The §8.3 boundary flags, asserted on the COMPOSED argv immediately before the
#: spawn. ``availability.py`` says it plainly: the receipt is defense in depth
#: and "the LOAD-BEARING boundary is the argv CONTENT … because that is what the
#: kernel enforces". This is where that content is checked, at the last moment
#: it still means anything.
REQUIRED_SANDBOX_FLAGS: Final[tuple[str, ...]] = (
    "--unshare-all",
    "--die-with-parent",
    "--new-session",
    "--clearenv",
)

#: How much the runner reads per ``read`` call.
_READ_CHUNK: Final = 65536

#: §14.1 events emitted by :func:`run`.
_TOOL_RESULT_EVENT: Final = "tool_result"
_VERIFY_EVENT: Final = "verify"

#: §7.1's approval terms, class by class: ``(ttl_s, max_uses)``.
CLASS_APPROVAL_TERMS: Final[Mapping[PermissionClass, tuple[int, int]]] = MappingProxyType(
    {
        PermissionClass.CONFIRM_ONCE: (300, 1),
        PermissionClass.CONFIRM_EXACT: (120, 1),
    }
)

#: §7.1's risk line per class — the first half of ``policy_note``. Transcribed
#: from the §7.1 table's "სემანტიკა" column so the renderer shows the SPEC's own
#: words rather than a paraphrase invented here.
_CLASS_RISK: Final[Mapping[PermissionClass, str]] = MappingProxyType(
    {
        PermissionClass.AUTO_READ: "non-sensitive read-only access inside scope",
        PermissionClass.AUTO_SCOPED_WRITE: "workspace write, checkpoint-backed",
        PermissionClass.CONFIRM_ONCE: "one specific action, approved once",
        PermissionClass.CONFIRM_EXACT: (
            "high risk — delete, overwrite outside scope, network config, "
            "credentials, external send, destructive or security-setting change"
        ),
        PermissionClass.DENY_ALWAYS: "refused by §7.3; no approval can grant it",
    }
)

#: §6.2's rollback enum → the operator-facing recovery path. Read from the
#: MANIFEST rather than derived from the class: §6.2 already declares each
#: tool's rollback path, and a second class-to-hint mapping here could
#: contradict it.
_ROLLBACK_HINT: Final[Mapping[Rollback, str]] = MappingProxyType(
    {
        Rollback.CHECKPOINT: (
            "restore from the shadow-git checkpoint taken before this action (§14.4)"
        ),
        Rollback.MANUAL_STEPS: "manual rollback steps only — no automatic restore point",
        Rollback.NONE: "no rollback needed: this action changes no state",
    }
)

#: The §7.2 rules, in ``classify``'s own fold order, paired with their ids.
#: R1 is the manifest floor (not a callable) and R3 is a POST-FOLD elevation
#: keyed off the final class, so neither appears here; both are reported by
#: :func:`matched_rule_ids` from the facts instead.
_RULE_PROBES: Final[tuple[tuple[str, Any], ...]] = (
    ("R2", r2),
    ("R4", r4),
    ("R5", r5),
    ("R6", r6),
    ("R7", r7),
    ("R8", r8),
    ("R9", r9),
)

#: The §4.4 ``policy_blocked:<rule_id>`` parameter used when no numbered rule
#: claims the refusal (a DENY that came straight from the manifest floor).
_MANIFEST_FLOOR_RULE: Final = "R1"

_AUTO_CLASSES: Final[frozenset[PermissionClass]] = frozenset(
    {PermissionClass.AUTO_READ, PermissionClass.AUTO_SCOPED_WRITE}
)
_CONFIRM_CLASSES: Final[frozenset[PermissionClass]] = frozenset(CLASS_APPROVAL_TERMS)


class DispatchError(Exception):
    """The dispatcher is misconfigured, or the model's args are ill-formed.

    Two distinct populations share one type because both mean "this call cannot
    be evaluated", never "policy said no":

    * WIRING — a manifest whose ``input_schema`` is unusable, a tool/manifest
      mismatch, an fs tool with no declared path arguments, a rejected env
      addition, a path that will not canonicalize. :func:`dispatch` lets these
      propagate so the runner reports a misconfiguration.
    * MODEL — args that fail the tool's own schema. :func:`dispatch` catches
      exactly this one (it carries :data:`MALFORMED_TOOL_REQUEST`) and turns it
      into a BLOCKED decision with a budget refund, per §6.3 step 1.
    """


class MalformedToolRequest(DispatchError):
    """The MODEL's args failed the tool's own schema (§6.3 step 1).

    A distinct TYPE, not a substring of a message. The first draft told the two
    populations apart with ``if MALFORMED_TOOL_REQUEST not in str(exc)`` — and
    the model controls part of that string, because a path argument is echoed
    into the jsonschema diagnostic. A request naming
    ``/ws/malformed_tool_request.txt`` could therefore have a WIRING failure
    reported as a model error, complete with a budget refund. The class does the
    dispatching now, so nothing the model writes can change which branch runs.
    """


class ExecRefused(DispatchError):
    """A §6.3 step-5 refusal that is a FACT ABOUT THE WORLD, not a wiring bug.

    A ``.venv`` that appeared after the approval, a write target outside the only
    writable bind: nothing is misconfigured, and nothing may run. It is a
    :class:`DispatchError` subclass so a direct caller of :func:`build_exec_argv`
    gets a typed refusal, and :func:`run` turns it into an AUDITED ``BLOCKED``
    outcome — because a refusal nobody journalled is a refusal nobody can review.
    """

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind


class ExecutionNotJournalled(DispatchError):
    """The tool RAN and §14.1 could not record it.

    The most serious state this module can reach, and the reason it is neither
    swallowed nor raised bare. Swallowing it leaves an unrecorded action while
    the caller believes otherwise (``AuditWriter``'s own docstring: "an audit sink
    that swallows its own failures is worse than none"). Raising a bare error
    throws away the digests, evidence and exit status the caller needs in order
    to react to an action that already happened — so the result travels with the
    exception.
    """

    def __init__(self, result: ToolResult, cause: Exception) -> None:
        super().__init__(f"{result.tool} executed but could not be journalled: {cause}")
        self.result = result


class Decision(StrEnum):
    """What §6.3 step 4 concluded."""

    #: AUTO class, or a CONFIRM class satisfied by a VALID token. Steps 5-9 may run.
    PROCEED = "proceed"
    #: A CONFIRM class with no usable token: render the record and ask (§7.4).
    NEEDS_APPROVAL = "needs_approval"
    #: DENY_ALWAYS, or a malformed request. Nothing runs.
    BLOCKED = "blocked"


@final
@dataclass(frozen=True, slots=True)
class DispatchEnvironment:
    """Everything the dispatcher needs that is not the request itself.

    ``workspace_root`` and ``cwd`` are RAW here on purpose: the dispatcher owns
    their canonicalization (HARDEN-02), so accepting them pre-resolved would let
    a caller skip it.
    """

    workspace_root: str
    cwd: str
    stores: PolicyStores
    session_id: str
    untrusted_turn: bool = False
    skill_ceiling: PermissionClass | None = None
    env_extra: Mapping[str, str] | None = None
    token_service: TokenService | None = None
    #: §8.2: under profile ``ws`` a workspace ``.venv/bin`` is PREPENDED to PATH.
    #: The approval binds an env digest, so it has to describe the env the CHILD
    #: gets. Binding the host's PATH instead would let the user approve one
    #: environment while a different one runs.
    venv_exists: bool = False


@final
@dataclass(frozen=True, slots=True)
class ApprovalGrant:
    """A minted §7.4 record and the token bound to it, presented TOGETHER.

    The record must be the one that was MINTED, not one rebuilt at exec time.
    ``ApprovalRecord.canonical_bytes()`` covers ``issued_at`` and ``token_id``,
    so re-stamping either makes the HMAC differ from the minted one for every
    instant except the exact moment of minting — measured on the first draft: a
    token verified at ``T0`` and was ``HMAC_MISMATCH`` at ``T0+1s``, which made
    the whole §7.1 CONFIRM flow ("1 use, TTL 300 s") unusable and left
    ``TokenVerdict.EXPIRED`` unreachable, because ``now - issued_at`` was always
    zero. §7.4 says "Verify at exec: recompute NORMALIZATION -> compare
    action_hash; check TTL, uses" — the normalization is recomputed, the record
    is not.
    """

    record: ApprovalRecord
    token: ApprovalToken


@final
@dataclass(frozen=True, slots=True)
class NormalizedRequest:
    """§6.3 step 2's output — the ONLY thing a handler ever receives (§6.1).

    The field set is closed and deliberately contains no message, prompt,
    transcript or reasoning channel: §6.1 says handlers get "validated args +
    execution context" and nothing else, and the cheapest way to enforce that is
    to leave model text no seat on the vehicle.
    """

    tool: str
    args: Mapping[str, Any]
    canonical_paths: tuple[str, ...]
    workspace_root: str
    cwd_real: str
    env: Mapping[str, str]
    env_digest: str
    action_hash: str
    argv: tuple[str, ...] | None = None
    #: §7.5 step 2 — "Token ინახავს canonical paths + parent dir inode". Captured
    #: HERE, at approval time, because §7.5 step 3's pre-exec re-canonicalization
    #: has nothing to compare against otherwise. It is NOT part of
    #: :attr:`action_hash`: a snapshot is a measurement of the world at approval
    #: time, and folding it into the binding would make an approval stop matching
    #: its own action the moment anything on disk moved.
    path_snapshots: tuple[PathSnapshot, ...] = ()


@final
@dataclass(frozen=True, slots=True)
class DispatchDecision:
    """§6.3 step 4's verdict for one tool call.

    ``normalized`` is present IF AND ONLY IF ``decision is PROCEED`` — the
    structural form of "nothing executes without a decision to execute".
    """

    decision: Decision
    permission_class: PermissionClass
    normalized: NormalizedRequest | None = None
    approval_record: ApprovalRecord | None = None
    error: ToolError | None = None
    budget_refund: bool = False
    policy_rule_id: str | None = None
    matched_rules: tuple[str, ...] = field(default=())


# --------------------------------------------------------------------------
# step 1 — schema validate (§6.3, I2)
# --------------------------------------------------------------------------
def validate_args(manifest: ToolManifest, request: ToolRequest) -> dict[str, Any]:
    """Validate ``request.args`` against the manifest's ``input_schema``.

    :raises DispatchError: the request names a different tool, the schema is
        unusable, or the args violate it. An args violation carries
        :data:`MALFORMED_TOOL_REQUEST` so :func:`dispatch` can tell the model's
        error from the operator's.

    ``additionalProperties: false`` is REQUIRED, not merely honoured. §6.3 step 1
    says every tool has it, and the registry cannot enforce that because §6.2
    types ``input_schema`` as a free-form object — so a schema without it is
    refused here. An unknown key is an unvalidated channel into a handler.
    """
    if request.tool != manifest.name:
        raise DispatchError(
            f"request names tool {request.tool!r} but the manifest is {manifest.name!r}"
        )
    schema = manifest.input_schema
    if schema.get("type") != "object":
        raise DispatchError(f"{manifest.name}: input_schema must be an object schema (§6.3)")
    if schema.get("additionalProperties") is not False:
        raise DispatchError(
            f"{manifest.name}: input_schema must set additionalProperties: false (§6.3 step 1); "
            "an unknown key is an unvalidated channel into the handler"
        )
    try:
        Draft202012Validator.check_schema(schema)
        Draft202012Validator(schema).validate(request.args)
    except SchemaError as exc:
        raise DispatchError(f"{manifest.name}: input_schema is not a valid schema: {exc}") from exc
    except JsonSchemaValidationError as exc:
        location = "/".join(str(part) for part in exc.absolute_path) or "<root>"
        # NOTE the message carries the schema KEYWORD that failed and WHERE, but
        # never the offending VALUE. `exc.message` embeds the instance verbatim,
        # and the instance is model-supplied - a secret passed as an argument
        # would land in `ToolError.message_redacted`, a field whose name promises
        # the opposite (I8, §12.4).
        raise MalformedToolRequest(
            f"{MALFORMED_TOOL_REQUEST}: {manifest.name} args invalid at {location} "
            f"(failed {exc.validator!r})"
        ) from exc
    return copy.deepcopy(dict(request.args))


# --------------------------------------------------------------------------
# step 2 — normalize / canonicalize (§6.3, §7.5)
# --------------------------------------------------------------------------
def _canonical_root(path: str, *, label: str) -> str:
    """Resolve a root path fail-closed, discharging HARDEN-02's obligation.

    HARDEN-02 recorded two things for this module: realpath the
    ``workspace_root`` before ``PolicyContext`` sees it (the contract validator
    was made pure and no longer does it), and collapse a leading ``//`` because
    POSIX ``normpath`` PRESERVES one while §7.3's matcher splits on ``/``.

    MEASURED: the second half is already discharged by ``canonicalize``, which
    resolves through :func:`os.path.realpath`, and realpath COLLAPSES the double
    slash where normpath does not — ``normpath("//tmp") == "//tmp"`` but
    ``realpath("//tmp") == "/tmp"``. The obligation was written against the
    validator's ``normpath``, not against this path. An extra collapse loop here
    would be unreachable code standing in for a defense that already exists, so
    the invariant is pinned by a test on the OBSERVABLE result instead: if
    ``canonicalize`` ever stops resolving, that test goes red rather than a
    silent loop quietly covering for it.
    """
    try:
        return str(canonicalize(path))
    except CanonicalizationError as exc:
        raise DispatchError(f"{label} {path!r} does not canonicalize: {exc}") from exc


def _child_path(workspace_root: str, *, venv_exists: bool) -> str:
    """The PATH the sandboxed child will actually see (§8.1/§8.2).

    Mirrors ``sandbox.profiles.build_argv``'s own rule, and a test pins the two
    against each other so they cannot drift. Binding anything else into
    ``env_digest`` would make the approval describe an environment that never
    runs — and under ``ws`` with a workspace ``.venv``, §8.2 deliberately lets
    that venv outrank system tools, which is precisely the case the user most
    needs to see before consenting (recorded obligation 3).
    """
    if not venv_exists:
        return DEFAULT_PATH
    return f"{workspace_root.rstrip('/')}/.venv/bin:{DEFAULT_PATH}"


def _canonical_args(
    args: dict[str, Any], path_args: Sequence[str], *, create_if_missing: bool
) -> tuple[str, ...]:
    """Canonicalize every DECLARED path argument present, SUBSTITUTING in place.

    ``args`` is mutated: each declared path argument is replaced by its resolved
    form. §7.4 names the field ``args_normalized``, and it means it — the record
    the user approves, and the ``action_hash`` bound to it, must describe the
    path that will actually be opened, not the spelling the model happened to
    use. Leaving the raw string in place also breaks §7.5 step 3: re-requesting
    the same action spelled differently would recompute a different hash and
    force a spurious re-prompt.

    :returns: the sorted, de-duplicated canonical paths (§7.4 ``canonical_paths``).
    """
    resolved: list[str] = []
    for name in path_args:
        if name not in args:
            continue  # an optional path argument, legitimately absent
        value = args[name]
        if not isinstance(value, str) or not value:
            raise DispatchError(f"path argument {name!r} must be a non-empty string")
        try:
            canonical = str(canonicalize(value, allow_missing=create_if_missing))
        except CanonicalizationError as exc:
            raise DispatchError(f"path argument {name!r} does not canonicalize: {exc}") from exc
        args[name] = canonical
        resolved.append(canonical)
    return tuple(sorted(set(resolved)))


def _checked_argv(manifest: ToolManifest, args: Mapping[str, Any]) -> tuple[str, ...] | None:
    """The tool's caller-supplied argv, verbatim — or ``None`` if it has none.

    No interpolation, no templating, no shell (§7.5 rule 8). Metacharacters are
    DATA here; §7.2's R4 is what raises the class on them, and that happens in
    ``policy``, not in this function.

    **AN ABSENT ``argv`` IS LEGITIMATE, and this is load-bearing.** Only
    ``proc.exec`` and ``test.run`` take an argv from the model. §6.4's other four
    spawning tools — ``sys.info``, ``pkg.query``, ``git.read`` and the
    ``git.worktree`` write — take a SELECTOR (a probe name, a package name, a
    subcommand) and the HANDLER assembles a fixed argv from its own allowlist,
    which is precisely what makes them safe. Requiring an ``argv`` argument from
    every ``spawn_argv`` manifest would therefore reject four of the twelve V1
    tools outright. What is validated is the argv that IS supplied; what the
    handler builds is bound at §6.3 step 5, not here.

    A tool that does not spawn gets ``None`` regardless of what its args say, so
    a stray ``argv`` key cannot conjure an exec channel — and the §6.2 schema's
    ``additionalProperties: false`` has already rejected it anyway.
    """
    if manifest.capabilities.proc is not ProcCapability.SPAWN_ARGV:
        return None
    if "argv" not in args:
        return None
    argv = args["argv"]
    if not isinstance(argv, list) or not argv:
        raise DispatchError(
            f"{manifest.name}: 'argv' must be a non-empty list of strings (§6.3 step 2)"
        )
    if not all(isinstance(token, str) for token in argv):
        raise DispatchError(f"{manifest.name}: every argv token must be a string")
    return tuple(argv)


def _snapshot_targets(canonical_paths: Sequence[str], fs_view: FsView) -> tuple[str, ...]:
    """What §7.5 step 2 can actually measure for each approved path.

    An EXISTING path snapshots itself. A ``create_if_missing`` target has no node
    identity yet — but its PARENT does, and a swapped parent is precisely how a
    file gets created somewhere other than where it was approved. Snapshotting
    the parent reuses ``recheck``'s own comparison with nothing new invented:
    ``canonicalize(allow_missing=True)`` already required that parent to resolve,
    so it is there to be measured.

    Order-preserving and de-duplicated: two create-intent siblings share one
    parent, and snapshotting it twice would stat it twice to learn the same fact.
    """
    targets = [
        path if fs_view.exists(path) else os.path.dirname(path) for path in canonical_paths
    ]
    return tuple(dict.fromkeys(targets))


def normalize(
    request: ToolRequest,
    *,
    manifest: ToolManifest,
    environment: DispatchEnvironment,
    path_args: Sequence[str] = (),
    create_if_missing: bool = False,
) -> NormalizedRequest:
    """§6.3 step 2: canonicalize paths, freeze argv, project env, bind the hash.

    :param path_args: which argument names hold paths. REQUIRED for any manifest
        declaring ``capabilities.fs != none`` — see the module docstring.
    :param create_if_missing: the §6.3 step-2 carve-out for a tool that creates
        its target. The path still has to canonicalize; only its existence is
        waived.
    :raises DispatchError: any wiring or normalization failure.
    :raises ~lsassist.policy.recheck.RecheckError: a path canonicalized and then
        could not be stat'ed — a racing filesystem. Left to propagate: it is
        already a typed fail-closed error, and nothing has run.
    """
    args = validate_args(manifest, request)

    if manifest.capabilities.fs is not FsCapability.NONE and not path_args:
        raise DispatchError(
            f"{manifest.name} declares capabilities.fs={manifest.capabilities.fs.value} but no "
            "path_args were declared; an undeclared path argument would skip §7.5 entirely"
        )
    declared = set(manifest.input_schema.get("properties", {}))
    unknown = [name for name in path_args if name not in declared]
    if unknown:
        # A non-empty path_args tuple was the whole guard, so a typo or a
        # placeholder satisfied it while canonicalizing nothing at all - §7.5
        # silently became a no-op for a tool that looked correctly wired.
        raise DispatchError(
            f"{manifest.name}: path_args {unknown} name no property of input_schema; "
            "a mis-typed path argument would turn §7.5 canonicalization into a no-op"
        )
    if create_if_missing and manifest.capabilities.fs is not FsCapability.WRITE_SCOPED:
        raise DispatchError(
            f"{manifest.name}: create_if_missing requires capabilities.fs=write_scoped; "
            "waiving the dangling-target check for a tool that creates nothing weakens §7.5"
        )

    workspace_root = _canonical_root(environment.workspace_root, label="workspace_root")
    cwd_real = _canonical_root(environment.cwd, label="cwd")
    # Mutates `args` in place, substituting canonical paths — must run BEFORE the
    # action hash is computed over it.
    canonical_paths = _canonical_args(args, path_args, create_if_missing=create_if_missing)
    argv = _checked_argv(manifest, args)

    try:
        env = project_env(
            path=_child_path(workspace_root, venv_exists=environment.venv_exists),
            extra=environment.env_extra,
        )
    except EnvProjectionError as exc:
        raise DispatchError(f"child env projection refused: {exc}") from exc

    digest = env_digest(env)
    # The §7.5 sanctioned I/O adapter, not an injection point: step 2 measures
    # the REAL filesystem the approval is about, and a fake here would produce a
    # snapshot of nothing that step 3 would then happily re-check.
    view = OsFsView()
    return NormalizedRequest(
        tool=request.tool,
        args=MappingProxyType(args),
        canonical_paths=canonical_paths,
        workspace_root=workspace_root,
        cwd_real=cwd_real,
        env=MappingProxyType(dict(env)),
        env_digest=digest,
        action_hash=action_hash(
            tool=request.tool,
            args_normalized=args,
            canonical_paths=canonical_paths,
            cwd_real=cwd_real,
            env_digest=digest,
        ),
        argv=argv,
        path_snapshots=snapshot_paths(_snapshot_targets(canonical_paths, view), view),
    )


# --------------------------------------------------------------------------
# step 3 — classify, and describe the classification (§7.1, §7.2)
# --------------------------------------------------------------------------
def matched_rule_ids(
    request: ToolRequest,
    context: PolicyContext,
    stores: PolicyStores,
    *,
    floor: PermissionClass | None = None,
    final_class: PermissionClass | None = None,
) -> tuple[str, ...]:
    """Which §7.2 rules propose a raise for this request. DIAGNOSTIC ONLY.

    ``classify`` remains the authority for the CLASS; this probe exists so the
    approval prompt can say *why*. It calls the same public rule functions in
    ``classify``'s own fold order, but it deliberately does NOT reproduce the
    fold: it reports what fired, never what the answer is. R1 (the manifest
    floor) is not a callable, and R3 is a post-fold elevation keyed off the
    final class — that one is reported from ``context.untrusted_turn``.
    """
    fired: list[str] = []
    reached = floor
    for rule_id, probe in _RULE_PROBES:
        proposed = probe(request, context, stores)
        if proposed is None:
            continue
        if reached is not None and rank(proposed) <= rank(reached):
            # The rule matched but proposed nothing STRICTER than the class
            # already reached, so it raised nothing. Naming it would tell the
            # user "raised by R6" about a rule that changed no outcome.
            continue
        # Reaching here means the guard above did not `continue`, i.e. `reached`
        # is None or this proposal is strictly stricter — so the assignment is
        # unconditional. An `if` repeating that condition would be tautological.
        fired.append(rule_id)
        reached = proposed
        if proposed is PermissionClass.DENY_ALWAYS:
            break  # classify short-circuits on DENY; later rules never run
    r3_elevated = final_class is PermissionClass.CONFIRM_EXACT and (
        reached is not PermissionClass.CONFIRM_EXACT
    )
    if context.untrusted_turn and (final_class is None or r3_elevated):
        # R3 is a POST-FOLD elevation that only applies when the final class is
        # neither AUTO_READ nor already what it would raise to. Reporting it on
        # every untrusted turn told the user a rule had raised the class when it
        # had left it exactly where the fold put it.
        fired.append("R3")
    return tuple(fired)


def denying_rule_id(
    request: ToolRequest, context: PolicyContext, stores: PolicyStores
) -> str:
    """Which §7.2 rule actually returned DENY_ALWAYS — §4.4's ``<rule_id>``.

    NOT simply the first rule that fired. Measured on the first draft:
    ``proc.exec argv=["sudo","sh","-c","a && b"]`` fires R4 (metacharacters ->
    CONFIRM_EXACT) before R5 (``sudo`` -> DENY_ALWAYS), so ``policy_blocked:R4``
    named a rule that merely raised while the rule that REFUSED went unnamed —
    pointing whoever reads the audit journal at the wrong rule.
    """
    for rule_id, probe in _RULE_PROBES:
        if probe(request, context, stores) is PermissionClass.DENY_ALWAYS:
            return rule_id
    return _MANIFEST_FLOOR_RULE


def policy_note(
    permission_class: PermissionClass, matched: Sequence[str]
) -> str:
    """The §7.1 risk line plus the rules that raised it, for T5.03's renderer.

    Built FROM the authoritative class, so it can never contradict it even if
    the rule probe above were wrong.
    """
    risk = _CLASS_RISK[permission_class]
    if matched:
        return f"{permission_class.value} — {risk}; raised by {', '.join(matched)}"
    return f"{permission_class.value} — {risk}; from the manifest floor (R1)"


def rollback_hint(manifest: ToolManifest, permission_class: PermissionClass) -> str:
    """How this action is undone, read from §6.2's ``rollback`` declaration."""
    hint = _ROLLBACK_HINT[manifest.rollback]
    if permission_class is PermissionClass.DENY_ALWAYS:
        return "not applicable: the action is refused"
    return hint


# --------------------------------------------------------------------------
# step 4 — approval (§7.1, §7.4, I5/I6)
# --------------------------------------------------------------------------
def _approval_record(
    *,
    normalized: NormalizedRequest,
    permission_class: PermissionClass,
    manifest: ToolManifest,
    environment: DispatchEnvironment,
    matched: Sequence[str],
    now: datetime.datetime,
    token_id: str,
) -> ApprovalRecord:
    """Build the §7.4 canonical record — the renderer's ONLY input."""
    ttl_s, max_uses = CLASS_APPROVAL_TERMS[permission_class]
    return ApprovalRecord(
        token_id=token_id,
        session_id=environment.session_id,
        tool=normalized.tool,
        args_normalized=dict(normalized.args),
        canonical_paths=list(normalized.canonical_paths),
        cwd_real=normalized.cwd_real,
        env_digest=normalized.env_digest,
        action_hash=normalized.action_hash,
        max_uses=max_uses,
        ttl_s=ttl_s,
        issued_at=now,
        # §7.4's wire key is "class", a Python keyword, so the contract aliases
        # it. Spelled through the alias (as tests/integration/test_kernel_seams.py
        # does) rather than by field name: `populate_by_name` accepts both at
        # runtime, but only the alias type-checks without the pydantic mypy
        # plugin, and this file is TCB and therefore `--strict`.
        **{"class": ApprovalClass(permission_class.value)},
        policy_note=policy_note(permission_class, matched),
        rollback_hint=rollback_hint(manifest, permission_class),
    )


def _grant_satisfies(
    grant: ApprovalGrant,
    normalized: NormalizedRequest,
    permission_class: PermissionClass,
    environment: DispatchEnvironment,
    moment: datetime.datetime,
) -> bool:
    """Does this minted grant authorize THIS action, right now? Fail-closed.

    Three conditions, all required:

    1. the token verifies against the STORED record — HMAC, TTL and use count
       are all judged against the record as minted (see :class:`ApprovalGrant`);
    2. the stored ``action_hash`` equals the one recomputed from the current
       request — §7.4's "recompute normalization -> compare action_hash", which
       is what stops an approval for one action from authorizing another;
    3. the class the token was minted at is at least as strict as the class this
       request classifies to — mirroring ``machine._g_valid_token``'s condition
       3, so a CONFIRM_ONCE grant cannot satisfy a request that R3 has since
       raised to CONFIRM_EXACT.
    """
    service = environment.token_service
    if service is None:
        return False
    if service.verify(grant.token, grant.record, moment) is not TokenVerdict.VALID:
        return False
    if grant.record.action_hash != normalized.action_hash:
        return False
    return rank(PermissionClass(grant.record.policy_class.value)) >= rank(permission_class)


def dispatch(
    request: ToolRequest,
    *,
    manifest: ToolManifest,
    environment: DispatchEnvironment,
    path_args: Sequence[str] = (),
    create_if_missing: bool = False,
    grant: ApprovalGrant | None = None,
    now: datetime.datetime | None = None,
) -> DispatchDecision:
    """Run §6.3 steps 1-4 and return the decision. Never executes anything.

    :param grant: the MINTED §7.4 record plus its token, presented together. The
        token is verified against the STORED record (so the HMAC, TTL and use
        count are all meaningful), and the record's ``action_hash`` is then
        compared against the one recomputed here — which is how an approval is
        bound to the action it was granted for, and only that one. A grant for a
        DENY_ALWAYS action, or one presented without a :class:`TokenService`,
        changes nothing.
    :raises DispatchError: a WIRING failure. Args that fail the tool's own schema
        are the MODEL's error and come back as a BLOCKED decision instead.

    **THIS IS A PRE-FILTER, NOT THE I15 GATE.** ``kernel.machine._g_valid_token``
    is the authority that opens EXECUTE, and it checks four independent
    conditions: a VALID verdict, live affirmative consent, a token minted at a
    class at least as strict as the §4.6-reduced class, and an ALLOWED §4.7
    replay verdict. Consent liveness and the replay ledger are kernel state this
    module cannot see, so it checks the two it CAN — the verdict and the class
    strength — and never claims the other two are satisfied.
    """
    moment = now or datetime.datetime.now(datetime.UTC)

    try:
        normalized = normalize(
            request,
            manifest=manifest,
            environment=environment,
            path_args=path_args,
            create_if_missing=create_if_missing,
        )
    # ONLY the model's schema violation is caught here, and it is caught BY TYPE.
    # Every other DispatchError is a WIRING failure and propagates. The first
    # draft used `if MALFORMED_TOOL_REQUEST not in str(exc)`, and the model
    # controls part of that string — a path argument is echoed into the
    # diagnostic — so a request naming `/ws/malformed_tool_request.txt` could
    # have an operator's misconfiguration reported as a model error, budget
    # refund included.
    except MalformedToolRequest as exc:
        # §6.3 step 1: the model produced an ill-formed call. Budget is refunded
        # — it should not pay for its own schema violation — but the class is
        # still reported as the manifest floor, because nothing was classified.
        return DispatchDecision(
            decision=Decision.BLOCKED,
            permission_class=manifest.permission_class,
            error=ToolError(kind=MALFORMED_TOOL_REQUEST, message_redacted=str(exc)),
            budget_refund=True,
        )

    context = PolicyContext(
        workspace_root=normalized.workspace_root,
        untrusted_turn=environment.untrusted_turn,
        skill_ceiling=environment.skill_ceiling,
    )
    # CLASSIFY THE NORMALIZED REQUEST, never the raw one. §6.3 orders step 2
    # (realpath, symlink-chain resolution) BEFORE step 3 precisely so that policy
    # judges the path that will actually be opened. The first draft passed the
    # raw `request` here while handing the handler the RESOLVED path, and the gap
    # was a complete §7.3 bypass: a symlink at `<ws>/notes.txt` pointing at
    # `~/.ssh/id_rsa` classified AUTO_READ and PROCEEDed, with the handler
    # receiving the real secret path. `<ws>/readme.md -> <ws>/.env` does the same
    # with nothing outside the workspace at all, so a symlink already present in
    # a cloned repository is enough. DENY_ALWAYS is specified as absolute — "no
    # approval can grant it" — and it degraded to AUTO with no prompt at all.
    resolved_request = request.model_copy(update={"args": dict(normalized.args)})
    permission_class = classify(resolved_request, context, manifest, environment.stores)
    matched = matched_rule_ids(
        resolved_request,
        context,
        environment.stores,
        floor=manifest.permission_class,
        final_class=permission_class,
    )

    if permission_class is PermissionClass.DENY_ALWAYS:
        return DispatchDecision(
            decision=Decision.BLOCKED,
            permission_class=permission_class,
            error=ToolError(
                kind="policy_denied",
                message_redacted=policy_note(permission_class, matched),
            ),
            policy_rule_id=denying_rule_id(resolved_request, context, environment.stores),
            matched_rules=matched,
        )

    if permission_class in _AUTO_CLASSES:
        return DispatchDecision(
            decision=Decision.PROCEED,
            permission_class=permission_class,
            normalized=normalized,
            matched_rules=matched,
        )

    if permission_class not in _CONFIRM_CLASSES:
        # Unreachable while PermissionClass has exactly five members, all of them
        # handled above. Kept because the alternative is a fall-through that
        # would hand an unknown class to `CLASS_APPROVAL_TERMS[...]` and raise a
        # KeyError out of a function documented not to — an added enum member
        # should fail CLOSED and say so.
        raise DispatchError(f"no §6.3 step-4 route for permission class {permission_class!r}")

    if grant is not None and _grant_satisfies(
        grant, normalized, permission_class, environment, moment
    ):
        return DispatchDecision(
            decision=Decision.PROCEED,
            permission_class=permission_class,
            normalized=normalized,
            matched_rules=matched,
        )
    return DispatchDecision(
        decision=Decision.NEEDS_APPROVAL,
        permission_class=permission_class,
        approval_record=_approval_record(
            normalized=normalized,
            permission_class=permission_class,
            manifest=manifest,
            environment=environment,
            matched=matched,
            now=moment,
            token_id=str(uuid.uuid4()),
        ),
        matched_rules=matched,
    )


# --------------------------------------------------------------------------
# step 5 — sandbox profile build (§6.3, §8.1/§8.2)
# --------------------------------------------------------------------------
#: Largest write target this module will hash for §7.5 step-6 evidence. Beyond
#: it the snapshot is REFUSED rather than truncated: a partial hash presented as
#: a file hash is a false measurement, and §7.5 step 6 asks for the file's.
_MAX_EVIDENCE_BYTES: Final = 64 * 1024 * 1024

#: The observation for a dispatch where NO PROCESS EVER RAN. §6.5 has no
#: representation for "there is no exit status" — ``exit_code`` is ``0..255`` —
#: so a blocked outcome reports ``0`` and lets ``status=error`` plus
#: ``error.kind`` carry the meaning. NAMED RESIDUAL: a reader who looks only at
#: ``exit_code`` sees a success-shaped number for something that never started.
_NOTHING_RAN: Final = ExecObservation(
    exit_code=0,
    duration_ms=0,
    stdout=b"",
    stderr=b"",
    stdout_digest=sha256_digest(b""),
    stderr_digest=sha256_digest(b""),
    stdout_truncated=False,
    stderr_truncated=False,
    stdout_bytes=0,
    stderr_bytes=0,
    timed_out=False,
)


def profile_for(manifest: ToolManifest) -> Profile:
    """Which §8 profile the tool's DECLARED capability entitles it to.

    Mechanical, and fail-closed in the SAFE direction: only an explicit
    ``write_scoped`` earns §8.2's read-write bind, and everything else —
    including an ``FsCapability`` member added later — gets §8.1's read-only
    profile. The two errors are not symmetric. A read tool handed a writable
    workspace is a silently widened boundary that nothing downstream re-checks;
    a write tool under ``ro`` fails immediately and visibly as ``EROFS``.

    This is derivation, not policy: the manifest already declared the capability
    and §7.2 already fixed the class. Nothing here can widen either.
    """
    if manifest.capabilities.fs is FsCapability.WRITE_SCOPED:
        return Profile.WS
    return Profile.RO


def _within(inner: str, outer: str) -> bool:
    """Segment-aware containment for two already-canonical absolute paths."""
    return inner == outer or inner.startswith(outer.rstrip("/") + "/")


def _check_write_scope(normalized: NormalizedRequest) -> None:
    """Refuse any declared path of a write tool that §8.2 cannot expose.

    EVERY declared path, not only the write target: §6.2 carries ONE ``fs``
    capability per tool, not one per argument, so under ``write_scoped`` there is
    nothing in the manifest that could tell a read path from a write path. No V1
    manifest mixes the two, and a path outside the workspace is unreachable under
    ``ws`` for reading as well — the profile binds the workspace plus the fixed
    :data:`~lsassist.sandbox.profiles.SYSTEM_RO_BINDS` and nothing else. NAMED
    RESIDUAL: if §6.2 ever grows per-argument capabilities, this loop needs to
    learn the difference.

    §7.2 R2 ADMITS an approved out-of-workspace write (it raises the class to
    CONFIRM_EXACT rather than denying), and no V1 profile can express one: §8.2
    binds the workspace and nothing else read-write, and there is no ``ws-net``
    or wider variant. So an approved out-of-scope write reaches the sandbox and
    dies with ``EROFS`` — a failure that reads like a broken tool rather than
    like the boundary doing its job.

    Refusing here names the real reason. NAMED RESIDUAL: this is a gap between
    §7.2 and §8.2, not a dispatcher bug. Closing it properly means either a §8
    profile that can bind an approved external target or a §7.2 rule that denies
    the request outright — both SPEC changes, and neither is made from here.
    """
    for path in normalized.canonical_paths:
        if not _within(path, normalized.workspace_root):
            raise ExecRefused(
                WORKSPACE_SCOPE,
                f"{path!r} is outside the workspace {normalized.workspace_root!r}; §8.2 binds "
                "only the workspace read-write, so this write cannot succeed inside the sandbox",
            )


def _check_venv_binding(normalized: NormalizedRequest, environment: DispatchEnvironment) -> None:
    """Close T2.05's named residual at the last moment it can still be closed.

    §8.2 deliberately lets ``<workspace>/.venv/bin`` OUTRANK system tools, and
    under ``ws`` the workspace is both writable and untrusted — so which
    ``python`` runs depends on whether that directory exists. §7.4 binds a
    NAME. The decision was taken against one answer to that question; if the
    answer changed in the window before exec, the approved environment is not
    the one that would run, and the user consented to a different action than
    the one about to happen.

    The window is small and the consequence is a hijacked approved binary, so it
    is refused rather than reported afterwards.
    """
    present = os.path.isdir(os.path.join(normalized.workspace_root, ".venv", "bin"))
    if present != environment.venv_exists:
        raise ExecRefused(
            ENV_REBOUND,
            f"{normalized.workspace_root}/.venv/bin exists={present} at exec time but the "
            f"approval was bound with venv_exists={environment.venv_exists}; §8.2 would put a "
            "different PATH in front of the child (§7.4 binds a NAME, not a binary)",
        )


def _check_env_binding(composed: Sequence[str], normalized: NormalizedRequest) -> None:
    """The child's env must be EXACTLY the env the approval bound (§7.4).

    §7.4 binds an ``env_digest``; §8.1 hands the child its environment as
    ``--setenv`` pairs. Those are two independent computations of one thing —
    ``_child_path`` here and ``build_argv``'s own rule there — and if they ever
    drift the user approves one environment while a different one runs. A unit
    test pins the two functions against each other; this pins the ARGV that is
    about to be spawned, which is the artifact that actually matters.

    This is also why :func:`run` accepts no ``lc_all``/``term``: §8.3 allows both
    in the child, but T3.02 bound an ``env_digest`` computed without them, so
    adding either here would invalidate every approval. NAMED RESIDUAL — giving
    the child a locale means teaching §6.3 step 2 to bind one.

    **ONLY THE bwrap PREFIX IS PARSED, AND THAT IS LOAD-BEARING.** Everything
    after the single ``--`` is the ``prlimit`` fragment plus the TOOL's own argv,
    verbatim and model-controlled for ``proc.exec``/``test.run`` (§6.3 step 2
    freezes it; it does not sanitize it — metacharacters are DATA). Scanning the
    whole list, as the first draft did, read the tool's arguments as env syntax.
    Measured on ``["/bin/echo", "--setenv"]``: ``composed[index + 2]`` ran off the
    end and raised a bare ``IndexError``, which is neither
    :class:`SandboxUnavailable` nor :class:`ExecRefused` and so escaped
    :func:`run` entirely — an untyped crash out of a TCB function, with the
    refusal never journalled. With two more tokens after it the same parse
    produced a FALSE ``ENV_REBOUND`` for an approved, benign call.
    """
    prefix = list(takewhile(lambda token: token != "--", composed))
    emitted = {
        prefix[index + 1]: prefix[index + 2]
        for index, token in enumerate(prefix)
        # The bound is not decoration: a truncated trailing pair must DROP out of
        # the comparison (and so refuse, since the env will not match) rather than
        # index past the end.
        if token == "--setenv" and index + 2 < len(prefix)
    }
    if emitted != dict(normalized.env):
        raise ExecRefused(
            ENV_REBOUND,
            "the composed argv would give the child an environment that differs from the one "
            f"bound in the approval (env_digest={normalized.env_digest})",
        )


def build_exec_argv(
    *,
    normalized: NormalizedRequest,
    manifest: ToolManifest,
    environment: DispatchEnvironment,
    available: SandboxAvailable,
    cache_dir: str,
    argv: Sequence[str],
) -> list[str]:
    """§6.3 step 5: ``(tool, args, policy) → bwrap argv``.

    Everything about HOW the sandbox is built belongs to
    :func:`~lsassist.sandbox.availability.compose_exec_argv` — the only
    sanctioned exec-argv producer, and the one place the ``prlimit`` caps are
    spliced INSIDE the sandbox (HARDEN-03). What this function adds is the three
    bindings the sandbox layer cannot know about: the profile the manifest
    entitles the tool to, the workspace scope §8.2 can actually express, and the
    environment §7.4 already bound.

    :raises ExecRefused: a §8.2 scope or §7.4 binding refusal.
    :raises ~lsassist.sandbox.availability.SandboxUnavailable: the receipt is not
        one ``probe()`` issued, or carries an untrusted program path.
    :raises ~lsassist.sandbox.profiles.SandboxProfileError: a structurally
        invalid path, argv or mount shape — a WIRING failure, not policy.
    """
    profile = profile_for(manifest)
    if profile is Profile.WS:
        _check_write_scope(normalized)
        _check_venv_binding(normalized, environment)
    composed = compose_exec_argv(
        available=available,
        profile=profile,
        workspace=normalized.workspace_root,
        cwd=normalized.cwd_real,
        cache_dir=cache_dir,
        argv=argv,
        timeout_s=manifest.timeout_s,
        venv_exists=environment.venv_exists,
    )
    # FIRST, before anything subtler: is this still a sandbox? Everything below
    # is a binding question, and a binding question about an argv with no
    # namespaces is the wrong conversation entirely (I11).
    for flag in REQUIRED_SANDBOX_FLAGS:
        if flag not in composed:
            raise DispatchError(
                f"the composed argv is missing {flag!r}; refusing to hand back something the "
                "caller would then spawn and call a sandbox (I11, §8.3)"
            )
    _check_env_binding(composed, normalized)
    return composed


# --------------------------------------------------------------------------
# step 6 — execute (§6.3, §8.3)
# --------------------------------------------------------------------------
def _kill_group(pid: int) -> None:
    """``SIGKILL`` the child's whole process GROUP (§6.3 step 6).

    The GROUP, not the process. ``start_new_session=True`` makes the child a
    session leader, so its own descendants share its group id; killing only the
    direct child leaves a grandchild holding the write end of the pipe, the read
    never reaches EOF, and the runner sits there long after its deadline passed.
    That failure HANGS rather than fails, which is the shape this project has
    learned to hunt (T4.02's FIFO).

    ``SIGKILL`` cannot be caught, blocked or ignored, so EOF is guaranteed to
    follow. A group that is already gone is the desired end state, not an error.
    """
    try:
        os.killpg(os.getpgid(pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        return


def spawn_capped(
    argv: Sequence[str],
    *,
    timeout_s: int,
    stdout_cap: int,
    stderr_cap: int,
    clock: Callable[[], int] = time.monotonic_ns,
) -> ExecObservation:
    """Run ``argv`` and return §6.3 step 7's observation. NOT A SANCTIONED EXEC.

    **THIS SPAWNS EXACTLY THE ARGV IT IS GIVEN.** It does not compose a sandbox,
    does not consult a receipt, and does not check for the §8.3 namespace flags.
    §8.3's "never fallback to unsandboxed exec" is enforced by :func:`run`, which
    builds the argv through
    :func:`~lsassist.sandbox.availability.compose_exec_argv` and re-checks
    :data:`REQUIRED_SANDBOX_FLAGS` before handing the argv over. A second route to
    ``execve`` without that check is the I11 failure this project exists to
    prevent, so a contract test walks the AST of every module under ``src/`` and
    asserts that (a) no module OTHER than this one so much as names
    ``spawn_capped``, and (b) nothing calls it directly anywhere — the single
    sanctioned route is :func:`run`'s ``runner`` default.

    The first version of that test grepped for the substring ``spawn_capped(``,
    and the only occurrence of that substring in ``src/`` is the ``def`` line
    above: the real invocation is spelled ``runner(...)``. It passed on the
    definition alone, would have passed with ZERO callers, and could not see a
    second module adopting the same injected-default idiom — i.e. it asserted
    nothing about the property its own name claimed.

    The T2.06 runner obligations are discharged here and nowhere else:

    * ``env={}`` — an explicitly EMPTY environment. ``env=None`` inherits the
      parent's, and ``bwrap`` is the process that would inherit it: ``--clearenv``
      only governs what runs INSIDE the sandbox.
    * a LIST, never a shell string (§7.6 rule 8).
    * ``start_new_session=True`` so the timeout can kill the whole GROUP.
    * ``stdin`` closed: an inherited stdin is both a channel to the user's
      terminal and a way for a tool to wait forever.
    * the runner's OWN deadline. ``prlimit --cpu`` is a CPU-time budget that
      fires early on threads and resets on ``fork`` (measured — see
      :mod:`~lsassist.sandbox.prlimit`), and it kills with ``SIGKILL`` just like
      this deadline does, so ``137`` alone cannot distinguish them. ``timed_out``
      is what this function OBSERVED, not what it inferred from an exit status.

    Reading never stops at the cap. :class:`~lsassist.tools.result.OutputSink`
    discards the overflow while continuing to hash it; a reader that stopped
    draining would deadlock the child against a full pipe and the run would be
    reported as a timeout for a tool whose only fault was verbosity.

    :raises DispatchError: the program could not be spawned at all.
    """
    stdout, stderr = OutputSink(stdout_cap), OutputSink(stderr_cap)
    started = clock()
    try:
        # A fixed argv LIST with an explicitly EMPTY environment (§7.6 rule 8).
        process = subprocess.Popen(
            list(argv),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={},
            start_new_session=True,
            close_fds=True,
        )
    except OSError as exc:
        raise DispatchError(f"could not spawn {list(argv)[:1]}: {exc}") from exc

    timed_out = False
    deadline = time.monotonic() + timeout_s
    streams: dict[int, tuple[IO[bytes], OutputSink]] = {}
    with selectors.DefaultSelector() as selector:
        for handle, sink in (
            (cast("IO[bytes]", process.stdout), stdout),
            (cast("IO[bytes]", process.stderr), stderr),
        ):
            selector.register(handle, selectors.EVENT_READ)
            streams[handle.fileno()] = (handle, sink)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0 and not timed_out:
                timed_out = True
                _kill_group(process.pid)
            # After the kill, wait without a deadline: SIGKILL on the group makes
            # EOF certain, and re-arming a timer here would only re-kill a group
            # that is already gone.
            for key, _ in selector.select(timeout=None if timed_out else remaining):
                handle, sink = streams[key.fd]
                chunk = os.read(key.fd, _READ_CHUNK)
                if chunk:
                    sink.feed(chunk)
                else:
                    selector.unregister(handle)
                    handle.close()
    # THE DEADLINE OUTLIVES THE READ LOOP, and this is where the timeout is
    # actually enforced for the worst case. The loop above ends when both pipes
    # reach EOF — which a child can arrange while STILL RUNNING, simply by closing
    # its own stdout and stderr. Measured: `sh -c 'exec 1>&- 2>&-; sleep 20'` with
    # `timeout_s=1` returned after 20.00 s with `timed_out=False`, because the
    # deadline was only ever checked INSIDE the loop and `wait()` then blocked
    # unbounded. `prlimit --cpu` cannot cover this either — a sleeping process
    # burns no CPU — so this is the only wall clock the tool has.
    if timed_out:
        returncode = process.wait()
    else:
        try:
            returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
        except subprocess.TimeoutExpired:
            timed_out = True
            _kill_group(process.pid)
            returncode = process.wait()
    return ExecObservation.from_sinks(
        returncode=returncode,
        duration_ms=max(0, (clock() - started) // 1_000_000),
        stdout=stdout,
        stderr=stderr,
        timed_out=timed_out,
    )


# --------------------------------------------------------------------------
# step 8 — verify (§6.3, §7.5 step 6)
# --------------------------------------------------------------------------
def _approved_parents(snapshots: Sequence[PathSnapshot]) -> dict[str, tuple[int, int]]:
    """Every directory identity §7.5 step 2 captured, keyed by its path.

    Two rows per snapshot, because the two kinds of snapshot answer the same
    question from opposite sides: an EXISTING path carries its parent's ids in
    ``parent_*``, while a create-intent path was snapshotted BY its parent, whose
    ids are therefore in ``node_*``. Either way the result is "what was the
    identity of this directory at approval time".
    """
    ids: dict[str, tuple[int, int]] = {}
    for snapshot in snapshots:
        ids[os.path.dirname(snapshot.canonical_path)] = (snapshot.parent_dev, snapshot.parent_ino)
        ids[snapshot.canonical_path] = (snapshot.node_dev, snapshot.node_ino)
    return ids


def _file_snapshot(path: str) -> ToolResultEvidence | None:
    """§7.5 step 6's inode+hash evidence, taken from ONE opened descriptor.

    ``O_NOFOLLOW`` and a single ``fstat`` on the descriptor that is then read:
    the inode reported and the bytes hashed come from the SAME open file, so the
    evidence cannot describe one file while quoting another's contents. This is
    §7.5 step 4's fstat-pinning applied to the verification side.

    :returns: ``None`` when the evidence cannot be produced honestly — the file
        vanished mid-read, could not be read at all, or exceeds
        :data:`_MAX_EVIDENCE_BYTES`. A partial hash labelled ``sha256`` would be a
        false measurement, and I12's rule is to DOWNGRADE rather than fabricate;
        the caller turns ``None`` into
        :data:`~lsassist.tools.result.Verification.UNVERIFIED`.

    The size bound is enforced ON THE BYTES READ, not on ``st_size``. A single
    ``fstat`` taken before the loop bounds nothing: the workspace is writable
    under ``ws`` and may still have a writer in it, so a target that keeps growing
    would sail past a stale size check and hash forever — which is the opposite of
    what a documented cap promises.
    """
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    except OSError:
        return None
    try:
        info = os.fstat(descriptor)
        digest = hashlib.sha256()
        read = 0
        while chunk := os.read(descriptor, _READ_CHUNK):
            read += len(chunk)
            if read > _MAX_EVIDENCE_BYTES:
                return None
            digest.update(chunk)
    except OSError:
        # `open` succeeding says nothing about `read` succeeding: a DIRECTORY
        # opens fine and then fails with EISDIR, and this runs after a tool has
        # already executed, so an escaping OSError would lose the whole record.
        return None
    finally:
        os.close(descriptor)
    return ToolResultEvidence(
        type=EvidenceType.FILE_SNAPSHOT,
        path=path,
        sha256=digest.hexdigest(),
        inode=info.st_ino,
    )


def _verify_written(
    normalized: NormalizedRequest, fs_view: FsView
) -> tuple[Verification, ToolResultEvidence | None]:
    """§7.5 step 6 for a write tool: does the target still name what was approved?

    **A CHANGED INODE IS THE EXPECTED OUTCOME, NOT THE ALARM.** §6.4's ``fs.write``
    is "atomic: tmp+``fsync``+``rename``", so a correct write REPLACES the target's
    inode every time. A post-exec check demanding a stable inode would report
    every successful write as tampering, and an alarm that fires on the happy
    path is an alarm the project learns to ignore.

    What must still hold is that the path names the same PLACE: it exists, it
    resolves to itself (no component became a symlink), and its parent directory
    is the one that was approved. A swapped parent is how a write lands in a
    directory nobody consented to while the evidence describes a file in the new
    one.
    """
    if not normalized.canonical_paths:
        # A write manifest whose optional path argument was not supplied. There
        # is no expected path to compare, so there is no §7.5 step-6 measurement
        # — and saying VERIFIED here would claim one was taken.
        return Verification.NOT_APPLICABLE, None
    approved = _approved_parents(normalized.path_snapshots)
    for path in normalized.canonical_paths:
        if not fs_view.exists(path):
            return Verification.UNVERIFIED, None
        if fs_view.realpath(path) != path:
            return Verification.UNVERIFIED, None
        # `.get` rather than `[...]`: a path with no snapshot compares against
        # `None`, which no identity tuple equals — fail-closed by construction.
        if fs_view.parent_ids(path) != approved.get(os.path.dirname(path)):
            return Verification.UNVERIFIED, None
    evidence = _file_snapshot(normalized.canonical_paths[0])
    if evidence is None:
        return Verification.UNVERIFIED, None
    # NAMED RESIDUAL: §6.5's `evidence` is ONE object, so a multi-path write tool
    # can only publish the first target's snapshot. Carrying all of them needs a
    # contracts change, which is not made from here.
    return Verification.VERIFIED, evidence


def _validate_result(manifest: ToolManifest, payload: Mapping[str, Any]) -> ToolError | None:
    """§6.3 step 8: validate ``result`` against the manifest's ``output_schema``.

    The diagnostic carries the failing KEYWORD and WHERE, never the offending
    VALUE — the same rule step 1 follows, for the same reason: ``exc.message``
    embeds the instance verbatim, the instance here is tool output, and
    ``message_redacted`` is a field whose name promises the opposite (I8, §12.4).
    """
    try:
        Draft202012Validator(manifest.output_schema).validate(dict(payload))
    except (SchemaError, JsonSchemaValidationError) as exc:
        location = "/".join(str(part) for part in exc.absolute_path) or "<root>"
        return ToolError(
            kind=MALFORMED_TOOL_RESULT,
            message_redacted=(
                f"{manifest.name} result invalid at {location} (failed {exc.validator!r})"
            ),
        )
    return None


# --------------------------------------------------------------------------
# step 9 — audit (§6.3, §14.1)
# --------------------------------------------------------------------------
def _exec_payload(
    *,
    result: ToolResult,
    normalized: NormalizedRequest,
    permission_class: PermissionClass,
    profile: Profile,
    verification: Verification,
) -> dict[str, Any]:
    """The §14.1 ``tool_result`` payload: every digest, and no body.

    §6.3 step 9 says "with all digests" and this takes it literally — the
    stdout/stderr BODIES never enter the journal. They are unbounded,
    attacker-influenced, and already attested by the digests beside them; the
    §14.3 redactor would have to be the only thing standing between tool output
    and a permanent record, on every event of every session.

    The three bindings (``action_hash``, ``env_digest``, ``canonical_paths``) are
    what make the record reviewable: they tie this execution to the approval it
    ran under.
    """
    return {
        "tool": result.tool,
        "status": result.status.value,
        "exit_code": result.exit_code,
        "duration_ms": result.duration_ms,
        "stdout_digest": result.stdout_digest,
        "stderr_digest": result.stderr_digest,
        "action_hash": normalized.action_hash,
        "env_digest": normalized.env_digest,
        "canonical_paths": list(normalized.canonical_paths),
        "permission_class": permission_class.value,
        "profile": profile.value,
        "verification": verification.value,
        "evidence": result.evidence.model_dump(mode="json") if result.evidence else {},
        "error": result.error.model_dump(mode="json") if result.error else {},
    }


def _journal(
    audit: AuditWriter,
    *,
    payload: dict[str, Any],
    result: ToolResult,
    verification: Verification,
    task_id: str,
    now: datetime.datetime | None,
) -> int:
    """Append the §14.1 events for this dispatch, or explain why it could not.

    :raises ExecutionNotJournalled: the journal refused or failed. Never
        swallowed — see the exception's own docstring.
    """
    try:
        record = audit.write(_TOOL_RESULT_EVENT, payload, task_id=task_id, now=now)
        if verification is Verification.UNVERIFIED:
            # §7.5 step 6: "mismatch = verdict UNVERIFIED + audit alert". A
            # SEPARATE event, because a reviewer greps for the alarm, not for a
            # field inside the ordinary record of a run that looked fine.
            audit.write(
                _VERIFY_EVENT,
                {**payload, "alert": "§7.5 step 6 post-exec verification failed"},
                task_id=task_id,
                now=now,
            )
    except (AuditWriteError, AuditRefusedError) as exc:
        raise ExecutionNotJournalled(result, exc) from exc
    return record.seq


@final
@dataclass(frozen=True, slots=True)
class ExecOutcome:
    """What §6.3 steps 5-9 concluded for one tool call.

    ``decision`` answers only "did a process run?" — PROCEED for an execution
    that happened, BLOCKED for one that was refused before any child existed. A
    tool that ran and failed is a PROCEED outcome carrying an ``error`` result:
    collapsing the two would make "policy refused this" and "the tool exited 1"
    the same event in the journal.
    """

    decision: Decision
    result: ToolResult
    verification: Verification
    #: The §14.1 ``seq`` of the ``tool_result`` record. Never ``None``: journalling
    #: is not optional, so there is no outcome without one.
    audit_seq: int
    observation: ExecObservation | None = None


def _no_result(observation: ExecObservation) -> Mapping[str, Any]:
    """The default step-8 payload: nothing.

    §6.1 gives the HANDLER the job of turning an observation into the tool's
    ``result``, and this module must not invent one — the shape belongs to the
    manifest's ``output_schema``, and guessing it would make every tool's
    contract this file's opinion. A manifest whose schema requires fields refuses
    the empty mapping, which is the correct and loud failure for a tool
    dispatched without its handler wired.
    """
    del observation
    return {}


def run(
    decision: DispatchDecision,
    *,
    manifest: ToolManifest,
    environment: DispatchEnvironment,
    cache_dir: str,
    task_id: str,
    argv: Sequence[str],
    audit: AuditWriter,
    probe_fn: Callable[[], SandboxAvailable] = sandbox_probe,
    runner: Callable[..., ExecObservation] = spawn_capped,
    result_of: Callable[[ExecObservation], Mapping[str, Any]] = _no_result,
    fs_view: FsView | None = None,
    now: datetime.datetime | None = None,
) -> ExecOutcome:
    """Carry out §6.3 steps 5-9 for a PROCEED decision.

    :param decision: the step-4 verdict. Anything but PROCEED is a WIRING bug —
        "nothing executes without a decision to execute" is structural in
        :class:`DispatchDecision`, and running one anyway would route around it.
    :param argv: the tool's command line, as the handler assembled it. §6.4's
        selector-style tools (``sys.info``, ``pkg.query``, ``git.read``) build a
        FIXED argv from their own allowlist, which is what makes them safe; only
        ``proc.exec`` and ``test.run`` pass one through from the model, and that
        one was already frozen verbatim at step 2.
    :param audit: the §14.1 journal. REQUIRED, with no default: an optional audit
        sink makes "every execution is recorded" a property of whoever remembered
        to pass one. Every other guarantee in this module is structural, and this
        one is cheaper to make structural than to document.
    :param result_of: how this tool's observation becomes its §6.5 ``result``.
    :param probe_fn: the §8.3 availability probe. Injected so a test can model a
        host without ``bwrap``; there is no parameter that skips it.
    :returns: an :class:`ExecOutcome`. BLOCKED outcomes are journalled too — a
        refusal nobody recorded is a refusal nobody can review.
    :raises DispatchError: a wiring failure, including a composed argv that does
        not carry the §8.3 flags.
    :raises ExecutionNotJournalled: §14.1 could not record the outcome.
    """
    if decision.decision is not Decision.PROCEED or decision.normalized is None:
        raise DispatchError(
            f"run() takes a PROCEED decision with a normalized request, got "
            f"{decision.decision.value} — nothing executes without a decision to execute"
        )
    normalized = decision.normalized
    view = fs_view or OsFsView()
    profile = profile_for(manifest)

    def blocked(kind: str, detail: str) -> ExecOutcome:
        result = build_result(
            tool=normalized.tool,
            observation=_NOTHING_RAN,
            result={},
            error=ToolError(kind=kind, message_redacted=detail),
        )
        payload = _exec_payload(
            result=result,
            normalized=normalized,
            permission_class=decision.permission_class,
            profile=profile,
            verification=Verification.NOT_APPLICABLE,
        )
        return ExecOutcome(
            decision=Decision.BLOCKED,
            result=result,
            verification=Verification.NOT_APPLICABLE,
            audit_seq=_journal(
                audit,
                payload=payload,
                result=result,
                verification=Verification.NOT_APPLICABLE,
                task_id=task_id,
                now=now,
            ),
        )

    # §7.5 step 3 — pre-exec re-canonicalization. T3.02 stopped at the decision,
    # so until now nothing re-resolved the target in the window between approval
    # and exec, which is exactly where the TOCTOU lives.
    try:
        verdict = recheck(normalized.path_snapshots, view)
    except RecheckError as exc:
        return blocked(PATH_INVALIDATED, f"the approved paths could not be re-checked: {exc}")
    if verdict is not RecheckVerdict.VALID:
        return blocked(PATH_INVALIDATED, f"§7.5 step 3 re-canonicalization: {verdict.value}")

    # §6.3 step 5.
    try:
        composed = build_exec_argv(
            normalized=normalized,
            manifest=manifest,
            environment=environment,
            available=probe_fn(),
            cache_dir=cache_dir,
            argv=argv,
        )
    except SandboxUnavailable as exc:
        # §8.3: BLOCKED, and there is no other branch. Catching this and running
        # the tool anyway is precisely the unsandboxed execution I11 forbids.
        return blocked(SANDBOX_UNAVAILABLE, exc.detail)
    except ExecRefused as exc:
        return blocked(exc.kind, str(exc))

    # §6.3 steps 6-7. `composed` came from `build_exec_argv`, which already
    # refused any argv missing the §8.3 flags, and nothing between there and here
    # touches it — so the list handed to the runner is the list that was checked.
    try:
        observation = runner(
            composed,
            timeout_s=manifest.timeout_s,
            stdout_cap=manifest.output_limits.max_stdout_bytes,
            stderr_cap=manifest.output_limits.max_stderr_bytes,
        )
    except DispatchError as exc:
        # §8.3 names this case exactly: "bwrap spawn failure → typed error
        # `sandbox_unavailable` → exec tool BLOCKED". `Popen` raising means NO
        # child was created, so this is a refusal like every other one here and
        # belongs in the journal — not an exception escaping past step 9. The
        # measured trigger is not exotic: `fork` returns EAGAIN under RLIMIT_NPROC
        # pressure, which is the same limit HARDEN-03 already watched break the
        # whole exec path on this host.
        return blocked(SANDBOX_UNAVAILABLE, str(exc))

    # §6.3 step 8.
    payload = dict(result_of(observation))
    error = _validate_result(manifest, payload)
    try:
        capped, result_truncated = cap_result(payload, manifest.output_limits.max_result_chars)
    except ResultError as exc:
        # A payload the §6.5 record cannot carry. `output_schema` does NOT catch
        # this on its own — jsonschema validates only the properties a schema
        # constrains, so `{"stdout": {1, 2}}` passes and then fails to serialize.
        # Left unhandled it escaped `run()` after the tool had run and before the
        # journal was written.
        capped, result_truncated = {}, False
        error = ToolError(kind=MALFORMED_TOOL_RESULT, message_redacted=str(exc))
    if profile is Profile.WS:
        try:
            verification, evidence = _verify_written(normalized, view)
        except RecheckError:
            # The tool ALREADY RAN, and the §7.5 adapter raises fail-closed when a
            # path or its parent is racing. A measurement that could not be taken
            # is not a reason to lose the record of an action that happened — I12
            # says DOWNGRADE, so the outcome is UNVERIFIED and the journal still
            # gets its record. (The pre-exec `recheck` above has its own handler;
            # this one did not exist and the exception escaped `run()` entirely.)
            verification, evidence = Verification.UNVERIFIED, None
    else:
        # §7.5 step 6 is scoped to WRITE tools (SPEC:564). CROSS-PHASE FLAG,
        # carried forward from `policy/recheck.py`: a same-path file swap in the
        # exec window has no post-exec backstop for read/exec tools, so their
        # handlers (T3.04/T3.06) must fstat-PIN the inode they opened.
        verification, evidence = Verification.NOT_APPLICABLE, None

    result = build_result(
        tool=normalized.tool,
        observation=observation,
        # A result the schema rejected is not published: handing the kernel an
        # unvalidated structure is what step 8 exists to prevent.
        result=capped if error is None else {},
        evidence=evidence,
        error=error,
        result_truncated=result_truncated,
    )

    # §6.3 step 9.
    audit_seq = _journal(
        audit,
        payload=_exec_payload(
            result=result,
            normalized=normalized,
            permission_class=decision.permission_class,
            profile=profile,
            verification=verification,
        ),
        result=result,
        verification=verification,
        task_id=task_id,
        now=now,
    )
    return ExecOutcome(
        decision=Decision.PROCEED,
        result=result,
        verification=verification,
        observation=observation,
        audit_seq=audit_seq,
    )
