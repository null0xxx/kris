"""Dispatch pipeline steps 1-4 — validate, normalize, classify, approve.

SPEC §6.3: "1. Schema validate … 2. Normalize/canonicalize … 3. Policy classify
… 4. Approval". Steps 5-9 (sandbox build, execute, observe, verify, audit) are
T3.03's; this module stops at the decision and hands nothing to a handler
without one.

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
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum
from types import MappingProxyType
from typing import Any, Final, final

from jsonschema import Draft202012Validator  # type: ignore[import-untyped]
from jsonschema.exceptions import SchemaError  # type: ignore[import-untyped]
from jsonschema.exceptions import ValidationError as JsonSchemaValidationError

from lsassist.contracts.approval import ApprovalClass, ApprovalRecord
from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.manifest import FsCapability, ProcCapability, Rollback, ToolManifest
from lsassist.contracts.policy_context import PolicyContext
from lsassist.contracts.tool_request import ToolRequest
from lsassist.contracts.tool_result import ToolError
from lsassist.policy.canonical import CanonicalizationError, action_hash, canonicalize, env_digest
from lsassist.policy.classes import rank
from lsassist.policy.rules import classify, r2, r4, r5, r6, r7, r8, r9
from lsassist.policy.stores import PolicyStores
from lsassist.policy.token import ApprovalToken, TokenService, TokenVerdict
from lsassist.sandbox.env import DEFAULT_PATH, EnvProjectionError, project_env

__all__ = [
    "CLASS_APPROVAL_TERMS",
    "MALFORMED_TOOL_REQUEST",
    "ApprovalGrant",
    "Decision",
    "DispatchDecision",
    "DispatchEnvironment",
    "DispatchError",
    "MalformedToolRequest",
    "NormalizedRequest",
    "dispatch",
    "matched_rule_ids",
    "normalize",
    "policy_note",
    "rollback_hint",
    "validate_args",
]

#: §6.3 step 1's error kind. A ``ToolError.kind``, NOT a §4.4 ExitReason: the
#: model produced an ill-formed call, which is a tool-level result, not a reason
#: the whole task ended.
MALFORMED_TOOL_REQUEST: Final = "malformed_tool_request"

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
