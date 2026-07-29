"""§6.4 read-only tool handlers and the contract the dispatcher calls them by (T3.04).

A handler is the ONLY code that touches a tool's actual subject matter. It runs
AFTER the §6.3 pipeline has validated, canonicalized, classified and approved the
request, so it never re-decides any of that — but it does re-CHECK two things,
because a handler is the last code that runs before the bytes leave the machine.

**WHY A HANDLER RE-CHECKS WHAT POLICY ALREADY DECIDED.** §7.5's chain is only as
strong as its last link. The dispatcher's §7.3 DENY test ran against the path as
canonicalized at step 2, and its `recheck` ran at step 3; between step 3 and the
`open` there is a real window. The handler-side double-check (§7.3) and the
inode pin (§7.5 step 6) close it at the only moment where "the path I checked"
and "the file I am reading" can be proven to be the same object — after `open`,
against the fd. Checking earlier is checking a name; checking the fd is checking
the file.

**TWO ROUTES, ONE PIPELINE.** Tools whose manifest declares ``capabilities.proc =
none`` (``fs.read``, ``fs.list``, ``fs.find``) create no process: there is nothing
for bwrap to isolate, and their protection is the path chain — canonicalization,
workspace scope, the DENY list, ``O_NOFOLLOW`` and a parent ``dir_fd``. They run
IN-PROCESS through :data:`Handler`. Tools declaring ``spawn_argv`` (``sys.info``,
``pkg.query``, ``git.read``) keep the T3.03 sandbox route unchanged and use the
dispatcher's ``argv``/``result_of`` seam instead. Both routes converge on the same
§6.3 step 8-9 code, so there is exactly one place where a result is validated,
capped and journalled.

**NAMED RESIDUAL — the audit cannot yet tell the two routes apart.** §14.1's
``tool_result`` payload carries ``profile``, whose only V1 values are ``ro`` and
``ws`` (:class:`~lsassist.contracts.sandbox_profile.Profile`). An in-process read
enters NO sandbox, so recording the decision's ``ro`` describes the approval
rather than the execution. Adding a third value would ripple through
``contracts``, ``policy`` and ``kernel``; the tool NAME plus its manifest already
identify the route to a reader. Flagged for the audit-schema owner.
"""

from __future__ import annotations

from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, final

if TYPE_CHECKING:  # pragma: no cover - import cycle guard, typing only
    from lsassist.contracts.manifest import ToolManifest
    from lsassist.tools.dispatcher import DispatchEnvironment, NormalizedRequest

__all__ = [
    "CANARY_TRIPPED",
    "DENY_PATH",
    "READ_FAILED",
    "TARGET_REPLACED",
    "TIMED_OUT",
    "WORKSPACE_SCOPE",
    "Handler",
    "HandlerContext",
    "HandlerRefused",
]

#: §19 scenario 1. A read was attempted against a canary honeyfile. The handler
#: raises this INSTEAD of returning content — the file's bytes never enter a
#: result, a digest or the journal, because the whole point of a honeyfile is
#: that reaching it is the signal, not the data.
#:
#: **CROSS-PHASE OBLIGATION (T5.12 session engine).** §19 asks for three
#: reactions: audit alert, SESSION FREEZE, and a user notice. A handler can only
#: own the first half of the first one — it refuses, and the refusal is
#: journalled by §6.3 step 9 like any other. There is today no freeze state in
#: :class:`~lsassist.kernel.states.State` and no compromise member in
#: :class:`~lsassist.audit.schema.AuditEvent` (whose vocabulary is closed), so
#: the freeze and the notice are NOT implemented here and must not be assumed.
CANARY_TRIPPED: Final = "canary_tripped"

#: §7.3 handler-side double-check. The dispatcher already refuses these at step
#: 3; this fires when a path became denied between that check and the open.
DENY_PATH: Final = "deny_path"

#: §7.5 step 6 for READ tools. The inode behind the opened fd is not the inode
#: the approval was bound to — a same-path swap inside the exec window.
TARGET_REPLACED: Final = "target_replaced"

#: The subject could not be read at all (absent, not a regular file, EACCES,
#: a symlink where ``O_NOFOLLOW`` refused to follow).
READ_FAILED: Final = "read_failed"

#: §6.2 ``path_scope`` was violated: the path is outside the workspace the tool
#: declared it works within.
#:
#: **This exists because the declaration alone enforced NOTHING.** ``path_scope``
#: is on every manifest and was, until this check, read by no code in ``src/``:
#: :mod:`lsassist.policy.rules`'s R2 fires only for ``{fs.write, fs.patch}``,
#: ``AUTO_READ`` short-circuits §6.3 step 3 to PROCEED, and
#: :func:`lsassist.policy.canonical.canonicalize` takes no workspace argument. The
#: narrow §7.3 blocklist was therefore the ONLY bound on a read, and everything
#: not enumerated there — ``~/.netrc``, ``~/.kube/config``, ``~/.npmrc``,
#: ``~/.docker/config.json``, shell history, browser profile stores — was
#: readable, listable and content-searchable in-process and unsandboxed
#: (reproduced against this candidate before the check existed).
#:
#: The value deliberately matches
#: :data:`lsassist.tools.dispatcher.WORKSPACE_SCOPE`: it is the same class of
#: violation, and one reason code is easier to key an alert on than two.
WORKSPACE_SCOPE: Final = "workspace_scope"

#: The tool's ``timeout_s`` elapsed. The spawn route gets this enforced by the
#: runner's own clock; an in-process handler has no child to kill, so it is given
#: a DEADLINE and must check it — a budget nothing consults is a number in a
#: manifest, not a bound.
TIMED_OUT: Final = "timeout"


class HandlerRefused(Exception):
    """A handler declined to produce a result, with a typed reason.

    Handlers never return a partial or "best effort" result: §6.5 has one
    ``status=error`` shape and the dispatcher turns this into it. Raising rather
    than returning is deliberate — a refusal that travelled as a normal return
    value would be one forgotten ``if`` away from being published as success.
    """

    def __init__(self, kind: str, detail: str) -> None:
        super().__init__(f"{kind}: {detail}")
        self.kind = kind
        self.detail = detail


@final
@dataclass(frozen=True, slots=True)
class HandlerContext:
    """Everything a handler may see — and nothing else (§6.1).

    §6.1 scopes a handler's input to "validated args + canonical paths"; there is
    deliberately no transcript, no reasoning channel and no provider state here,
    so a handler cannot be steered by model output.

    :param canary_paths: canonical paths of the §19 honeyfiles, resolved ONCE per
        session. It is injected rather than read here because
        :func:`~lsassist.config.canary.canary_registry` does filesystem I/O and
        raises ``ConfigSecurityError`` on tamper — running that on every
        ``fs.read`` would turn a per-session integrity check into a per-call
        failure mode, and a handler that cannot read the registry must not
        thereby become a handler that skips the check.
    """

    normalized: NormalizedRequest
    manifest: ToolManifest
    environment: DispatchEnvironment
    canary_paths: frozenset[str] = field(default_factory=frozenset)
    #: ``time.monotonic()`` value after which the handler must stop, derived from
    #: the manifest's ``timeout_s``. ``None`` means "no budget", which is correct
    #: only for a direct unit call — :func:`lsassist.tools.dispatcher.run` always
    #: supplies one. A walk that never consults it can run for as long as the
    #: filesystem is wide, and nothing kills an in-process handler.
    deadline: float | None = None


#: What the dispatcher's in-process route calls. Returns the §6.5 ``result``
#: payload, which is then validated against the manifest's ``output_schema`` and
#: capped by ``max_result_chars`` exactly as a spawned tool's payload is.
Handler = Callable[[HandlerContext], Mapping[str, Any]]
