"""THE redactor engine — the single one in the codebase (SPEC §14.3, §12.4, I8).

§14.3: "Single module; ordered rules; fail-closed on pattern-engine error (event
stored digest-only)." §12.4: "Redaction = replace with ``[REDACTED:<class>]``,
audit records the fact of redaction." §2.2 places the engine in ``audit/``; I8
makes "single" an invariant rather than a preference.

**DATA vs ENGINE.** ``config/redaction_patterns.py`` (T1.10) owns the §12.4
pattern table, the class labels, the synthetic canary seed and the
``exact_match_pattern`` escape hook — all as DATA, with no substitution logic.
This module is the only consumer permitted to compile and apply it. Nothing here
restates a key FORMAT that T1.10 already carries; :data:`REDACTION_PATTERNS` is
a re-export of T1.10's tuple, by reference, so the two cannot drift.

**WHERE THE ENGINE IS WIDER THAN THE DATA — three places, all measured.**

1. *Private keys are BLOCKS, not header lines.* T1.10's ``private-key`` source
   is ``-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`` — the header ONLY. Applied
   literally it replaces that line and leaves the base64 body in the audit
   journal. The engine compiles that class as a block.

2. *The block body is TEMPERED-GREEDY, not lazy.* A lazy ``.*?`` stops at the
   FIRST ``-----END … PRIVATE KEY-----``, so content that merely CONTAINS such a
   line — which tool output and model output can — truncates the match and emits
   the real body verbatim. Measured on the pre-fix engine:
   ``BEGIN RSA / END OPENSSH / SECRETKEYBODY… / END RSA`` redacted only the
   first two lines. The body is now ``(?:(?!-----BEGIN )[\\s\\S])*`` — greedy,
   so it reaches the LAST END, but tempered so it can never cross into the next
   key's ``BEGIN`` and swallow the text between two keys. Benchmarked linear:
   30 ms over a 1 MB unterminated block, 7 ms over 2000 unterminated BEGINs.

3. *OpenPGP armor is a private-key class T1.10's table does not match.*
   ``-----BEGIN PGP PRIVATE KEY BLOCK-----`` ends in ``BLOCK-----`` and so does
   not match ``[A-Z0-9 ]*PRIVATE KEY-----`` at all — a GPG secret key passed
   through the pre-fix engine completely unredacted, while ``~/.gnupg`` is a
   §7.3 DENY_ALWAYS subtree. See :data:`_ENGINE_PRIVATE_KEY_BEGINS`; this is the
   one place the engine ships a pattern SOURCE, and it is a named residual.

**AND ONE PLACE THE ORDERED PASS IS NOT ENOUGH.** Rules run in order over the
text, so an earlier replacement can REVEAL a later rule's left boundary:
``AKIACANARYDECOY00000sk-<20 chars>`` was emitted with the ``sk-`` key intact,
because at ``sk-`` time the key was preceded by an alphanumeric (the generic
``sk-`` rule carries a ``(?<![A-Za-z0-9])`` boundary) and by ``AKIA`` time the
``sk-`` rule had already run. The engine therefore iterates the whole rule list
to a FIXPOINT (bounded by :data:`MAX_PASSES`); failing to converge is a §14.3
engine error, not a best-effort result.

**RULE ORDER (specific → generic).** Configured secrets first (a known literal
value is the most specific thing there is), then T1.10's table verbatim —
private-key block (plus the engine's armor forms), Kimi, generic ``sk-``,
GitHub PAT, AWS key id — then the deny-path placeholder expanded in place into
one literal rule per §7.3 path.

**FAIL-CLOSED (§14.3).** :func:`redact_for_audit` is a TOTAL function: it returns
an :class:`AuditRedaction` for every input and raises nothing at the caller. All
of these collapse to the digest-only branch — ``text=""``, ``digest_only=True``,
``payload_digest=sha256(original)``, an ``engine_error`` hit, and a payload-free
``error_detail``:

* a pattern table that does not cover every §12.4 class T1.10 declares (an empty
  or filtered table used to build a no-op redactor that reported clean success —
  the one degenerate input that failed OPEN),
* an uncompilable pattern, or an empty configured secret (T1.10 rejects it:
  ``re.escape("")`` matches every position),
* ``deny_paths`` supplied with no ``deny-path-content`` slot to place them in
  (they were silently discarded, which is the same fail-open in miniature),
* a non-``str`` payload — including one whose ``__repr__`` itself raises,
* a payload over :data:`MAX_PAYLOAD_CHARS`,
* non-convergence, or ANY exception during substitution.

The branch emits NO payload, not even a partially-substituted one: "some rules
ran" is the dangerous outcome, because it looks redacted and is not.

**``error_detail`` IS PAYLOAD-FREE BY CONSTRUCTION.** Build-time failures
describe the PATTERN TABLE and carry their full message. Substitution-time
failures carry the exception's TYPE NAME only — an arbitrary exception's
``str()`` can quote the input it choked on, and the input here is the secret.

**NAMED RESIDUAL — the digest is a confirmation oracle.** ``payload_digest`` is
the sha256 of the PRE-redaction text, as T4.01 specifies for the digest-only
branch and as §14.1 expects as evidence. Anyone who can guess a secret can
confirm it against a stored record. Inherent to digest-based evidence (§6.5 uses
the same shape for ``stdout_digest``); recorded rather than silently changed,
because digesting the redacted text would break the failure branch's only link
back to what was dropped.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Final, final

from lsassist.config.redaction_patterns import (
    CLASS_DENY_PATH_CONTENT,
    CLASS_PRIVATE_KEY,
    REDACTION_PATTERNS,
    RedactionConfigError,
    RedactionPattern,
    exact_match_pattern,
    validate_patterns,
)

__all__ = [
    "CLASS_ENGINE_ERROR",
    "MAX_PASSES",
    "MAX_PAYLOAD_CHARS",
    "REDACTION_PATTERNS",
    "AuditRedaction",
    "RedactionHit",
    "Redactor",
    "RedactorError",
    "RuleInfo",
    "redact_for_audit",
]

#: The ``<class>`` recorded in ``hits`` when the engine itself failed. Spelled
#: with an underscore per the T4.01 plan text; it is an ENGINE marker, not one of
#: T1.10's hyphenated §12.4 class labels, and the difference is deliberate — a
#: reader can tell "a rule matched" from "the engine broke" at a glance.
CLASS_ENGINE_ERROR: Final = "engine_error"

#: Every §12.4 class T1.10's shipped table declares. A caller-supplied table that
#: does not cover all of them is refused: a filtered table used to produce a
#: redactor that quietly stopped redacting a class while reporting success.
_REQUIRED_CLASSES: Final[frozenset[str]] = frozenset(
    pattern.class_label for pattern in REDACTION_PATTERNS
)

#: Block BEGIN lines for the ``private-key`` class that T1.10's table does not
#: match. OpenPGP armor terminates in ``PRIVATE KEY BLOCK-----``, so it is not
#: covered by ``[A-Z0-9 ]*PRIVATE KEY-----`` — a GPG secret key passed through
#: unredacted while ``~/.gnupg`` is a §7.3 DENY_ALWAYS subtree (an I8 false
#: negative found by an adversarial critic and reproduced).
#:
#: NAMED RESIDUAL: this is pattern DATA and belongs in T1.10's table. It lives
#: here because T4.01's scope forbids modifying ``config/``, and shipping a
#: known credential format unredacted is worse than a documented boundary
#: stretch. A follow-up should move it and delete this constant.
_ENGINE_PRIVATE_KEY_BEGINS: Final[tuple[str, ...]] = (
    r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY BLOCK-----",
)

#: Body of a private-key block: any character, TEMPERED so it can never cross
#: into the next key's ``BEGIN``. That temper is what stops one block from
#: swallowing the text between two keys. ``[\s\S]`` rather than ``re.DOTALL`` so
#: the flag cannot leak into neighbouring rules.
_BLOCK_BODY: Final = r"(?:(?!-----BEGIN )[\s\S])*"

#: A block terminator, in either armor spelling.
_BLOCK_END: Final = r"-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----"

#: Body + terminator appended to a private-key BEGIN to make it a BLOCK matcher.
#:
#: TWO FULL BRANCHES, not one branch with an optional terminator. The body is
#: GREEDY so it reaches the LAST end line rather than the first — an injected
#: ``-----END … PRIVATE KEY-----`` in surrounding content must not truncate the
#: match — and the terminated branch comes FIRST because alternation is tried
#: left to right. Writing it as ``<body>(?:<end>|\Z)`` instead is WRONG and was
#: measured to be: ``\Z`` matches the empty string at end-of-text, so the greedy
#: body simply consumed the whole payload and the terminator was never needed —
#: one private key deleted every event that followed it in the same record.
#: The second branch exists only for a block whose end line never arrives, where
#: consuming to end-of-text is the safe direction.
#:
#: Linear in practice, measured: 43 ms over a 1 MB unterminated block, 10 ms
#: over 2000 unterminated BEGINs, 11 ms over 2000 complete blocks.
_PRIVATE_KEY_BLOCK_TAIL: Final = f"(?:{_BLOCK_BODY}{_BLOCK_END}|{_BLOCK_BODY})"

#: Longest single payload the engine will substitute over. Beyond it the payload
#: is stored digest-only: an unbounded regex sweep over an attacker-influenced
#: body is a denial-of-service surface, and a truncated-but-redacted journal is
#: worth more than a stalled kernel.
MAX_PAYLOAD_CHARS: Final = 1_000_000

#: Fixpoint bound. One pass performs the substitutions, a second observes that
#: nothing changed; anything beyond that means a rule is producing text another
#: rule matches, which the markers are designed to prevent. Not converging is an
#: engine error, never a best-effort partial result.
MAX_PASSES: Final = 4


class RedactorError(Exception):
    """The engine could not complete a redaction — never raised at the caller.

    Caught inside :meth:`Redactor.redact`, which converts it into the §14.3
    digest-only result. It exists so an internal failure is a typed signal
    rather than a bare ``Exception``.
    """


@final
@dataclass(frozen=True, slots=True)
class RedactionHit:
    """One §12.4 class and how many times it matched — evidence OF redaction.

    Deliberately carries no sample of what was replaced: a hit is written into
    the audit journal, and a "here is what we redacted" field would undo the
    redaction it is reporting.
    """

    class_label: str
    count: int


@final
@dataclass(frozen=True, slots=True)
class RuleInfo:
    """The public description of one ordered rule: its name and its class.

    The compiled pattern is deliberately NOT exposed. For a configured-secret
    rule the pattern source is ``re.escape(<the secret>)``, so a property that
    handed out compiled rules would hand out the secrets that
    :class:`RedactionHit` is careful never to carry.
    """

    name: str
    class_label: str


@final
@dataclass(frozen=True, slots=True)
class AuditRedaction:
    """The result of one redaction pass (§14.3 audit-facing facade).

    :ivar text: the redacted payload, or ``""`` in the digest-only branch.
    :ivar hits: one entry per matched class, sorted by label for determinism.
    :ivar digest_only: ``True`` when the engine failed closed; the caller must
        store the digest and NO payload.
    :ivar payload_digest: ``sha256:<hex>`` of the ORIGINAL text (see the module
        docstring's named residual).
    :ivar error_detail: why the engine failed closed; ``""`` on success. Free of
        payload text by construction (see the module docstring), so it is safe
        to journal — a fail-closed redactor with no diagnosis is one nobody can
        repair, and it would fail closed on every subsequent event too.
    """

    text: str
    hits: tuple[RedactionHit, ...]
    digest_only: bool
    payload_digest: str
    error_detail: str = field(default="")

    @property
    def redacted(self) -> bool:
        """True when anything at all was replaced or dropped."""
        return bool(self.hits)

    def hit_count(self, class_label: str) -> int:
        """How many times ``class_label`` matched (0 if it did not)."""
        return sum(hit.count for hit in self.hits if hit.class_label == class_label)


@final
@dataclass(frozen=True, slots=True)
class _CompiledRule:
    """One ordered rule: a compiled pattern plus the class it reports."""

    name: str
    class_label: str
    pattern: re.Pattern[str]


def _digest(text: str) -> str:
    """``sha256:<64 lowercase hex>`` — the ``Sha256Digest`` contract shape."""
    return "sha256:" + hashlib.sha256(text.encode("utf-8", errors="surrogatepass")).hexdigest()


def _marker(class_label: str) -> str:
    """§12.4's replacement token."""
    return f"[REDACTED:{class_label}]"


def _compile_source(name: str, class_label: str, source: str) -> _CompiledRule:
    """Compile one regex source into a rule, or raise :class:`RedactorError`."""
    try:
        compiled = re.compile(source)
    except re.error as exc:
        raise RedactorError(f"rule {name!r} failed to compile: {exc}") from exc
    return _CompiledRule(name=name, class_label=class_label, pattern=compiled)


def _compile(pattern: RedactionPattern) -> _CompiledRule:
    """Compile one T1.10 pattern, widening the private-key class to a BLOCK."""
    source = pattern.pattern_src
    if pattern.class_label == CLASS_PRIVATE_KEY:
        source += _PRIVATE_KEY_BLOCK_TAIL
    return _compile_source(pattern.name, pattern.class_label, source)


@final
class Redactor:
    """Ordered, fail-closed §12.4 rule engine over T1.10's pattern data.

    :param patterns: the ordered table. Defaults to T1.10's
        :data:`REDACTION_PATTERNS`; injectable so a broken rule can be tested.
        It MUST cover every class T1.10 declares — a filtered table is refused.
    :param deny_paths: canonical §7.3 DENY paths (from ``policy/denylist.py``'s
        domain). Each becomes a literal rule expanded AT the position of
        T1.10's ``deny-path-content`` placeholder.
    :param configured_secrets: resolved secret VALUES (§12.4 exact-match). Each
        becomes a literal rule placed FIRST, ahead of every format pattern.

    Construction never raises. A rule set that cannot be assembled is recorded,
    and every :meth:`redact` call then returns the digest-only result — a
    redactor that cannot run must redact everything, not nothing.
    """

    __slots__ = ("_error", "_rules")

    def __init__(
        self,
        *,
        patterns: Sequence[RedactionPattern] = REDACTION_PATTERNS,
        deny_paths: Iterable[str] = (),
        configured_secrets: Iterable[str] = (),
    ) -> None:
        self._rules: tuple[_CompiledRule, ...] = ()
        self._error: str | None = None
        try:
            self._rules = self._build(patterns, deny_paths, configured_secrets)
        # Broad on purpose: ANY failure to assemble the rule set is one §14.3
        # outcome. Letting an unexpected exception escape __init__ would put the
        # decision "carry on without a redactor?" in the caller's hands. The
        # message describes the PATTERN TABLE, never a payload — nothing has been
        # redacted yet at this point.
        except Exception as exc:
            self._error = f"{type(exc).__name__}: {exc}"

    @staticmethod
    def _build(
        patterns: Sequence[RedactionPattern],
        deny_paths: Iterable[str],
        configured_secrets: Iterable[str],
    ) -> tuple[_CompiledRule, ...]:
        """Assemble the ordered rule list, or raise (caught by ``__init__``)."""
        missing = _REQUIRED_CLASSES - {pattern.class_label for pattern in patterns}
        if missing:
            raise RedactorError(
                f"pattern table omits the §12.4 class(es) {sorted(missing)}; a redactor "
                "that silently stops covering a class is the one failure that looks "
                "like success"
            )

        # T1.10's own load-time self-check, on whatever table we were handed.
        # `RedactionConfigError` is one of the two failures §14.3 names.
        try:
            validate_patterns(patterns)
        except RedactionConfigError as exc:
            raise RedactorError(f"pattern table rejected by T1.10 validation: {exc}") from exc

        rules: list[_CompiledRule] = [
            # Most specific first: a known literal beats every format heuristic.
            # `exact_match_pattern` is T1.10's hook — it `re.escape`s the value,
            # so a secret containing regex syntax is matched literally, and it
            # REJECTS an empty value fail-closed (an empty pattern matches every
            # position and would redact the whole journal).
            _compile(exact_match_pattern(secret))
            for secret in configured_secrets
        ]

        deny_rules = [_compile(exact_match_pattern(path)) for path in deny_paths]
        placed_deny = False
        for pattern in patterns:
            rules.append(_compile(pattern))
            if pattern.class_label == CLASS_PRIVATE_KEY:
                # The armor forms T1.10's source cannot match (see the constant).
                rules.extend(
                    _compile_source(
                        f"engine-armor-{index}", CLASS_PRIVATE_KEY, begin + _PRIVATE_KEY_BLOCK_TAIL
                    )
                    for index, begin in enumerate(_ENGINE_PRIVATE_KEY_BEGINS)
                )
            if pattern.class_label == CLASS_DENY_PATH_CONTENT:
                # Expanded IN PLACE so T1.10's ordering survives verbatim.
                rules.extend(
                    _CompiledRule(
                        name=f"deny-path::{rule.name}",
                        class_label=CLASS_DENY_PATH_CONTENT,
                        pattern=rule.pattern,
                    )
                    for rule in deny_rules
                )
                placed_deny = True
        if deny_rules and not placed_deny:
            raise RedactorError(
                "deny_paths were supplied but the pattern table has no "
                f"{CLASS_DENY_PATH_CONTENT!r} slot to place them in; discarding them "
                "silently would leak §7.3 path content with digest_only=False"
            )
        return tuple(rules)

    @property
    def rules(self) -> tuple[RuleInfo, ...]:
        """The ordered rule list in force, as names + classes (never patterns)."""
        return tuple(RuleInfo(name=rule.name, class_label=rule.class_label) for rule in self._rules)

    def redact(self, text: str) -> AuditRedaction:
        """Apply every rule to a fixpoint; never raise (§14.3).

        :returns: the redacted payload plus per-class hit counts, or the
            digest-only result if anything went wrong.
        """
        if not isinstance(text, str):
            # A caller bug must not become an unredacted payload OR a crash in
            # the audit path. `repr` is inside the guard because an object whose
            # __repr__ raises would otherwise escape this "total" function.
            try:
                digest = _digest(repr(text))
            except Exception:
                digest = _digest("")
            return self._fail_closed(digest, f"payload must be str, got {type(text).__name__}")

        digest = _digest(text)
        if self._error is not None:
            return self._fail_closed(digest, self._error)
        if len(text) > MAX_PAYLOAD_CHARS:
            return self._fail_closed(
                digest, f"payload of {len(text)} chars exceeds the {MAX_PAYLOAD_CHARS} cap"
            )

        try:
            redacted, counts = self._apply(text)
        # Our own signal: the message is engine-authored (a rule name, a pass
        # count) and provably carries no payload, so it is kept in full.
        except RedactorError as exc:
            return self._fail_closed(digest, str(exc))
        # Broad on purpose (§14.3): the failure mode this branch exists to
        # prevent is a HALF-substituted payload reaching the journal, and every
        # exception produces one. Only the TYPE is recorded — an arbitrary
        # exception's str() can quote the input it choked on, and that input is
        # the secret.
        except Exception as exc:
            return self._fail_closed(digest, f"substitution raised {type(exc).__name__}")

        hits = tuple(
            RedactionHit(class_label=label, count=counts[label]) for label in sorted(counts)
        )
        return AuditRedaction(text=redacted, hits=hits, digest_only=False, payload_digest=digest)

    def _apply(self, text: str) -> tuple[str, dict[str, int]]:
        """Ordered substitution repeated to a fixpoint; returns text and counts.

        Repeated because a replacement can reveal a later rule's left boundary
        (see the module docstring). Convergence is a whole pass that changes
        nothing; :data:`MAX_PASSES` bounds it and non-convergence raises.
        """
        counts: dict[str, int] = {}
        for _ in range(MAX_PASSES):
            before = text
            for rule in self._rules:
                text, replaced = rule.pattern.subn(_marker(rule.class_label), text)
                if replaced:
                    counts[rule.class_label] = counts.get(rule.class_label, 0) + replaced
            if text == before:
                return text, counts
        raise RedactorError(f"redaction did not converge within {MAX_PASSES} passes")

    @staticmethod
    def _fail_closed(digest: str, detail: str) -> AuditRedaction:
        """The §14.3 digest-only result: no payload, and the reason recorded."""
        return AuditRedaction(
            text="",
            hits=(RedactionHit(class_label=CLASS_ENGINE_ERROR, count=1),),
            digest_only=True,
            payload_digest=digest,
            error_detail=detail,
        )


#: The default engine: T1.10's table, no runtime §7.3 paths, no configured
#: secrets. Built once because compiling the table on every audit write would
#: put a regex compile in the journal's hot path.
#:
#: NOTE FOR T4.02: the runtime forms below rebuild and recompile the rule set per
#: call. In production ``configured_secrets`` is never empty (the Kimi key), so
#: the audit writer must hold ONE :class:`Redactor` built at startup rather than
#: calling the facade per event.
_DEFAULT_REDACTOR: Final = Redactor()


def redact_for_audit(
    text: str,
    *,
    deny_paths: Sequence[str] = (),
    configured_secrets: Sequence[str] = (),
) -> AuditRedaction:
    """The §14.3 audit-facing facade — the single redaction entry point.

    :param text: the payload about to be journalled.
    :param deny_paths: canonical §7.3 DENY paths to redact by literal match.
    :param configured_secrets: resolved secret values (§12.4 exact-match).
    :returns: an :class:`AuditRedaction`. This function does not raise: every
        failure becomes the digest-only branch (see the module docstring).

    Both keywords default to empty, which means the ``configured-secret`` and
    ``deny-path-content`` classes match NOTHING on a bare call. That is not a
    silent omission — neither class is knowable statically (T1.10 ships a
    never-matching ``(?!)`` placeholder for the second and says so), so a caller
    that holds resolved secrets MUST pass them. T4.02's writer is that caller.
    """
    if not deny_paths and not configured_secrets:
        return _DEFAULT_REDACTOR.redact(text)
    return Redactor(deny_paths=deny_paths, configured_secrets=configured_secrets).redact(text)
