"""§4.6 untrusted content: the SOLE delimiter producer + the untrusted-turn flag.

SINGLE PRODUCER (I7). This module is the ONLY place in the codebase that
constructs the §4.6 untrusted delimiter or neutralizes marker-like text. Every
consumer — memory retrieval (T4.08), skill injection (T4.12), the coding
pipeline (T5.05), the red-team corpus runner (T6.01), prompt assembly — MUST
import :func:`wrap_untrusted` / :func:`defang` from here. Re-implementing the
delimiter or the defang anywhere else is forbidden and is asserted by a CI grep
(any other occurrence of ``UNTRUSTED_DATA`` construction is a defect).

SPEC §4.6 step 1 — the delimiter block, quoted verbatim::

    <<<UNTRUSTED_DATA id="<random 8-byte hex>" source="<origin>" provenance="<tier>">>
    …
    <<<END_UNTRUSTED_DATA <id>>>

(the start marker closes with ``>>`` and the end marker with ``>>>`` — that
asymmetry is the SPEC's, reproduced byte-for-byte.)

SPEC §4.6 step 2 — capability reduction. :class:`TurnTrust` is the SOURCE of
``PolicyContext.untrusted_turn``: ingesting untrusted content flips the flag
and the flag is STICKY for the rest of the turn (monotone — trusted content
ingested afterwards can never restore trust). The policy consequence (R3: any
non-AUTO_READ classification raises to CONFIRM_EXACT) already lives in
``policy.rules.classify`` (T2.01) and is NOT re-implemented here.

SPEC §4.6 step 3 — never system-role: an untrusted block belongs in a USER-role
context message. This module returns a plain string; the caller places it. It
must never be concatenated into a system prompt.

SPEC §4.6 step 4 — LIMIT HONESTY. Delimiters and defanging are a SIGNAL layer,
NOT a security boundary (§2.1). A sufficiently capable model can still be
persuaded by text inside the fence. The load-bearing controls are capability
reduction (the flag below → R3), the human gate (CONFIRM_EXACT), and OS-level
isolation (bwrap + rlimits). Nothing in this module should ever be described as
"preventing prompt injection"; it makes injected text *identifiable*.

PURITY (§2.2): stdlib only — no filesystem, network, child-process, environment
or clock access. The single non-deterministic element, the unpredictable marker
id, is INJECTED (``marker_id=`` or ``id_generator=``) so every path is
deterministically testable; the default generator is :func:`secrets.token_hex`
because a PREDICTABLE id would let attacker-controlled text emit a matching end
marker and close the fence from the inside.
"""

from __future__ import annotations

import re
import secrets
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from lsassist.contracts.enums import PermissionClass
from lsassist.contracts.policy_context import PolicyContext

#: SPEC §4.6: "random 8-byte hex" → 16 lowercase hex characters.
MARKER_ID_BYTES = 8

#: Attribute values are quote-delimited, so anything that could terminate the
#: attribute or the marker is refused (fail closed): quotes, angle brackets,
#: C0/C1 controls, DEL. Length-capped to keep the header bounded.
_ATTRIBUTE = r'[^"<>\x00-\x1f\x7f-\x9f]{1,256}'

#: The ONE valid start marker (§4.6, verbatim). Groups: id, source, provenance.
START_MARKER_PATTERN = re.compile(
    r'<<<UNTRUSTED_DATA id="(?P<id>[0-9a-f]{16})"'
    r' source="(?P<source>' + _ATTRIBUTE + r')"'
    r' provenance="(?P<provenance>' + _ATTRIBUTE + r')">>'
)

#: The ONE valid end marker (§4.6, verbatim), carrying the same id.
END_MARKER_PATTERN = re.compile(r"<<<END_UNTRUSTED_DATA (?P<id>[0-9a-f]{16})>>>")

#: The sentinel word shared by BOTH markers. Case-insensitive on purpose: a
#: lowercase forgery cannot match the real patterns but can still mislead a
#: reader, and neutralizing the word is what makes forgery structurally
#: impossible (no sentinel in the body → no marker of any id in the body).
SENTINEL_PATTERN = re.compile("UNTRUSTED_DATA", re.IGNORECASE)

#: Characters deleted before folding: C0/C1 controls (incl. NUL) except tab /
#: LF / CR, DEL, soft hyphen, Arabic letter mark, Mongolian vowel separator,
#: zero-width + directional marks, bidi embeddings/overrides/isolates, word
#: joiner + invisible operators, variation selectors, interlinear annotation,
#: BOM, lone surrogates, and the invisible Unicode TAG block. Each of these can
#: split the sentinel word (hiding it from the matcher while a model still
#: reads it) or reverse/obscure how the block renders.
FORBIDDEN_CHAR_PATTERN = re.compile(
    "[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f\u00ad\u061c\u180e\u200b-\u200f"
    "\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufe00-\ufe0f\ufeff\ufff9-\ufffb"
    "\ud800-\udfff\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)

#: What the sentinel's ``_`` becomes. Chosen so the replacement can never match
#: the sentinel again — which is exactly what makes :func:`defang` idempotent.
DEFANG_SEPARATOR = "-"

IdGenerator = Callable[[], str]


class UntrustedWrapError(Exception):
    """A well-formed §4.6 block could not be built — fail CLOSED (I7).

    Raised when the frame would not verify: a marker id that is not 16 lowercase
    hex characters, or a ``source``/``provenance`` carrying a quote, an angle
    bracket, a control character, or nothing at all. Never fall back to emitting
    the raw text: unfenced untrusted content is worse than no content.
    """


def generate_marker_id() -> str:
    """Return a fresh, cryptographically unpredictable 8-byte hex marker id.

    The default (injectable) id source. Unpredictability is load-bearing: it is
    what stops attacker-controlled text from spelling out a matching end marker.
    """
    return secrets.token_hex(MARKER_ID_BYTES)


def _break_sentinel(match: re.Match[str]) -> str:
    return match.group(0).replace("_", DEFANG_SEPARATOR)


def defang(text: str) -> str:
    """Neutralize every marker-like substring in ``text`` (§4.6 step 1).

    Three stages, in this order:

    1. DELETE the :data:`FORBIDDEN_CHAR_PATTERN` characters (NUL, other C0/C1
       controls, zero-width, bidi, variation selectors, BOM, tag characters,
       surrogates) — otherwise ``UNTRUSTED_\\u200bDATA`` would slip past stage 3
       while still reading as the sentinel.
    2. FOLD with NFKC, collapsing compatibility homoglyphs (fullwidth
       U+FF21..U+FF5A letters and U+FF3F low line, mathematical
       alphanumerics, ...) onto ASCII so stage 3 sees them. Deleting before
       folding also guarantees the result is normalization-stable, hence
       idempotent, since removing a character can otherwise re-open a
       composition NFKC had already settled.
    3. BREAK the sentinel word: ``UNTRUSTED_DATA`` → ``UNTRUSTED-DATA``
       (case-preserving, case-insensitively matched). Since the replacement can
       never re-match, ``defang(defang(x)) == defang(x)``.

    Non-goals, honestly stated: cross-script confusables (e.g. U+0410, the
    Cyrillic capital A) are NOT folded — they cannot forge the ASCII markers, so
    they cannot escape the fence; they can only *look* like one to a reader.
    Legitimate ``<<<`` runs (git conflict markers, heredocs, CUDA) are
    deliberately left intact: without the sentinel they are not delimiters, and
    mangling them would corrupt the very payload the model must reason about.
    """
    folded = unicodedata.normalize("NFKC", FORBIDDEN_CHAR_PATTERN.sub("", text))
    return SENTINEL_PATTERN.sub(_break_sentinel, folded)


def _is_well_formed(block: str, marker_id: str) -> bool:
    """Verify the built block really is ONE §4.6 pair with an inert body."""
    starts = list(START_MARKER_PATTERN.finditer(block))
    ends = list(END_MARKER_PATTERN.finditer(block))
    return (
        len(starts) == 1
        and len(ends) == 1
        and starts[0].start() == 0
        and ends[0].end() == len(block)
        and starts[0]["id"] == marker_id
        and ends[0]["id"] == marker_id
        and SENTINEL_PATTERN.search(block, starts[0].end(), ends[0].start()) is None
    )


def wrap_untrusted(
    text: str,
    source: str,
    provenance: str,
    *,
    marker_id: str | None = None,
    id_generator: IdGenerator = generate_marker_id,
) -> str:
    """Wrap untrusted ``text`` in the §4.6 delimiter block (step 1).

    ``source`` (origin, e.g. ``tool:fs.read``) and ``provenance`` (trust tier)
    are written verbatim into the header attributes; ``text`` is :func:`defang`ed
    BEFORE insertion. ``marker_id`` pins the id for deterministic tests,
    otherwise ``id_generator`` (default :func:`generate_marker_id`) supplies one.

    The attributes are :func:`defang`ed too — they routinely carry attacker-
    influenced strings (a filename may legally contain a bidi override that
    would render the whole header reversed), and "verbatim" is unaffected for
    any value that does not already carry invisible or sentinel text. What
    defang cannot neutralize there — a quote, an angle bracket, a newline, an
    empty value — is REFUSED rather than mangled.

    The finished block is re-parsed with the public patterns and MUST contain
    exactly one start marker at offset 0, one end marker at the end, both
    carrying ``marker_id``, and no sentinel in between — otherwise
    :class:`UntrustedWrapError` is raised (fail closed, never emit a
    half-fenced block).
    """
    resolved_id = id_generator() if marker_id is None else marker_id
    block = (
        f'<<<UNTRUSTED_DATA id="{resolved_id}" source="{defang(source)}"'
        f' provenance="{defang(provenance)}">>\n'
        f"{defang(text)}\n"
        f"<<<END_UNTRUSTED_DATA {resolved_id}>>>"
    )
    if not _is_well_formed(block, resolved_id):
        raise UntrustedWrapError(
            "refusing to emit an unverifiable untrusted block: the marker id must "
            "be 16 lowercase hex characters and source/provenance must be "
            "non-empty and free of quotes, angle brackets and control characters"
        )
    return block


@dataclass(frozen=True, slots=True)
class TurnTrust:
    """Monotone (STICKY) untrusted-content accumulator for ONE turn (§4.6 step 2).

    ``untrusted`` starts ``False`` and can only ever go ``True``: the only
    transition is :meth:`ingest_untrusted`. :meth:`ingest_trusted` exists to make
    that asymmetry explicit at every call site — it CANNOT clear the flag. A turn
    is reset by starting a new value (:func:`new_turn`), never by mutation; the
    dataclass is frozen so a caller cannot clear the flag by assignment either.

    Fail-closed by design: ANY untrusted ingestion flips the flag. We do not gate
    it behind an "is this text action-requesting?" heuristic — such a classifier
    is precisely the signal-layer guess §2.1 assumes will fail.
    """

    untrusted: bool = False
    untrusted_sources: tuple[str, ...] = ()

    def ingest_untrusted(self, source: str) -> TurnTrust:
        """Record one untrusted ingestion → flag set, ``source`` appended."""
        return TurnTrust(untrusted=True, untrusted_sources=(*self.untrusted_sources, source))

    def ingest_trusted(self, source: str) -> TurnTrust:
        """Record trusted content (direct user instruction) — NEVER clears."""
        return self

    def to_policy_context(
        self,
        workspace_root: str,
        *,
        skill_ceiling: PermissionClass | None = None,
    ) -> PolicyContext:
        """Project this turn's trust onto the §7.2 classification context.

        This is the propagation edge: ``PolicyContext.untrusted_turn`` gets its
        value here and nowhere else, which is what arms T2.01's R3 raise.
        """
        return PolicyContext(
            workspace_root=workspace_root,
            untrusted_turn=self.untrusted,
            skill_ceiling=skill_ceiling,
        )


def new_turn() -> TurnTrust:
    """Start a fresh turn: trusted until untrusted content is ingested."""
    return TurnTrust()


def compute_turn_trust(ingestions: Iterable[tuple[str, bool]]) -> TurnTrust:
    """Fold ``(source, trusted)`` ingestion events into one :class:`TurnTrust`."""
    trust = TurnTrust()
    for source, trusted in ingestions:
        trust = trust.ingest_trusted(source) if trusted else trust.ingest_untrusted(source)
    return trust


def ingest_untrusted_block(
    trust: TurnTrust,
    text: str,
    source: str,
    provenance: str,
    *,
    marker_id: str | None = None,
    id_generator: IdGenerator = generate_marker_id,
) -> tuple[TurnTrust, str]:
    """Wrap untrusted content AND flag the turn — the single kernel call site.

    Returns ``(trust', block)``. Binding the two halves of §4.6 (step 1 wrap,
    step 2 capability reduction) into one call makes it structurally impossible
    to inject untrusted content into a turn without also reducing that turn's
    capability. Raises :class:`UntrustedWrapError` (fail closed) before any flag
    change if the block cannot be verified.
    """
    block = wrap_untrusted(
        text, source, provenance, marker_id=marker_id, id_generator=id_generator
    )
    return trust.ingest_untrusted(source), block
