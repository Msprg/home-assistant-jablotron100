"""Rules governing what may be written into the panel's user table.

This is the single implementation of those rules. Both write paths run
through it:

- the operator CLI — ``jablotron_user_tool`` ``add``/``edit`` →
  :func:`jablotron_user_tool.validate_preflight`
- the HTTP API — ``server/app.py`` → ``panel/runtime`` →
  :func:`jablotron_api.services.user_manager.apply_upsert`

Rules enforced here:

``invalid_user_code`` / ``code_length_unknown``
    The PIN stored in a user slot must be digits of the panel's own
    ``code_length`` (4, 6 or 8, panel-wide, from the exported
    ``main_config``). When that length cannot be established we refuse
    rather than guess.

``duplicate_code`` / ``duplicate_card`` / ``card_repeated_in_request``
    Two users must not share a code or an access card.

``panic_code_collision``
    Entering a user's code with its last digit incremented mod 10 fires a
    **silent panic alarm** on this panel (``1483`` → ``1484``, ``1489`` →
    ``1480``). A code that is another user's panic twin must therefore never
    be assigned: that user would trip a silent alarm on every legitimate
    unlock, and by construction nobody would notice.

    The rule is symmetric. For any two distinct codes ``X`` and ``Y`` in the
    table::

        panic(X) != Y  and  panic(Y) != X  and  X != Y

    Checking a single direction makes the outcome depend on which user was
    created first, so half the collisions get through. Both directions are
    checked here against the same table.

    Consequence, which is expected rather than a defect: codes sharing a
    prefix can only use non-adjacent last digits, so a prefix supports at
    most five codes ({0, 2, 4, 6, 8}), not ten.

``time_limited_group_requires_code``
    A user in a time-limited group must have a code.

``name_too_long`` / ``comment_too_long``
    ``name`` and ``comment`` are 60-byte fields on the panel
    (``CFG_MAX_TEXT_LEN`` in its configuration schema). The limit is in
    UTF-8 bytes, not characters. The usable length is 60, not 59: the live
    panel exports a comment of exactly 60 bytes that decodes cleanly, so
    the field carries no terminator. The record encoder does not clip an
    over-long value, so without this rule it would reach the panel and be
    cut there with nothing in the response to say so.

The arithmetic is deliberately length-agnostic (see :func:`panic_code`): it
rewrites the last digit of the code string, so it generalises to whatever
``code_length`` the panel reports without a 4-digit assumption anywhere.

Message discipline: violation messages name the rule and the conflicting
user IDs, and never quote a code or card value. These messages reach HTTP
clients (which may hold ``users:write`` without the sensitive read scope
that unredacts codes) and the server log, so echoing a credential back
would leak it.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Iterable, Sequence

from jablotron_api.domain.codes import CodeFormat, validate_user_table_code

REASON_INVALID_USER_CODE = "invalid_user_code"
REASON_CODE_LENGTH_UNKNOWN = "code_length_unknown"
REASON_DUPLICATE_CODE = "duplicate_code"
REASON_PANIC_CODE_COLLISION = "panic_code_collision"
REASON_DUPLICATE_CARD = "duplicate_card"
REASON_CARD_REPEATED = "card_repeated_in_request"
REASON_TIME_LIMITED_GROUP_REQUIRES_CODE = "time_limited_group_requires_code"
REASON_NAME_TOO_LONG = "name_too_long"
REASON_COMMENT_TOO_LONG = "comment_too_long"

# CFG_MAX_TEXT_LEN. Measured rather than assumed: a live record's comment is
# exactly 60 UTF-8 bytes in the panel's own export and decodes cleanly.
NAME_MAX_BYTES = 60
COMMENT_MAX_BYTES = 60

__all__ = [
    "COMMENT_MAX_BYTES",
    "NAME_MAX_BYTES",
    "REASON_CARD_REPEATED",
    "REASON_CODE_LENGTH_UNKNOWN",
    "REASON_COMMENT_TOO_LONG",
    "REASON_DUPLICATE_CARD",
    "REASON_DUPLICATE_CODE",
    "REASON_INVALID_USER_CODE",
    "REASON_NAME_TOO_LONG",
    "REASON_PANIC_CODE_COLLISION",
    "REASON_TIME_LIMITED_GROUP_REQUIRES_CODE",
    "UserSlotOccupied",
    "UserTableEntry",
    "UserWriteRejected",
    "UserWriteViolation",
    "entry_from_record",
    "panic_code",
    "validate_user_write",
]


@dataclass(frozen=True)
class UserTableEntry:
    """One row of the panel's user table, reduced to the validated fields."""

    user_id: int | None = None
    code: str = ""
    cards: tuple[str, ...] = ()
    time_limited_group_raw: int | None = None
    name: str = ""
    comment: str = ""


@dataclass(frozen=True)
class UserWriteViolation:
    """One broken rule: a machine-readable reason plus a human message."""

    reason: str
    message: str
    user_ids: tuple[int, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "reason": self.reason,
            "message": self.message,
            "user_ids": list(self.user_ids),
        }


class UserWriteRejected(ValueError):
    """The submitted user record is illegal for this panel.

    Deliberately distinct from a panel/transport failure: this means "you
    gave me a bad value, here is why" — the caller can retry with a
    different value — whereas a ``RuntimeError`` from the write path means
    the panel or the link is broken and the caller should stop.

    Subclasses ``ValueError`` so that any handler which does not know about
    this type still treats it as bad input rather than an internal fault.
    """

    def __init__(self, violations: Sequence[UserWriteViolation]) -> None:
        self.violations: tuple[UserWriteViolation, ...] = tuple(violations)
        super().__init__(self.summary())

    @property
    def reason(self) -> str:
        return self.violations[0].reason if self.violations else "user_write_rejected"

    @property
    def conflicting_user_ids(self) -> tuple[int, ...]:
        ids: set[int] = set()
        for violation in self.violations:
            ids.update(violation.user_ids)
        return tuple(sorted(ids))

    def summary(self) -> str:
        return "; ".join(violation.message for violation in self.violations)

    def cli_message(self) -> str:
        return "Preflight validation failed:\n- " + "\n- ".join(
            f"[{violation.reason}] {violation.message}" for violation in self.violations
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "error": "user_write_rejected",
            "reason": self.reason,
            "message": self.summary(),
            "violations": [violation.as_dict() for violation in self.violations],
            "conflicting_user_ids": list(self.conflicting_user_ids),
        }


class UserSlotOccupied(Exception):
    """A create was aimed at a slot that already holds a named user.

    The panel's import is an upsert, so without this check a ``POST`` onto
    an occupied slot would silently overwrite whoever is there. It is not a
    :class:`UserWriteRejected` — the record itself may be perfectly legal —
    and it is not a panel failure either: the HTTP layer reports it as
    ``409`` with ``error: user_slot_occupied``, and the caller either picks
    another slot or repeats the request with ``replace=1``.
    """

    def __init__(self, user_id: int) -> None:
        self.user_id = user_id
        super().__init__(
            f"User slot {user_id} already holds a named user; pass replace=1 to "
            "overwrite it, or edit it with PATCH."
        )

    def to_payload(self) -> dict[str, Any]:
        return {
            "error": "user_slot_occupied",
            "user_id": self.user_id,
            "message": str(self),
        }


def entry_from_record(record: Any) -> UserTableEntry:
    """Adapt a user record into the shape the rules operate on.

    Duck-typed on purpose: it accepts the RE tools' ``UserRecord`` and the
    API's ``UserModel`` alike (``UserModel`` names its ID ``id``), which
    keeps this module free of any import from the reverse-engineering
    layer and therefore unit-testable without a panel.
    """

    user_id = getattr(record, "user_id", None)
    if user_id is None:
        user_id = getattr(record, "id", None)
    return UserTableEntry(
        user_id=user_id,
        code=getattr(record, "code", "") or "",
        cards=tuple(card for card in (getattr(record, "cards", ()) or ()) if card),
        time_limited_group_raw=getattr(record, "time_limited_group_raw", None),
        name=getattr(record, "name", "") or "",
        comment=getattr(record, "comment", "") or "",
    )


def panic_code(code: str | None) -> str | None:
    """Return the silent-panic twin of ``code``, or ``None`` if there is none.

    ``panic(C)`` is ``C`` with its last digit replaced by
    ``(last_digit + 1) % 10``. Rewriting the last character rather than
    doing modular arithmetic on the whole number is what makes this correct
    for every panel ``code_length`` — 4, 6 and 8 alike — with no length
    constant involved.

    Returns ``None`` for an empty or non-numeric code, which has no panic
    twin that could be typed on a keypad.
    """

    digits = (code or "").strip()
    if not digits or not digits.isdigit():
        return None
    return digits[:-1] + str((int(digits[-1]) + 1) % 10)


def _format_user_ids(user_ids: Sequence[int]) -> str:
    return ", ".join(str(user_id) for user_id in user_ids)


def validate_user_write(
    *,
    existing: Iterable[UserTableEntry],
    user_id: int,
    current: UserTableEntry | None,
    target: UserTableEntry,
    code_format: CodeFormat,
) -> list[str]:
    """Decide whether writing ``target`` into slot ``user_id`` is legal.

    ``existing`` must come from a **fresh** read of the panel's user table —
    a cached view means the decision is made against a table that no longer
    exists. ``current`` is that user's own row as read from the same fresh
    table (``None`` for a create).

    Returns the list of non-fatal warnings. Raises :class:`UserWriteRejected`
    listing every rule that fired.

    A conflict the user already has with their own unchanged value is
    demoted to a warning: an edit that leaves a code or card as-is must not
    be refused for colliding with itself, or for a collision that already
    exists on the panel and is not being introduced by this write.
    """

    errors: list[UserWriteViolation] = []
    warnings: list[str] = []

    def record(violation: UserWriteViolation, *, unchanged: bool) -> None:
        if unchanged:
            warnings.append(violation.message)
        else:
            errors.append(violation)

    others = [
        entry
        for entry in existing
        if entry.user_id is not None and entry.user_id != user_id
    ]

    # Field widths, in UTF-8 bytes. Never demoted to a warning: a value the
    # panel already holds fits by construction, so an over-long one is
    # always being introduced by this write.
    name_bytes = len((target.name or "").encode("utf-8"))
    if name_bytes > NAME_MAX_BYTES:
        errors.append(
            UserWriteViolation(
                REASON_NAME_TOO_LONG,
                f"The name is {name_bytes} bytes of UTF-8; the panel's name field "
                f"holds at most {NAME_MAX_BYTES}.",
            )
        )
    comment_bytes = len((target.comment or "").encode("utf-8"))
    if comment_bytes > COMMENT_MAX_BYTES:
        errors.append(
            UserWriteViolation(
                REASON_COMMENT_TOO_LONG,
                f"The comment is {comment_bytes} bytes of UTF-8; the panel's comment "
                f"field holds at most {COMMENT_MAX_BYTES}.",
            )
        )

    code = (target.code or "").strip()
    current_code = (current.code or "").strip() if current is not None else ""
    code_unchanged = bool(code) and code == current_code

    if code:
        if code_format.code_length is None:
            record(
                UserWriteViolation(
                    REASON_CODE_LENGTH_UNKNOWN,
                    "The panel's code length is unknown, so the submitted code's "
                    "shape cannot be checked; refusing to write a user code rather "
                    "than guessing it.",
                ),
                unchanged=code_unchanged,
            )
        else:
            try:
                validate_user_table_code(code, code_format)
            except ValueError as exc:
                record(
                    UserWriteViolation(REASON_INVALID_USER_CODE, str(exc)),
                    unchanged=code_unchanged,
                )

        duplicates = sorted(
            entry.user_id
            for entry in others
            if (entry.code or "").strip() == code
            if entry.user_id is not None
        )
        if duplicates:
            record(
                UserWriteViolation(
                    REASON_DUPLICATE_CODE,
                    "The submitted code is already assigned to user(s) "
                    f"{_format_user_ids(duplicates)}.",
                    tuple(duplicates),
                ),
                unchanged=code_unchanged,
            )

        # Direction A: the submitted code IS another user's panic twin, so
        # this user would fire that user's silent alarm on every use.
        tripped_by_target = sorted(
            entry.user_id
            for entry in others
            if panic_code(entry.code) == code
            if entry.user_id is not None
        )
        if tripped_by_target:
            record(
                UserWriteViolation(
                    REASON_PANIC_CODE_COLLISION,
                    "The submitted code is the silent-panic (duress) code of user(s) "
                    f"{_format_user_ids(tripped_by_target)}, so user {user_id} would "
                    "raise a silent panic alarm on every legitimate use.",
                    tuple(tripped_by_target),
                ),
                unchanged=code_unchanged,
            )

        # Direction B: the submitted code's panic twin is already another
        # user's code, so THAT user would fire this user's silent alarm on
        # every use. Omitting this half is the classic order-dependent bug.
        target_panic = panic_code(code)
        tripping_target = sorted(
            entry.user_id
            for entry in others
            if target_panic is not None and (entry.code or "").strip() == target_panic
            if entry.user_id is not None
        )
        if tripping_target:
            record(
                UserWriteViolation(
                    REASON_PANIC_CODE_COLLISION,
                    "The silent-panic (duress) code of the submitted code is already "
                    f"the code of user(s) {_format_user_ids(tripping_target)}, who "
                    "would raise a silent panic alarm on every legitimate use.",
                    tuple(tripping_target),
                ),
                unchanged=code_unchanged,
            )

    current_cards = set(current.cards) if current is not None else set()
    submitted_cards = [card for card in target.cards if card]
    if len(submitted_cards) != len(set(submitted_cards)):
        errors.append(
            UserWriteViolation(
                REASON_CARD_REPEATED,
                "card1 and card2 would contain the same card ID.",
            )
        )
    for position, card in enumerate(target.cards, start=1):
        if not card:
            continue
        conflicts = sorted(
            entry.user_id
            for entry in others
            if card in entry.cards
            if entry.user_id is not None
        )
        if conflicts:
            record(
                UserWriteViolation(
                    REASON_DUPLICATE_CARD,
                    f"Card {position} is already assigned to user(s) "
                    f"{_format_user_ids(conflicts)}.",
                    tuple(conflicts),
                ),
                unchanged=card in current_cards,
            )

    time_limit_group = int(target.time_limited_group_raw or 0)
    current_time_limit = (
        int(current.time_limited_group_raw or 0) if current is not None else 0
    )
    if time_limit_group > 0 and not code:
        record(
            UserWriteViolation(
                REASON_TIME_LIMITED_GROUP_REQUIRES_CODE,
                f"Time-limited group {time_limit_group} requires a code.",
            ),
            unchanged=current is not None and current_time_limit > 0 and not current_code,
        )

    if errors:
        raise UserWriteRejected(errors)
    return warnings
