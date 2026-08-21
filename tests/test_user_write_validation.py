"""Unit tests for the panel's user-table write rules.

Everything here runs against synthetic user tables: the arithmetic and the
symmetry of the panic rule are fully testable offline, and that is where the
bugs are. Nothing in this file may touch a panel.
"""

from __future__ import annotations

import pytest

from jablotron_api.domain.codes import CodeFormat, validate_user_table_code
from jablotron_api.domain.user_validation import (
    REASON_CARD_REPEATED,
    REASON_CODE_LENGTH_UNKNOWN,
    REASON_DUPLICATE_CARD,
    REASON_DUPLICATE_CODE,
    REASON_INVALID_USER_CODE,
    REASON_PANIC_CODE_COLLISION,
    REASON_TIME_LIMITED_GROUP_REQUIRES_CODE,
    UserTableEntry,
    UserWriteRejected,
    entry_from_record,
    panic_code,
    validate_user_write,
)

PANEL_4 = CodeFormat(4, False, "panel")
PANEL_6 = CodeFormat(6, False, "panel")
PANEL_8 = CodeFormat(8, False, "panel")
UNKNOWN = CodeFormat(None, None, "unknown")


def entry(user_id: int, code: str = "", *, cards: tuple[str, ...] = (), time_limit: int | None = None):
    return UserTableEntry(user_id=user_id, code=code, cards=cards, time_limited_group_raw=time_limit)


def check(existing, *, user_id, code="", current=None, cards=(), time_limit=None, fmt=PANEL_4):
    return validate_user_write(
        existing=existing,
        user_id=user_id,
        current=current,
        target=entry(user_id, code, cards=cards, time_limit=time_limit),
        code_format=fmt,
    )


def reasons(excinfo) -> list[str]:
    return [violation.reason for violation in excinfo.value.violations]


# --------------------------------------------------------------- panic arithmetic


@pytest.mark.parametrize(
    "code, expected",
    [
        ("1483", "1484"),
        ("1489", "1480"),
        ("0000", "0001"),
        ("9999", "9990"),
        ("148300", "148301"),
        ("148309", "148300"),
        ("14830000", "14830001"),
        ("14830009", "14830000"),
    ],
)
def test_panic_code_increments_last_digit_mod_10_at_any_length(code, expected):
    assert panic_code(code) == expected


def test_panic_code_preserves_length():
    for code in ("1489", "148909", "14890909"):
        assert len(panic_code(code)) == len(code)


def test_panic_code_has_no_twin_for_empty_or_non_numeric():
    assert panic_code("") is None
    assert panic_code(None) is None
    assert panic_code("   ") is None
    assert panic_code("12a4") is None


def test_panic_code_never_equals_its_own_code():
    for last in range(10):
        code = f"148{last}"
        assert panic_code(code) != code


# ------------------------------------------------------------ panic rule, both ways


def test_panic_rule_rejects_new_code_that_is_an_existing_users_panic_code():
    # User 7 holds 1483, so 1484 fires user 7's silent alarm.
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1483")], user_id=4, code="1484")
    assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION
    assert excinfo.value.conflicting_user_ids == (7,)


def test_panic_rule_rejects_new_code_whose_panic_code_is_an_existing_users_code():
    # The mirrored case: user 7 holds 1484, and a new 1483 would make user 7's
    # own code the panic twin, so user 7 trips the alarm on every use.
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1484")], user_id=4, code="1483")
    assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION
    assert excinfo.value.conflicting_user_ids == (7,)


def test_panic_rule_is_order_independent():
    """Creation order must not decide whether a collision is found."""

    pair = ("1483", "1484")
    for first, second in (pair, tuple(reversed(pair))):
        with pytest.raises(UserWriteRejected) as excinfo:
            check([entry(1, first)], user_id=2, code=second)
        assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION


def test_panic_rule_wraps_around_nine_in_both_directions():
    with pytest.raises(UserWriteRejected):
        check([entry(1, "1489")], user_id=2, code="1480")
    with pytest.raises(UserWriteRejected):
        check([entry(1, "1480")], user_id=2, code="1489")


@pytest.mark.parametrize("fmt, prefix", [(PANEL_4, "148"), (PANEL_6, "14830"), (PANEL_8, "1483000")])
def test_panic_rule_applies_at_every_panel_code_length(fmt, prefix):
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(1, f"{prefix}3")], user_id=2, code=f"{prefix}4", fmt=fmt)
    assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION
    # And the mirrored direction at the same length.
    with pytest.raises(UserWriteRejected):
        check([entry(1, f"{prefix}4")], user_id=2, code=f"{prefix}3", fmt=fmt)


def test_panic_rule_ignores_codes_on_a_different_prefix():
    assert check([entry(1, "1583"), entry(2, "9484")], user_id=3, code="1484") == []


def test_panic_rule_ignores_codes_of_a_different_length():
    # A 6-digit table entry cannot be the panic twin of a 4-digit code.
    assert check([entry(1, "148300")], user_id=2, code="1484") == []


def test_panic_rule_reports_every_conflicting_user():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(5, "1483"), entry(9, "1485")], user_id=2, code="1484")
    assert excinfo.value.conflicting_user_ids == (5, 9)
    assert reasons(excinfo) == [REASON_PANIC_CODE_COLLISION, REASON_PANIC_CODE_COLLISION]


def test_panic_rule_skips_the_slot_being_written():
    # Rewriting user 4 from 1483 to 1484 is legal: the old code is replaced,
    # so there is nothing left for the new one to collide with.
    assert check([entry(4, "1483")], user_id=4, code="1484", current=entry(4, "1483")) == []


def test_panic_rule_skips_rows_without_a_user_id():
    assert check([UserTableEntry(user_id=None, code="1483")], user_id=2, code="1484") == []


def test_panic_rule_demotes_a_preexisting_collision_on_an_unchanged_code():
    # User 4 already collides with user 7 (someone bypassed validation, or the
    # panel was provisioned by hand). An edit that leaves the code alone must
    # warn rather than refuse, matching the duplicate-code behaviour.
    warnings = check(
        [entry(7, "1483"), entry(4, "1484")],
        user_id=4,
        code="1484",
        current=entry(4, "1484"),
    )
    assert len(warnings) == 1
    assert "silent panic" in warnings[0]


def test_panic_rule_still_refuses_when_the_edit_changes_the_code():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1483"), entry(4, "9999")], user_id=4, code="1484", current=entry(4, "9999"))
    assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION


def test_five_codes_per_prefix_is_the_documented_ceiling():
    """Non-adjacent last digits fit; adjacent ones do not. Expected, not a bug."""

    table: list[UserTableEntry] = []
    for index, last in enumerate((0, 2, 4, 6, 8), start=1):
        assert check(table, user_id=index, code=f"148{last}") == []
        table.append(entry(index, f"148{last}"))
    assert len(table) == 5

    for last in (1, 3, 5, 7, 9):
        with pytest.raises(UserWriteRejected) as excinfo:
            check(table, user_id=99, code=f"148{last}")
        assert excinfo.value.reason == REASON_PANIC_CODE_COLLISION


def test_full_table_is_pairwise_legal_under_the_symmetric_rule():
    codes = [f"148{last}" for last in (0, 2, 4, 6, 8)]
    for left in codes:
        for right in codes:
            if left == right:
                continue
            assert panic_code(left) != right
            assert panic_code(right) != left


# ------------------------------------------------------------------ code format


@pytest.mark.parametrize("fmt, code", [(PANEL_4, "1483"), (PANEL_6, "148300"), (PANEL_8, "14830000")])
def test_code_of_the_panels_length_is_accepted(fmt, code):
    assert check([], user_id=1, code=code, fmt=fmt) == []


@pytest.mark.parametrize(
    "fmt, code",
    [
        (PANEL_4, "148"),
        (PANEL_4, "14830"),
        (PANEL_6, "1483"),
        (PANEL_6, "14830000"),
        (PANEL_8, "148300"),
    ],
)
def test_code_of_the_wrong_length_is_refused(fmt, code):
    with pytest.raises(UserWriteRejected) as excinfo:
        check([], user_id=1, code=code, fmt=fmt)
    assert excinfo.value.reason == REASON_INVALID_USER_CODE
    assert f"exactly {fmt.code_length} digits" in excinfo.value.summary()


def test_non_digit_code_is_refused():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([], user_id=1, code="14a3")
    assert excinfo.value.reason == REASON_INVALID_USER_CODE


def test_prefixed_code_is_refused_for_a_user_slot():
    # A user record stores the bare PIN; the '<user_id>*' part is typed at the
    # keypad. It must never be written into the slot, prefixed panel or not.
    with pytest.raises(UserWriteRejected):
        check([], user_id=1, code="1*1483", fmt=CodeFormat(4, True, "panel"))


def test_unknown_code_length_refuses_rather_than_guessing():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([], user_id=1, code="1483", fmt=UNKNOWN)
    assert excinfo.value.reason == REASON_CODE_LENGTH_UNKNOWN
    assert "unknown" in excinfo.value.summary()


def test_unknown_code_length_still_enforces_the_panic_rule():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1483")], user_id=2, code="1484", fmt=UNKNOWN)
    assert set(reasons(excinfo)) == {REASON_CODE_LENGTH_UNKNOWN, REASON_PANIC_CODE_COLLISION}


def test_unknown_code_length_does_not_block_an_edit_that_keeps_the_code():
    warnings = check([], user_id=1, code="1483", current=entry(1, "1483"), fmt=UNKNOWN)
    assert len(warnings) == 1


def test_no_code_means_no_code_checks():
    assert check([entry(7, "1483")], user_id=2, code="", fmt=UNKNOWN) == []


def test_inferred_code_length_is_still_enforced():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([], user_id=1, code="148300", fmt=CodeFormat(4, False, "inferred"))
    assert excinfo.value.reason == REASON_INVALID_USER_CODE


# ------------------------------------------------------------------- duplicates


def test_duplicate_code_is_refused_and_names_the_holder():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1483")], user_id=2, code="1483")
    assert excinfo.value.reason == REASON_DUPLICATE_CODE
    assert excinfo.value.conflicting_user_ids == (7,)


def test_duplicate_code_is_a_warning_when_the_user_keeps_its_own_code():
    warnings = check(
        [entry(7, "1483"), entry(2, "1483")], user_id=2, code="1483", current=entry(2, "1483")
    )
    assert len(warnings) == 1
    assert "already assigned to user(s) 7" in warnings[0]


def test_duplicate_card_is_refused_and_names_the_slot():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, cards=("00123456",))], user_id=2, code="1483", cards=("00123456",))
    assert excinfo.value.reason == REASON_DUPLICATE_CARD
    assert "Card 1" in excinfo.value.summary()


def test_duplicate_card_keeps_its_slot_number_when_the_first_slot_is_empty():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, cards=("00123456",))], user_id=2, code="1483", cards=("", "00123456"))
    assert "Card 2" in excinfo.value.summary()


def test_duplicate_card_is_a_warning_when_the_user_keeps_its_own_card():
    warnings = check(
        [entry(7, cards=("00123456",)), entry(2, cards=("00123456",))],
        user_id=2,
        code="1483",
        cards=("00123456",),
        current=entry(2, cards=("00123456",)),
    )
    assert len(warnings) == 1


def test_the_same_card_in_both_slots_is_refused():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([], user_id=2, code="1483", cards=("00123456", "00123456"))
    assert excinfo.value.reason == REASON_CARD_REPEATED


# ------------------------------------------------------------- time-limited group


def test_time_limited_group_requires_a_code():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([], user_id=2, code="", time_limit=3)
    assert excinfo.value.reason == REASON_TIME_LIMITED_GROUP_REQUIRES_CODE


def test_time_limited_group_without_a_code_is_a_warning_if_it_was_already_so():
    warnings = check([], user_id=2, code="", time_limit=3, current=entry(2, "", time_limit=3))
    assert len(warnings) == 1


# ----------------------------------------------------------------- refusal shape


def test_refusal_is_a_value_error_not_a_system_exit():
    with pytest.raises(ValueError):
        check([entry(7, "1483")], user_id=2, code="1483")


def test_refusal_payload_is_machine_readable():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1483")], user_id=2, code="1484")
    payload = excinfo.value.to_payload()
    assert payload["error"] == "user_write_rejected"
    assert payload["reason"] == REASON_PANIC_CODE_COLLISION
    assert payload["conflicting_user_ids"] == [7]
    assert payload["violations"][0]["user_ids"] == [7]
    assert payload["message"]


def test_refusal_reports_every_rule_that_fired():
    # A 5-digit code on a 4-digit panel that also collides with the panic twin
    # of an equally wrong-length code already in the table, on a card someone
    # else holds: every rule reports, not just the first.
    with pytest.raises(UserWriteRejected) as excinfo:
        check(
            [entry(7, "14830"), entry(9, cards=("00123456",))],
            user_id=2,
            code="14831",
            cards=("00123456",),
        )
    assert set(reasons(excinfo)) == {
        REASON_INVALID_USER_CODE,
        REASON_PANIC_CODE_COLLISION,
        REASON_DUPLICATE_CARD,
    }


def test_refusal_never_quotes_a_code_or_card_value():
    """Messages reach clients without the sensitive read scope, and the log."""

    with pytest.raises(UserWriteRejected) as excinfo:
        check(
            [entry(7, "1483"), entry(9, cards=("00123456",))],
            user_id=2,
            code="1484",
            cards=("00123456",),
        )
    rendered = excinfo.value.summary() + excinfo.value.cli_message()
    assert "1483" not in rendered
    assert "1484" not in rendered
    assert "00123456" not in rendered


def test_cli_message_lists_each_rule():
    with pytest.raises(UserWriteRejected) as excinfo:
        check([entry(7, "1483")], user_id=2, code="1484")
    message = excinfo.value.cli_message()
    assert message.startswith("Preflight validation failed:")
    assert f"[{REASON_PANIC_CODE_COLLISION}]" in message


# ------------------------------------------------------------------- adaptation


class _Record:
    """Stand-in for the RE tools' UserRecord."""

    def __init__(self, user_id, code, cards, time_limited_group_raw=None):
        self.user_id = user_id
        self.code = code
        self.cards = cards
        self.time_limited_group_raw = time_limited_group_raw


class _Model:
    """Stand-in for the API UserModel, which names its ID differently."""

    def __init__(self, id, code, cards):  # noqa: A002 - mirrors UserModel
        self.id = id
        self.code = code
        self.cards = cards
        self.time_limited_group_raw = None


def test_entry_from_record_accepts_the_re_tools_shape():
    adapted = entry_from_record(_Record(7, "1483", ["00123456", ""], 2))
    assert adapted == UserTableEntry(7, "1483", ("00123456",), 2)


def test_entry_from_record_accepts_the_api_model_shape():
    adapted = entry_from_record(_Model(7, "1483", ["00123456"]))
    assert adapted == UserTableEntry(7, "1483", ("00123456",), None)


# ------------------------------------------------------ user-table code format


def test_validate_user_table_code_rejects_the_prefixed_form():
    with pytest.raises(ValueError, match="digits"):
        validate_user_table_code("1*1483", CodeFormat(4, True, "panel"))


def test_validate_user_table_code_refuses_unknown_length():
    with pytest.raises(ValueError, match="unknown"):
        validate_user_table_code("1483", UNKNOWN)


def test_validate_user_table_code_accepts_each_panel_length():
    validate_user_table_code("1483", PANEL_4)
    validate_user_table_code("148300", PANEL_6)
    validate_user_table_code("14830000", PANEL_8)


def test_validate_user_table_code_rejects_empty():
    with pytest.raises(ValueError, match="empty"):
        validate_user_table_code("", PANEL_4)
