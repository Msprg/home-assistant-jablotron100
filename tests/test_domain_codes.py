import pytest

from jablotron_api.domain.codes import (
    CodeFormat,
    resolve_code_format,
    validate_user_code,
)


def test_resolve_prefers_catalog_values():
    fmt = resolve_code_format(
        catalog_code_length=6, catalog_code_prefix=True, server_auth_code="0*1234"
    )
    assert fmt == CodeFormat(6, True, source="panel")


def test_resolve_infers_from_server_code_unprefixed():
    fmt = resolve_code_format(
        catalog_code_length=None, catalog_code_prefix=None, server_auth_code="9146"
    )
    assert fmt == CodeFormat(4, False, source="inferred")


def test_resolve_infers_from_server_code_prefixed():
    fmt = resolve_code_format(
        catalog_code_length=None, catalog_code_prefix=None, server_auth_code="100*123456"
    )
    assert fmt == CodeFormat(6, True, source="inferred")


def test_resolve_unknown_when_nothing_available():
    fmt = resolve_code_format(
        catalog_code_length=None, catalog_code_prefix=None, server_auth_code=None
    )
    assert fmt == CodeFormat(None, None, source="unknown")


def test_validate_none_is_allowed():
    validate_user_code(None, CodeFormat(4, False, "panel"))


def test_validate_empty_string_rejected():
    with pytest.raises(ValueError, match="empty"):
        validate_user_code("", CodeFormat(4, False, "panel"))


def test_validate_whitespace_rejected():
    with pytest.raises(ValueError, match="empty"):
        validate_user_code("   ", CodeFormat(4, False, "panel"))


def test_validate_unprefixed_correct_length():
    validate_user_code("1234", CodeFormat(4, False, "panel"))


def test_validate_unprefixed_wrong_length():
    with pytest.raises(ValueError, match="exactly 4"):
        validate_user_code("12345", CodeFormat(4, False, "panel"))


def test_validate_unprefixed_non_digit():
    with pytest.raises(ValueError, match="all digits"):
        validate_user_code("abcd", CodeFormat(4, False, "panel"))


def test_validate_unprefixed_rejects_star_when_prefix_off():
    with pytest.raises(ValueError, match="not configured for prefixed"):
        validate_user_code("0*1234", CodeFormat(4, False, "panel"))


def test_validate_prefixed_correct():
    validate_user_code("100*123456", CodeFormat(6, True, "panel"))
    validate_user_code("0*1234", CodeFormat(4, True, "panel"))


def test_validate_prefixed_missing_star():
    with pytest.raises(ValueError, match="requires prefixed"):
        validate_user_code("1234", CodeFormat(4, True, "panel"))


def test_validate_prefixed_bad_form():
    with pytest.raises(ValueError, match="digits"):
        validate_user_code("x*1234", CodeFormat(4, True, "panel"))
    with pytest.raises(ValueError, match="digits"):
        validate_user_code("1*ab12", CodeFormat(4, True, "panel"))


def test_validate_prefixed_double_star():
    with pytest.raises(ValueError, match="digits"):
        validate_user_code("1*2*3", CodeFormat(4, True, "panel"))


def test_validate_prefixed_wrong_length():
    with pytest.raises(ValueError, match="exactly 6"):
        validate_user_code("100*1234", CodeFormat(6, True, "panel"))


def test_validate_unknown_format_accepts_digits():
    # Format fully unknown: only basic digit-shape check applies.
    validate_user_code("1234", CodeFormat(None, None, "unknown"))


def test_validate_unknown_format_rejects_non_digits():
    with pytest.raises(ValueError):
        validate_user_code("abcd", CodeFormat(None, None, "unknown"))
