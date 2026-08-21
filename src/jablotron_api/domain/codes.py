"""User-code format resolution and validation.

The Jablotron panel exposes two installation-wide settings that govern the
shape of every user code submitted to it:

- ``code_length`` — required PIN length (4, 6, or 8 digits on JA-10x panels).
- ``code_prefix`` — whether codes must be supplied as ``<user_id>*<code>``
  (e.g. ``0*1234`` for the service user) or as the bare ``<code>``.

``validate_user_code`` applies both settings to a code submitted for
authentication. ``validate_user_table_code`` applies the digit/length half
of it to a PIN being written into a user slot, where the prefix is typed at
the keypad rather than stored.

Both values come from the panel's exported ``main_config`` and arrive in
:class:`InitialSetupModel`. Until the catalog has been pulled (e.g. during
the very first poll cycle, or in tests that skip the export), we fall back
to inferring the format from the server's own configured auth code: its
length and whether it contains ``*``.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CodeFormat:
    code_length: int | None
    code_prefix: bool | None
    source: str  # "panel" if from catalog, "inferred" if from server auth code, "unknown" otherwise


def resolve_code_format(
    *,
    catalog_code_length: int | None,
    catalog_code_prefix: bool | None,
    server_auth_code: str | None,
) -> CodeFormat:
    """Return the panel's code format, falling back to inference if needed."""

    if catalog_code_length is not None and catalog_code_prefix is not None:
        return CodeFormat(catalog_code_length, catalog_code_prefix, source="panel")

    inferred_length: int | None = None
    inferred_prefix: bool | None = None
    if server_auth_code:
        if "*" in server_auth_code:
            _, _, tail = server_auth_code.partition("*")
            inferred_length = len(tail) if tail.isdigit() else None
            inferred_prefix = True
        elif server_auth_code.isdigit():
            inferred_length = len(server_auth_code)
            inferred_prefix = False

    code_length = catalog_code_length if catalog_code_length is not None else inferred_length
    code_prefix = catalog_code_prefix if catalog_code_prefix is not None else inferred_prefix
    if code_length is None and code_prefix is None:
        return CodeFormat(None, None, source="unknown")
    return CodeFormat(code_length, code_prefix, source="inferred")


def validate_user_code(code: str | None, fmt: CodeFormat) -> None:
    """Reject obviously-bad codes before they reach the HID packet builder.

    Raises ``ValueError`` (mapped to HTTP 400 by the server) on bad input.

    ``code is None`` means the ``code=`` query parameter was not supplied at
    all — accepted here (the caller decides whether a code is required for
    the operation). ``code == ""`` (empty string from ``?code=``) is treated
    as malformed input and rejected: callers either omit the parameter or
    supply a valid code, never both at once.
    """

    if code is None:
        return
    if code == "" or code.strip() == "":
        raise ValueError("Code must not be empty; omit the parameter to use the server code.")
    stripped = code.strip()

    has_star = "*" in stripped
    if fmt.code_prefix is True and not has_star:
        raise ValueError("Panel requires prefixed codes in the form '<user_id>*<code>'.")
    if fmt.code_prefix is False and has_star:
        raise ValueError("Panel is not configured for prefixed codes; submit '<code>' only.")

    if has_star:
        user_part, _, code_part = stripped.partition("*")
        if "*" in code_part or not user_part or not user_part.isdigit() or not code_part.isdigit():
            raise ValueError("Prefixed code must be digits in the form '<user_id>*<code>'.")
        digits = code_part
    else:
        if not stripped.isdigit():
            raise ValueError("Code must be all digits.")
        digits = stripped

    if fmt.code_length is not None and len(digits) != fmt.code_length:
        raise ValueError(f"Panel code must be exactly {fmt.code_length} digits.")


def validate_user_table_code(code: str | None, fmt: CodeFormat) -> None:
    """Validate a PIN destined for a slot in the panel's user table.

    Distinct from :func:`validate_user_code`, which validates a code being
    *submitted for authentication*. A user record stores the bare PIN: when
    the panel is configured for prefixed codes the ``<user_id>*`` part is
    typed at the keypad, not stored in the slot, so the prefix rule must not
    be applied here.

    ``fmt.code_length`` is the panel's own installation-wide setting and the
    only authority on the required length. If it is unknown we refuse rather
    than guess — writing a wrong-length PIN into a user slot is not
    something to be optimistic about.

    Raises ``ValueError``. The message never quotes the code: it travels
    into HTTP responses and the server log.
    """

    digits = (code or "").strip()
    if not digits:
        raise ValueError("User code must not be empty.")
    if not digits.isdigit():
        raise ValueError("User code must be all digits.")
    if fmt.code_length is None:
        raise ValueError(
            "The panel's code length is unknown, so the submitted code's shape "
            "cannot be checked; refusing to write a user code rather than guessing it."
        )
    if len(digits) != fmt.code_length:
        raise ValueError(f"Panel code must be exactly {fmt.code_length} digits.")
