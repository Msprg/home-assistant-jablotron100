"""User CRUD service.

Wraps `jablotron_user_tool.build_upsert_sector`, `build_delete_sector`, and
`jablotron_re_tools.apply_import_sector` behind a typed service interface so
`panel/runtime.py` no longer has to construct an argparse-shaped Namespace
inline.

The post-write verification policy (`verify_added_user`, `verify_edited_user`)
preserves the 2026-04-27 fix: only fields the API caller explicitly supplied
are compared; omitted optional create fields are not treated as mismatches
when the panel writes its own concrete defaults.

`apply_upsert` runs the shared user-table rules
(`jablotron_api.domain.user_validation`) against the record that is about to
be written, before the sector reaches the panel. The caller supplies the
freshly read table as a `UserWritePreflight`; the rules are the same ones
`jablotron_user_tool` runs for the CLI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Mapping, Protocol

from jablotron_re_tools import (
    LoginRights,
    UserRecord,
    apply_config_payload_over_hid,
    apply_import_sector,
    probe_login_rights,
    sector_payload_bytes as _sector_payload_bytes,
)
from import_cfg_tool import pack_msgpack
from import_cfg_tool import encode_sector, write_output
import jablotron_user_tool
from jablotron_user_tool import build_delete_sector, build_upsert_payload, build_upsert_sector

from jablotron_api.domain.codes import CodeFormat
from jablotron_api.domain.models import (
    UserCreateModel,
    UserModel,
    UserPatchModel,
)
from jablotron_api.domain.user_validation import (
    UserTableEntry,
    entry_from_record,
    validate_user_write,
)

LOGGER = logging.getLogger(__name__)

WRITE_TRANSPORTS = ("auto", "hid", "storage")


@dataclass
class UserManagerConfig:
    import_path: Path
    flexi_cfg_device: str
    port: str
    auth_code: str = field(repr=False)
    write_auth_code: str = field(repr=False)
    reset: bool
    mount_tool: str
    stage_mode: str
    write_cleanup_mode: str
    read_cleanup_mode: str
    # How the user record reaches the panel. "storage" stages the msgpack
    # sector in IMPORT.CFG (needs the block device and a service- or
    # ARC-rights login); "hid" sends the same msgpack as a 0x1D HID packet
    # (what F-Link does for a master-rights login; no block device for the
    # write). "auto" does what F-Link does: reads the rights the panel
    # grants the write code from its login reply, then uses hid for master
    # rights and storage for service or ARC rights. In the server the reply
    # comes from the status session's own login; a separate probe login runs
    # only when the write code differs or the session reported nothing.
    write_transport: str = "auto"


class PanelConfigSession(Protocol):
    """What write_sector_to_panel needs from the status session
    (PersistentSnapshotSession)."""

    def login_rights_for_code(self, code: str) -> LoginRights | None: ...

    def write_configuration(self, payload: bytes, *, code: str | None = None) -> int | None: ...

    def close(self) -> None: ...


def session_code_matches(config: UserManagerConfig) -> bool:
    """True when user writes log in with the same code as the status session,
    so a write can run inside that session instead of a separate client."""

    return not config.write_auth_code or config.write_auth_code == config.auth_code


def resolve_write_transport(config: UserManagerConfig) -> str:
    """Normalise the configured transport; ``"auto"`` is resolved per write."""

    transport = (config.write_transport or "auto").lower()
    if transport not in WRITE_TRANSPORTS:
        raise RuntimeError(
            f"Unsupported user write transport {config.write_transport!r}; expected one of {', '.join(WRITE_TRANSPORTS)}."
        )
    return transport


def select_write_transport(config: UserManagerConfig, *, session_rights: LoginRights | None = None) -> str:
    """Pick hid or storage for this write when configured "auto".

    ``session_rights`` are the rights the status session's own login reply
    reported for the write code; they decide without a second login, but
    only when the write code is the session code. Otherwise the panel is
    probed with a separate login, as before.
    """

    transport = resolve_write_transport(config)
    if transport != "auto":
        return transport
    if session_rights is not None and session_code_matches(config):
        chosen = "hid" if session_rights.is_master else "storage"
        LOGGER.info(
            "Status session is logged in with %s rights (position %d); using the %s transport.",
            session_rights.rights,
            session_rights.position,
            chosen,
        )
        return chosen
    rights = probe_login_rights(
        port=config.port,
        code=config.write_auth_code or config.auth_code,
        reset=config.reset,
        verbose=False,
    )
    if rights is None:
        LOGGER.warning("The panel did not report login rights; using the storage transport for this write.")
        return "storage"
    chosen = "hid" if rights.is_master else "storage"
    LOGGER.info(
        "Write code logged in with %s rights (position %d); using the %s transport.",
        rights.rights,
        rights.position,
        chosen,
    )
    return chosen


def sector_payload_bytes(sector_path: Path) -> bytes:
    """The msgpack command inside an encoded IMPORT.CFG sector.

    The sector builders already produce exactly the bytes F-Link sends over
    HID (XOR-decoded, without the `C1 C1 C1 C1` trailer and the fill), so the
    HID transport reuses them instead of a second encoder.
    """

    return _sector_payload_bytes(sector_path.read_bytes())


def _choose_transport(
    config: UserManagerConfig, session: PanelConfigSession | None, code: str
) -> tuple[str, bool]:
    """The transport for this write ("hid" or "storage") and whether it may
    run inside ``session``. Under "auto" the session's own login reply names
    the rights; the separate probe login only runs when the session cannot
    answer for this code, and the session is closed first, since two
    sessions on the device split the replies."""

    in_session_allowed = session is not None and session_code_matches(config)
    transport = resolve_write_transport(config)
    if transport == "auto":
        rights = session.login_rights_for_code(code) if in_session_allowed else None
        if rights is None and session is not None:
            session.close()
        transport = select_write_transport(config, session_rights=rights)
    return transport, in_session_allowed


def write_sector_to_panel(
    config: UserManagerConfig,
    *,
    sector_path: Path,
    verify_prefix: str,
    session: PanelConfigSession | None = None,
) -> None:
    """Write one user-table sector to the panel.

    With a status ``session`` and a write code equal to the session code, the
    HID transport runs inside that session (device-state streaming keeps
    publishing). With the "auto" transport the rights come from the session's
    own login reply for the write code, so no second login runs; only when
    the session cannot report them (or the write code differs) is the
    session closed and the panel probed. Every separate-client path closes
    the session first: the
    probe and the standalone write sessions need the bus to themselves, and
    the runtime's next poll reopens the session. No verification export runs
    in the server path; the runtime's post-write catalog refresh is the
    read-back. ``verify_prefix`` is kept as a log label.
    """

    code = config.write_auth_code or config.auth_code
    transport, in_session_allowed = _choose_transport(config, session, code)
    if transport == "hid" and in_session_allowed:
        LOGGER.info("User write %s goes over HID inside the status session.", verify_prefix)
        session.write_configuration(sector_payload_bytes(sector_path), code=code)
        return
    if session is not None:
        session.close()
    if transport == "hid":
        apply_config_payload_over_hid(
            payload=sector_payload_bytes(sector_path),
            device=config.flexi_cfg_device,
            port=config.port,
            code=code,
            reset=config.reset,
            write_cleanup_mode=config.write_cleanup_mode,
            verbose=False,
            verify_output=None,
        )
        return
    apply_import_sector(
        sector_path=sector_path,
        import_path=config.import_path,
        device=config.flexi_cfg_device,
        port=config.port,
        code=code,
        reset=config.reset,
        mount_tool=config.mount_tool,
        stage_mode=config.stage_mode,
        write_cleanup_mode=config.write_cleanup_mode,
        verbose=False,
        verify_output=None,
    )


def write_payload_to_panel(
    config: UserManagerConfig,
    *,
    payload: Mapping[Any, Any],
    verify_prefix: str,
    session: PanelConfigSession | None = None,
) -> None:
    """Write one msgpack configuration command, which may carry several user
    records, to the panel in one configuration event.

    The transport choice is ``write_sector_to_panel``'s. Over HID the msgpack
    bytes go out as they are, so a command larger than one IMPORT.CFG sector
    is possible there (up to the HID write's own bound); over storage the
    command is encoded into one 512-byte sector, and ``encode_sector``
    refuses a larger one. The batch planner checks the size against the
    configured transport before any panel traffic.
    """

    code = config.write_auth_code or config.auth_code
    data = pack_msgpack(payload)
    transport, in_session_allowed = _choose_transport(config, session, code)
    if transport == "hid" and in_session_allowed:
        LOGGER.info("User write %s goes over HID inside the status session.", verify_prefix)
        session.write_configuration(data, code=code)
        return
    if session is not None:
        session.close()
    if transport == "hid":
        apply_config_payload_over_hid(
            payload=data,
            device=config.flexi_cfg_device,
            port=config.port,
            code=code,
            reset=config.reset,
            write_cleanup_mode=config.write_cleanup_mode,
            verbose=False,
            verify_output=None,
        )
        return
    sector_path = jablotron_user_tool.default_sector_output(verify_prefix)
    write_output(sector_path, encode_sector(payload))
    try:
        apply_import_sector(
            sector_path=sector_path,
            import_path=config.import_path,
            device=config.flexi_cfg_device,
            port=config.port,
            code=code,
            reset=config.reset,
            mount_tool=config.mount_tool,
            stage_mode=config.stage_mode,
            write_cleanup_mode=config.write_cleanup_mode,
            verbose=False,
            verify_output=None,
        )
    finally:
        if sector_path.exists():
            sector_path.unlink()


@dataclass(frozen=True)
class UserWritePreflight:
    """The panel state a user write is validated against.

    Built by the runtime from the panel's user table as read under the
    panel lock: a fresh pull, or the cached export while its pull started
    within ``write_preflight_max_age_seconds`` and no write has dirtied it
    (the runtime's guard enforces this). Any other cached view would decide
    against a table the panel may no longer hold.
    """

    existing: tuple[UserTableEntry, ...] = ()
    current: UserTableEntry | None = None
    # CodeFormat is frozen, so a plain default is safe here.
    code_format: CodeFormat = CodeFormat(None, None, "unknown")

    @classmethod
    def from_records(
        cls,
        records,
        *,
        user_id: int,
        code_format: CodeFormat,
        include_current: bool,
    ) -> "UserWritePreflight":
        entries = tuple(entry_from_record(record) for record in records)
        current = None
        if include_current:
            current = next(
                (entry for entry in entries if entry.user_id == user_id), None
            )
        return cls(existing=entries, current=current, code_format=code_format)


def build_user_args(
    config: UserManagerConfig,
    *,
    command: str,
    user_id: int,
    payload: UserCreateModel | UserPatchModel | None = None,
) -> SimpleNamespace:
    fields: dict = {}
    if payload is not None:
        # An explicit JSON null means "not sent", like an omitted field.
        fields = {key: value for key, value in payload.model_dump(exclude_unset=True).items() if value is not None}
    # Sent lists replace the masks; an empty list clears them. Unsent ones
    # leave the masks the sector builder carries over from the current record.
    sections = fields.get("sections")
    pgs = fields.get("pgs")
    return SimpleNamespace(
        command=command,
        user_id=user_id,
        name=fields.get("name"),
        phone=fields.get("phone"),
        pin=fields.get("code"),
        card1=fields.get("card1"),
        card2=None,
        comment=fields.get("comment"),
        flags_raw=fields.get("flags_raw"),
        field0_raw=None,
        access_raw=fields.get("access_raw"),
        permissions_raw=None,
        sections_mask=0 if sections == [] else None,
        sections=",".join(str(item) for item in sections) if sections else None,
        pg_masks="0,0,0,0" if pgs == [] else None,
        pgs=",".join(str(item) for item in pgs) if pgs else None,
        pg_num_if_ring_raw=None,
        field8_raw=None,
        time_limited_group_raw=fields.get("time_limited_group_raw"),
        field9_raw=None,
        parent_user_no_raw=None,
        field11_raw=None,
        template_file=None,
        template_pcap=None,
        template_frame=None,
        sector_output=None,
        keep_sector=False,
        import_path=str(config.import_path),
        device=config.flexi_cfg_device,
        port=config.port,
        auth_code=config.auth_code,
        no_reset=not config.reset,
        mount_tool=config.mount_tool,
        stage_mode=config.stage_mode,
        write_cleanup_mode=config.write_cleanup_mode,
        verify_output=None,
        no_apply=False,
        verbose=False,
        export_cfg=None,
        output=None,
        no_trigger=False,
        read_cleanup_mode=config.read_cleanup_mode,
        show_access_names=False,
        no_preflight_validation=False,
        format="json",
    )


def user_first_card(user: UserModel) -> str:
    return user.cards[0] if user.cards else ""


def same_ids(decoded: list[int], requested: list[int]) -> bool:
    """Compare sections or PGs as the panel stores them: a bitmask has no
    order and no duplicates, and the export decodes it in ascending order."""

    return set(decoded) == set(requested)


def verify_added_user(user: UserModel, payload: UserCreateModel) -> None:
    requested_fields = set(payload.model_fields_set) | {"name"}
    checks = {
        "name": user.name == payload.name,
        "phone": user.phone == payload.phone,
        "code": user.code == payload.code,
        "card1": user_first_card(user) == payload.card1,
        "comment": user.comment == payload.comment,
        "flags_raw": user.flags_raw == payload.flags_raw,
        "access_raw": user.access_raw == payload.access_raw,
        "sections": same_ids(user.section_ids, payload.sections),
        "pgs": same_ids(user.pg_ids, payload.pgs),
        "time_limited_group_raw": user.time_limited_group_raw == payload.time_limited_group_raw,
    }
    mismatches = [field for field, ok in checks.items() if field in requested_fields and not ok]
    if mismatches:
        raise RuntimeError(
            f"User {payload.id} post-add verification failed for: {', '.join(mismatches)}."
        )


def verify_edited_user(user: UserModel, payload: UserPatchModel) -> None:
    # An explicit null was not written (build_user_args), so it is not checked.
    expected = {key: value for key, value in payload.model_dump(exclude_unset=True).items() if value is not None}
    checks: dict[str, bool] = {}
    for field, value in expected.items():
        if field == "sections":
            checks[field] = same_ids(user.section_ids, value)
        elif field == "pgs":
            checks[field] = same_ids(user.pg_ids, value)
        elif field == "card1":
            checks[field] = user_first_card(user) == value
        else:
            checks[field] = getattr(user, field) == value
    mismatches = [field for field, ok in checks.items() if not ok]
    if mismatches:
        raise RuntimeError(
            f"User {user.id} post-edit verification failed for: {', '.join(mismatches)}."
        )


def target_entry_from_summary(summary: dict, *, user_id: int) -> UserTableEntry:
    """Adapt a `build_upsert_sector` payload summary into a rule input.

    Mirrors `jablotron_user_tool._preflight_target`: the summary describes
    the encoded sector, i.e. exactly the record the panel will store.
    """

    return UserTableEntry(
        user_id=user_id,
        code=str(summary.get("code") or ""),
        cards=tuple(str(card) for card in summary.get("cards") or ()),
        time_limited_group_raw=summary.get("time_limited_group_raw"),
        name=str(summary.get("name") or ""),
        comment=str(summary.get("comment") or ""),
    )


def apply_upsert(
    config: UserManagerConfig,
    *,
    user_id: int,
    payload: UserCreateModel | UserPatchModel,
    current: UserRecord | None,
    preflight: UserWritePreflight,
    verify_prefix: str,
    session: PanelConfigSession | None = None,
) -> None:
    """Build the upsert sector, validate it, then write it to the panel.

    Raises ``UserWriteRejected`` (a ``ValueError``) before the panel is
    touched if the resulting record would break a user-table rule.
    """

    args = build_user_args(
        config,
        command="edit" if current is not None else "add",
        user_id=user_id,
        payload=payload,
    )
    sector_path, summary, cleanup_sector = build_upsert_sector(args, current=current)
    try:
        # Validate the record that will actually be written, not the request:
        # unsupplied fields are carried over from `current` by the sector
        # builder, and those carried-over values are subject to the rules too.
        warnings = validate_user_write(
            existing=preflight.existing,
            user_id=user_id,
            current=preflight.current,
            target=target_entry_from_summary(summary, user_id=user_id),
            code_format=preflight.code_format,
        )
        if preflight.code_format.source != "panel" and preflight.code_format.code_length is not None:
            LOGGER.warning(
                "User %s write validated against a %s code length of %s, not the panel's main_config.",
                user_id,
                preflight.code_format.source,
                preflight.code_format.code_length,
            )
        for message in warnings:
            LOGGER.warning("User %s write preflight warning: %s", user_id, message)

        write_sector_to_panel(config, sector_path=sector_path, verify_prefix=verify_prefix, session=session)
    finally:
        if cleanup_sector and sector_path.exists():
            sector_path.unlink()


def upsert_is_noop(
    config: UserManagerConfig,
    *,
    user_id: int,
    payload: UserPatchModel,
    current: UserRecord,
) -> bool:
    """True when the record an edit would write is, byte for byte, the
    current record re-encoded with nothing sent: the write would change
    nothing on the panel, so no configuration event is needed."""

    def encoded(patch: UserPatchModel | None) -> bytes:
        args = build_user_args(config, command="edit", user_id=user_id, payload=patch)
        return pack_msgpack(build_upsert_payload(args, current=current))

    try:
        return encoded(payload) == encoded(None)
    except SystemExit:
        # The builder refuses a section or PG outside the panel's range with
        # SystemExit; the write path reports that as it always has.
        return False


def apply_delete(
    config: UserManagerConfig,
    *,
    user_id: int,
    verify_prefix: str,
    session: PanelConfigSession | None = None,
) -> None:
    args = build_user_args(config, command="delete", user_id=user_id)
    sector_path, _, cleanup_sector = build_delete_sector(args)
    try:
        write_sector_to_panel(config, sector_path=sector_path, verify_prefix=verify_prefix, session=session)
    finally:
        if cleanup_sector and sector_path.exists():
            sector_path.unlink()
