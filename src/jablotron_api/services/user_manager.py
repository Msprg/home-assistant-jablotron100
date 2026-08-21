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

from dataclasses import dataclass
import logging
from pathlib import Path
from types import SimpleNamespace

from jablotron_re_tools import (
    UserRecord,
    apply_import_sector,
    default_export_output,
)
from jablotron_user_tool import build_delete_sector, build_upsert_sector

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


@dataclass
class UserManagerConfig:
    import_path: Path
    flexi_cfg_device: str
    port: str
    auth_code: str
    reset: bool
    mount_tool: str
    stage_mode: str
    write_cleanup_mode: str
    read_cleanup_mode: str


@dataclass(frozen=True)
class UserWritePreflight:
    """The panel state a user write is validated against.

    Built by the runtime from a *fresh* read of the panel's user table,
    taken under the panel lock immediately before the write. Passing a
    cached view here would decide against a table that no longer exists.
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
        fields = payload.model_dump(exclude_unset=True)
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
        sections_mask=None,
        sections=",".join(str(item) for item in fields.get("sections", [])) or None,
        pg_masks=None,
        pgs=",".join(str(item) for item in fields.get("pgs", [])) or None,
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
        "sections": user.section_ids == payload.sections,
        "pgs": user.pg_ids == payload.pgs,
        "time_limited_group_raw": user.time_limited_group_raw == payload.time_limited_group_raw,
    }
    mismatches = [field for field, ok in checks.items() if field in requested_fields and not ok]
    if mismatches:
        raise RuntimeError(
            f"User {payload.id} post-add verification failed for: {', '.join(mismatches)}."
        )


def verify_edited_user(user: UserModel, payload: UserPatchModel) -> None:
    expected = payload.model_dump(exclude_unset=True)
    checks: dict[str, bool] = {}
    for field, value in expected.items():
        if field == "sections":
            checks[field] = user.section_ids == value
        elif field == "pgs":
            checks[field] = user.pg_ids == value
        elif field == "card1":
            checks[field] = user_first_card(user) == value
        else:
            checks[field] = getattr(user, field) == value
    mismatches = [field for field, ok in checks.items() if not ok]
    if mismatches:
        raise RuntimeError(
            f"User {user.id} post-edit verification failed for: {', '.join(mismatches)}."
        )


def user_to_record(user: UserModel) -> UserRecord:
    """Adapt the API `UserModel` back into the RE-tools `UserRecord` shape.

    The RE tools require a current `UserRecord` when building an upsert sector
    for an edit. Only fields used by `build_upsert_sector` need to be populated;
    the rest are left at neutral defaults.
    """

    return UserRecord(
        offset=0,
        user_id=user.id,
        raw_id_bytes="",
        flags_raw=user.flags_raw,
        flags=[],
        access_raw=user.access_raw,
        rights=user.rights,
        enabled=user.enabled,
        section_access_mask_raw=None,
        section_ids=user.section_ids,
        pg_access_masks_raw=[],
        pg_ids=user.pg_ids,
        name=user.name,
        phone=user.phone,
        code=user.code,
        cards=user.cards,
        comment=user.comment,
        pg_num_if_ring_raw=None,
        time_limited_group_raw=user.time_limited_group_raw,
        parent_user_no_raw=None,
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
    )


def apply_upsert(
    config: UserManagerConfig,
    *,
    user_id: int,
    payload: UserCreateModel | UserPatchModel,
    current: UserRecord | None,
    preflight: UserWritePreflight,
    verify_prefix: str,
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

        verify_output = default_export_output(verify_prefix)
        apply_import_sector(
            sector_path=sector_path,
            import_path=config.import_path,
            device=config.flexi_cfg_device,
            port=config.port,
            code=config.auth_code,
            reset=config.reset,
            mount_tool=config.mount_tool,
            stage_mode=config.stage_mode,
            write_cleanup_mode=config.write_cleanup_mode,
            verbose=False,
            verify_output=verify_output,
        )
    finally:
        if cleanup_sector and sector_path.exists():
            sector_path.unlink()


def apply_delete(
    config: UserManagerConfig,
    *,
    user_id: int,
    verify_prefix: str,
) -> None:
    args = build_user_args(config, command="delete", user_id=user_id)
    sector_path, _, cleanup_sector = build_delete_sector(args)
    try:
        verify_output = default_export_output(verify_prefix)
        apply_import_sector(
            sector_path=sector_path,
            import_path=config.import_path,
            device=config.flexi_cfg_device,
            port=config.port,
            code=config.auth_code,
            reset=config.reset,
            mount_tool=config.mount_tool,
            stage_mode=config.stage_mode,
            write_cleanup_mode=config.write_cleanup_mode,
            verbose=False,
            verify_output=verify_output,
        )
    finally:
        if cleanup_sector and sector_path.exists():
            sector_path.unlink()
