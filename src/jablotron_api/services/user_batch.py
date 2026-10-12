"""POST /v1/users/batch: several user records in one configuration event.

The panel takes a collection-7 command with several records in one map,
``{7: {slot: record, ...}}``, and answers it with one ack, one accept, one
leave and one revision step; F-Link sends three records in one 397-byte
write that way. This module plans such a write without touching the panel:
it checks the request's shape, decides each record from the preflight
table, judges every record against that table with the batch's other
records at their new values, leaves out updates that change nothing, and
checks the encoded size against the write transport. The runtimes
(``panel/runtime.py``, ``panel/demo.py``) hold the lock, make the one write
and the one refresh, and judge each user against the read-back with
``judge_write``.

Deletes are not part of a batch: a map that mixes nil deletes with upserts
has not been seen on the wire.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import logging
from typing import Any, Iterable, Sequence

from import_cfg_tool import (
    IMPORT_COLLECTION_KEY,
    PADDING_MARKER,
    SECTOR_SIZE,
    describe_payload,
    pack_msgpack,
)
from jablotron_re_tools import HID_CONFIG_WRITE_MAX_PAYLOAD, UserRecord
from jablotron_user_tool import build_upsert_payload

from jablotron_api.domain.codes import CodeFormat
from jablotron_api.domain.models import (
    UserBatchCreate,
    UserBatchResult,
    UserCreateModel,
    UserModel,
    UserPatchModel,
)
from jablotron_api.domain.user_validation import (
    UserBatchRecordRejected,
    UserBatchRejected,
    UserSlotOccupied,
    UserTableEntry,
    UserWriteRejected,
    entry_from_record,
    validate_user_write,
)
from jablotron_api.services.user_manager import (
    UserManagerConfig,
    UserWritePreflight,
    build_user_args,
    resolve_write_transport,
    target_entry_from_summary,
    upsert_is_noop,
    verify_added_user,
    verify_edited_user,
)

LOGGER = logging.getLogger(__name__)

# The msgpack command must leave room for the C1 C1 C1 C1 trailer in the one
# 512-byte IMPORT.CFG sector.
SECTOR_PAYLOAD_MAX = SECTOR_SIZE - len(PADDING_MARKER)


def write_id(write: Any) -> int:
    """The slot a batch write targets."""

    return write.user.id if isinstance(write, UserBatchCreate) else write.id


def check_batch_shape(writes: Sequence[Any], *, max_records: int) -> None:
    """Refuse a batch that is empty, longer than ``max_records``, or names a
    slot twice. Raises ``UserBatchRejected``; runs before any panel traffic."""

    if not writes:
        raise UserBatchRejected("empty", "The batch holds no writes.")
    if len(writes) > max_records:
        raise UserBatchRejected(
            "too_many",
            f"The batch holds {len(writes)} writes; this server takes at most {max_records} "
            "(JABLOTRON_PANEL_BATCH_MAX_RECORDS).",
        )
    seen: set[int] = set()
    repeated: list[int] = []
    for write in writes:
        user_id = write_id(write)
        if user_id in seen and user_id not in repeated:
            repeated.append(user_id)
        seen.add(user_id)
    if repeated:
        raise UserBatchRejected(
            "duplicate_id",
            "The batch names user(s) " + ", ".join(str(item) for item in repeated) + " more than once.",
        )


@dataclass(frozen=True)
class BatchTarget:
    """One record of a batch as the user-table rules see it."""

    user_id: int
    current: UserTableEntry | None
    target: UserTableEntry


def validate_batch(
    existing: Iterable[UserTableEntry],
    targets: Sequence[BatchTarget],
    code_format: CodeFormat,
) -> None:
    """Judge every record with ``validate_user_write`` against the table as
    it will be after the batch: each other record of the batch is taken as
    already present with its new values, in place of its current row.

    The first record that breaks a rule, in request order, raises
    ``UserBatchRecordRejected`` with its slot; its ``conflicting_user_ids``
    may name other records of the batch.
    """

    table = {entry.user_id: entry for entry in existing if entry.user_id is not None}
    for item in targets:
        table[item.user_id] = item.target
    rows = list(table.values())
    for item in targets:
        try:
            warnings = validate_user_write(
                existing=rows,
                user_id=item.user_id,
                current=item.current,
                target=item.target,
                code_format=code_format,
            )
        except UserWriteRejected as exc:
            raise UserBatchRecordRejected(exc.violations, user_id=item.user_id) from None
        for message in warnings:
            LOGGER.warning("User %s batch preflight warning: %s", item.user_id, message)


@dataclass(frozen=True)
class PlannedWrite:
    """One write of a batch, decided. ``record`` is None for an update that
    would write the record the panel already holds (left out of the map)."""

    op: str
    user_id: int
    payload: UserCreateModel | UserPatchModel
    current: UserRecord | None
    record: Any = None

    @property
    def noop(self) -> bool:
        return self.record is None


@dataclass(frozen=True)
class BatchPlan:
    writes: tuple[PlannedWrite, ...]
    # {7: {slot: record, ...}} for the writes that change something, in
    # request order; empty when every write is a no-op.
    payload: Any

    @property
    def written_ids(self) -> list[int]:
        return [item.user_id for item in self.writes if not item.noop]


def check_payload_size(config: UserManagerConfig, payload: Any) -> int:
    """The encoded size of ``payload``, refused with ``payload_too_large``
    when the write transport cannot carry it in one configuration event.

    The HID write takes up to ``HID_CONFIG_WRITE_MAX_PAYLOAD`` bytes (a
    sanity bound, not a measured panel limit). IMPORT.CFG takes one 512-byte
    sector. Under "auto" the transport is only known from the login rights,
    which this check does not ask the panel for, so "auto" is held to the
    sector too.
    """

    size = len(pack_msgpack(payload))
    transport = resolve_write_transport(config)
    if transport == "hid":
        limit, carrier = HID_CONFIG_WRITE_MAX_PAYLOAD, "the HID configuration write"
    else:
        limit, carrier = SECTOR_PAYLOAD_MAX, "one 512-byte IMPORT.CFG sector"
    if size > limit:
        raise UserBatchRejected(
            "payload_too_large",
            f"The batch encodes to {size} bytes; with the {transport} write transport it must "
            f"fit {carrier}, at most {limit} bytes. Send fewer or shorter records.",
        )
    return size


def plan_batch(
    config: UserManagerConfig,
    writes: Sequence[Any],
    *,
    rows: Sequence[UserRecord],
    preflight: UserWritePreflight,
) -> BatchPlan:
    """Decide a batch against the preflight table ``rows``.

    In this order, each step for every write before the next: a create on a
    slot holding a named user without ``replace`` raises ``UserSlotOccupied``
    and an update of a slot without a named user raises ``RuntimeError("User
    N not found.")`` (the single routes' 409s); each record is built with the
    single routes' builder (an update carries the preflight row over, as a
    PATCH does); the records are judged jointly; the map is checked for size.
    Nothing here talks to the panel.
    """

    by_id = {row.user_id: row for row in rows}

    def named(user_id: int) -> bool:
        row = by_id.get(user_id)
        return row is not None and bool((row.name or "").strip())

    for write in writes:
        if isinstance(write, UserBatchCreate):
            if named(write.user.id) and not write.replace:
                raise UserSlotOccupied(write.user.id, batch=True)
        elif not named(write.id):
            raise RuntimeError(f"User {write.id} not found.")

    planned: list[PlannedWrite] = []
    targets: list[BatchTarget] = []
    for write in writes:
        user_id = write_id(write)
        if isinstance(write, UserBatchCreate):
            op, payload, current, current_entry = "create", write.user, None, None
        else:
            op, payload, current = "update", write.patch, by_id[user_id]
            current_entry = entry_from_record(current)
            if upsert_is_noop(config, user_id=user_id, payload=payload, current=current):
                planned.append(PlannedWrite(op, user_id, payload, current))
                continue
        args = build_user_args(
            config, command="edit" if current is not None else "add", user_id=user_id, payload=payload
        )
        try:
            command = build_upsert_payload(args, current=current)
        except SystemExit as exc:
            # A section or PG outside the panel's range; the single routes
            # answer it with the same text from inside the write.
            raise RuntimeError(f"Panel write failed: {exc}") from None
        record = command[IMPORT_COLLECTION_KEY][user_id]
        targets.append(
            BatchTarget(user_id, current_entry, target_entry_from_summary(describe_payload(command), user_id=user_id))
        )
        planned.append(PlannedWrite(op, user_id, payload, current, record))

    validate_batch(preflight.existing, targets, preflight.code_format)
    payload_map = OrderedDict(
        {IMPORT_COLLECTION_KEY: OrderedDict((item.user_id, item.record) for item in planned if not item.noop)}
    )
    if payload_map[IMPORT_COLLECTION_KEY]:
        check_payload_size(config, payload_map)
    return BatchPlan(tuple(planned), payload_map)


def judge_write(planned: PlannedWrite, user: UserModel | None) -> UserBatchResult:
    """One result, from the user as the panel holds it after the batch. A
    mismatch is ``verified: false`` with the single routes' message, not an
    error: the write landed and the cache is current."""

    if user is None:
        return UserBatchResult(
            id=planned.user_id,
            op=planned.op,
            verified=False,
            detail=f"User {planned.user_id} was not present after the batch write.",
        )
    if not planned.noop:
        try:
            if planned.op == "create":
                verify_added_user(user, planned.payload)
            else:
                verify_edited_user(user, planned.payload)
        except RuntimeError as exc:
            return UserBatchResult(id=planned.user_id, op=planned.op, verified=False, user=user, detail=str(exc))
    return UserBatchResult(id=planned.user_id, op=planned.op, verified=True, user=user)
