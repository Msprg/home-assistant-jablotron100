"""Recent panel event log reader.

Wraps `jablotron_event_tool.pull_live_archive` and friends behind a typed
service interface so `panel/runtime.py` does not have to assemble the
CLI-shaped argparse `Namespace` directly.

The 2026-04-26 behavior of treating non-configuration cleanup `0x80` as a
warning rather than an error is preserved by the underlying helpers.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import SimpleNamespace

from jablotron_event_tool import (
    build_decoded_records,
    parse_kind_filter,
    pull_live_archive,
    resolve_decoder_catalog,
    select_display_records,
    split_crlf_records,
)

from jablotron_api.domain.models import EventRecordModel


@dataclass
class EventReaderConfig:
    flexi_log_device: str
    port: str
    auth_code: str
    reset: bool
    mount_tool: str


def _build_archive_args(config: EventReaderConfig) -> SimpleNamespace:
    return SimpleNamespace(
        output=None,
        metadata_output=None,
        records_output=None,
        output_prefix="api_server_events",
        records_format="jsonl",
        save_records=False,
        log_device=config.flexi_log_device,
        mountpoint="/mnt/flexi_log",
        source_fdb=None,
        source_export_cfg=None,
        port=config.port,
        auth_code=config.auth_code,
        no_reset=not config.reset,
        verbose=False,
        mount_tool=config.mount_tool,
        end_mode="logical",
        copy_files_dir=None,
        transport="archive",
        window_bytes=65536,
        decode_records=False,
        record_preview_count=5,
        index_preview_count=8,
        crlf_preview_count=8,
        preview_limit=10,
        cleanup_mode="login-exit",
    )


def read_recent_events(
    config: EventReaderConfig,
    *,
    limit: int = 20,
    include_raw: bool = False,
    kinds: str | None = None,
    exclude_kinds: str | None = None,
) -> list[EventRecordModel]:
    args = _build_archive_args(config)
    snapshot = pull_live_archive(args)
    archive = snapshot.output.read_bytes()
    records = split_crlf_records(archive, base_offset=snapshot.window_start)
    catalog = resolve_decoder_catalog(fdb_path=None, export_cfg_path=None)
    decoded = build_decoded_records(records, archive, catalog=catalog)
    display_records = select_display_records(
        decoded,
        limit=limit,
        include_raw=include_raw,
        include_kinds=parse_kind_filter(kinds) or None,
        exclude_kinds=parse_kind_filter(exclude_kinds) or None,
    )
    return [
        EventRecordModel(
            timestamp=record.timestamp_prefix,
            kind=record.kind,
            text=record.text,
            event_code=record.event_code,
            source=record.source_name,
            channel=record.channel,
            section=record.section,
            raw=None,
        )
        for record in display_records
    ]
