#!/usr/bin/env python3
"""Shared reverse-engineering helpers for live Jablotron config workflows."""

from __future__ import annotations

import hashlib
import os
import re
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional

from jablotron_usb_debug import (
    JablotronUSBClient,
    describe_packet,
    ensure_serial_port,
    perform_flink_export_session,
    perform_login,
    perform_send_raw_report,
)

SECTOR_SIZE = 512
EXPORT_START_LBA = 35
EXPORT_SECTORS = 2048
DEFAULT_FLEXI_CFG_LABEL = "FLEXI_CFG"
DEFAULT_FLEXI_CFG_LINK = Path("/dev/disk/by-label") / DEFAULT_FLEXI_CFG_LABEL
DEFAULT_IMPORT_MOUNTPOINT = Path("/mnt/flexi_cfg")
DEFAULT_IMPORT_PATH = DEFAULT_IMPORT_MOUNTPOINT / "IMPORT.CFG"
REPO_ROOT = Path(__file__).resolve().parent
DEFAULT_ADD_TEMPLATE_PCAP = REPO_ROOT / "research/captures/usb/f_link/f-link-add-user-USER91TEST.pcapng"
DEFAULT_ADD_TEMPLATE_FRAME = 2085

REPORT_520102 = "520102" + "00" * 61
REPORT_520124 = "520124" + "00" * 61
REPORT_52010C = "52010c" + "00" * 61
REPORT_800114 = "800114" + "00" * 61
REPORT_80010F = "80010f" + "00" * 61


@dataclass(frozen=True)
class UserRecord:
    offset: int
    user_id: Optional[int]
    raw_id_bytes: str
    status_raw: Optional[int]
    permissions_raw: Optional[int]
    rights: str
    enabled: Optional[bool]
    name: str
    phone: str
    code: str
    card: str
    comment: str


@dataclass(frozen=True)
class ExportSnapshot:
    path: Path
    sha256: str
    raw_records: list[UserRecord]
    records: list[UserRecord]


def invert_blob(data: bytes) -> bytes:
    return bytes(byte ^ 0xFF for byte in data)


def _parse_lsblk_pairs(text: str) -> list[dict[str, str]]:
    rows: list[dict[str, str]] = []
    for line in text.splitlines():
        pairs = dict(re.findall(r'(\w+)="([^"]*)"', line))
        if pairs:
            rows.append(pairs)
    return rows


def resolve_flexi_cfg_device(device: str | None = None) -> str:
    if device and device != "auto":
        path = Path(device)
        return str(path.resolve()) if path.exists() else device

    if DEFAULT_FLEXI_CFG_LINK.exists():
        return str(DEFAULT_FLEXI_CFG_LINK.resolve())

    result = subprocess.run(
        ["lsblk", "-P", "-o", "PATH,LABEL,TYPE"],
        check=False,
        text=True,
        capture_output=True,
    )
    if result.returncode == 0:
        for row in _parse_lsblk_pairs(result.stdout):
            if row.get("LABEL") == DEFAULT_FLEXI_CFG_LABEL and row.get("TYPE") == "part":
                return row["PATH"]

    raise SystemExit(
        "Unable to resolve the FLEXI_CFG block device. "
        "Connect the panel or pass --device /dev/sdX1 explicitly."
    )


def default_export_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_EXPORT.CFG.bin"


def default_sector_output(prefix: str) -> Path:
    timestamp = time.strftime("%Y-%m-%d_%H%M%S")
    return Path("/tmp") / f"{timestamp}_{prefix}_IMPORT-sector.bin"


def find_record_starts(blob: bytes) -> list[int]:
    starts: list[int] = []
    for offset in range(len(blob) - 4):
        if blob[offset : offset + 2] != b"\x07\x81":
            continue
        if b"\x04" not in blob[offset : offset + 96]:
            continue
        if starts and offset - starts[-1] <= 32:
            continue
        starts.append(offset)
    return starts


def decode_user_id(id_bytes: bytes) -> Optional[int]:
    if len(id_bytes) == 1:
        return id_bytes[0]
    if len(id_bytes) == 3 and id_bytes[:2] == b"\xcd\x02":
        return 0x200 + id_bytes[2]
    return None


def decode_msgpack_string(data: bytes, start: int) -> str:
    if start >= len(data):
        return ""
    marker = data[start]
    if 0xA0 <= marker <= 0xBF:
        length = marker - 0xA0
        offset = start + 1
    elif marker == 0xD9 and start + 1 < len(data):
        length = data[start + 1]
        offset = start + 2
    elif marker == 0xDA and start + 2 < len(data):
        length = int.from_bytes(data[start + 1 : start + 3], "big")
        offset = start + 3
    elif marker == 0xDB and start + 4 < len(data):
        length = int.from_bytes(data[start + 1 : start + 5], "big")
        offset = start + 5
    else:
        return ""
    return data[offset : offset + length].decode("utf-8", "replace")


def decode_msgpack_int(data: bytes, start: int) -> tuple[Optional[int], int]:
    if start >= len(data):
        return None, start
    marker = data[start]
    if marker <= 0x7F:
        return marker, start + 1
    if marker >= 0xE0:
        return marker - 0x100, start + 1
    if marker == 0xCC and start + 1 < len(data):
        return data[start + 1], start + 2
    if marker == 0xCD and start + 2 < len(data):
        return int.from_bytes(data[start + 1 : start + 3], "big"), start + 3
    if marker == 0xCE and start + 4 < len(data):
        return int.from_bytes(data[start + 1 : start + 5], "big"), start + 5
    if marker == 0xD0 and start + 1 < len(data):
        return int.from_bytes(data[start + 1 : start + 2], "big", signed=True), start + 2
    if marker == 0xD1 and start + 2 < len(data):
        return int.from_bytes(data[start + 1 : start + 3], "big", signed=True), start + 3
    if marker == 0xD2 and start + 4 < len(data):
        return int.from_bytes(data[start + 1 : start + 5], "big", signed=True), start + 5
    return None, start


def parse_len_string(record: bytes, tag: int) -> str:
    index = record.find(bytes([tag]))
    if index == -1 or index + 1 >= len(record):
        return ""
    return decode_msgpack_string(record, index + 1)


def parse_card(record: bytes) -> str:
    start = record.find(b"\x07")
    if start == -1:
        return ""
    end = record.find(b"\x08", start)
    if end == -1:
        end = len(record)
    field = record[start:end]
    marker_index = field.find(b"\x81\x00")
    if marker_index == -1 or marker_index + 2 >= len(field):
        return ""
    return decode_msgpack_string(field, marker_index + 2)


def decode_rights_name(permissions_raw: Optional[int]) -> str:
    mapping = {
        2875: "coService",
        1851: "coMaster",
        811: "coUserNoSelfedit",
    }
    if permissions_raw in mapping:
        return mapping[permissions_raw]
    if permissions_raw is None:
        return ""
    return f"raw:{permissions_raw}"


def dedupe_user_records(records: Iterable[UserRecord]) -> list[UserRecord]:
    deduped: list[UserRecord] = []
    seen_ids: set[int] = set()
    for record in sorted(records, key=lambda item: item.offset):
        if record.user_id is None:
            deduped.append(record)
            continue
        if record.user_id in seen_ids:
            continue
        seen_ids.add(record.user_id)
        deduped.append(record)
    return deduped


def extract_users(path: Path, *, dedupe: str = "raw") -> list[UserRecord]:
    blob = invert_blob(path.read_bytes())
    starts = find_record_starts(blob)
    users: list[UserRecord] = []
    for index, start in enumerate(starts):
        end = starts[index + 1] if index + 1 < len(starts) else min(len(blob), start + 256)
        record = blob[start:end]

        cursor = 2
        id_bytes = bytearray()
        while cursor < len(record) and record[cursor] != 0x8C and len(id_bytes) < 4:
            id_bytes.append(record[cursor])
            cursor += 1
        if cursor >= len(record) or record[cursor] != 0x8C:
            continue

        inner = cursor + 1
        status_raw: Optional[int] = None
        permissions_raw: Optional[int] = None
        if inner + 1 < len(record) and record[inner] == 0:
            status_raw, inner = decode_msgpack_int(record, inner + 1)
        if inner + 1 < len(record) and record[inner] == 1:
            permissions_raw, inner = decode_msgpack_int(record, inner + 1)

        name = parse_len_string(record, 0x04)
        if not name:
            continue

        users.append(
            UserRecord(
                offset=start,
                user_id=decode_user_id(bytes(id_bytes)),
                raw_id_bytes=bytes(id_bytes).hex(),
                status_raw=status_raw,
                permissions_raw=permissions_raw,
                rights=decode_rights_name(permissions_raw),
                enabled=None if status_raw is None else status_raw != 1,
                name=name,
                phone=parse_len_string(record, 0x05),
                code=parse_len_string(record, 0x06),
                card=parse_card(record),
                comment=parse_len_string(record, 0x0A),
            )
        )

    if dedupe == "raw":
        return users
    if dedupe == "dedupe":
        return dedupe_user_records(users)
    raise ValueError(f"Unsupported dedupe mode: {dedupe}")


def iter_printable_strings(blob: bytes, *, min_length: int) -> Iterable[str]:
    pattern = re.compile(rb"[\x20-\x7e\xc0-\xff]{" + str(min_length).encode("ascii") + rb",}")
    for match in pattern.finditer(blob):
        yield match.group().decode("utf-8", "replace")


def read_export_direct(
    *,
    device: str,
    output: Path,
    start_lba: int = EXPORT_START_LBA,
    sectors: int = EXPORT_SECTORS,
) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    output.parent.mkdir(parents=True, exist_ok=True)
    command = [
        "dd",
        f"if={resolved_device}",
        f"of={output}",
        f"bs={SECTOR_SIZE}",
        f"skip={start_lba}",
        f"count={sectors}",
        "iflag=direct",
        "status=none",
    ]
    if os.geteuid() != 0:
        command = ["sudo", "-n"] + command
    subprocess.run(command, check=True)


def trigger_live_export(*, port: str, code: str, reset: bool) -> None:
    serial_port = ensure_serial_port(port)
    client = JablotronUSBClient(serial_port)
    try:
        perform_login(client, code, reset=reset)
        time.sleep(0.5)
        perform_flink_export_session(client)
        end = time.time() + 4.0
        while time.time() < end:
            for _packet in client.read_packets(timeout=0.2):
                pass
    finally:
        client.close()


def pull_live_export_snapshot(
    *,
    output: Path,
    device: str,
    port: str,
    code: str,
    reset: bool,
    trigger: bool = True,
    start_lba: int = EXPORT_START_LBA,
    sectors: int = EXPORT_SECTORS,
) -> ExportSnapshot:
    if trigger:
        trigger_live_export(port=port, code=code, reset=reset)
    read_export_direct(device=device, output=output, start_lba=start_lba, sectors=sectors)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    raw_records = extract_users(output, dedupe="raw")
    records = dedupe_user_records(raw_records)
    return ExportSnapshot(path=output, sha256=digest, raw_records=raw_records, records=records)


def run_command(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(command, check=check, text=True, capture_output=True)


def stage_import(import_path: Path, sector_path: Path) -> None:
    sector = sector_path.read_bytes()[:SECTOR_SIZE]
    write_error: OSError | None = None

    with import_path.open("r+b", buffering=0) as handle:
        try:
            handle.seek(0)
            handle.write(sector)
            handle.flush()
            os.fsync(handle.fileno())
        except OSError as exc:
            write_error = exc

    current = import_path.read_bytes()[:SECTOR_SIZE]
    if current != sector:
        if write_error is not None:
            raise SystemExit(f"IMPORT.CFG staging failed and did not verify: {write_error}") from write_error
        raise SystemExit("IMPORT.CFG staging failed verification.")

    if write_error is not None:
        print(f"warning: write raised {write_error}; continuing because staged bytes verified exactly")


def mount_device(device: str, mountpoint: Path, *, mount_tool: str) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    suppress_message = False
    if mount_tool == "sudo":
        mountpoint.mkdir(parents=True, exist_ok=True)
        result = run_command(["sudo", "-n", "mount", resolved_device, str(mountpoint)], check=False)
        stderr = result.stderr.lower()
        suppress_message = result.returncode != 0 and "already mounted" in stderr
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"mount failed for {resolved_device}")
    elif mount_tool == "udisksctl":
        result = run_command(["udisksctl", "mount", "-b", resolved_device], check=False)
        suppress_message = result.returncode != 0 and "already mounted" in result.stderr.lower()
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"mount failed for {resolved_device}")
    else:
        raise SystemExit(f"Unsupported mount tool: {mount_tool}")

    message = result.stdout.strip() or result.stderr.strip()
    if message and not suppress_message:
        print(message)


def unmount_device(device: str, *, mount_tool: str) -> None:
    resolved_device = resolve_flexi_cfg_device(device)
    suppress_message = False
    if mount_tool == "sudo":
        result = run_command(["sudo", "-n", "umount", resolved_device], check=False)
        stderr = result.stderr.lower()
        suppress_message = result.returncode != 0 and "not mounted" in stderr
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"unmount failed for {resolved_device}")
    elif mount_tool == "udisksctl":
        result = run_command(["udisksctl", "unmount", "-b", resolved_device], check=False)
        suppress_message = result.returncode != 0 and "not mounted" in result.stderr.lower()
        if result.returncode != 0 and not suppress_message:
            raise SystemExit(result.stderr.strip() or result.stdout.strip() or f"unmount failed for {resolved_device}")
    else:
        raise SystemExit(f"Unsupported mount tool: {mount_tool}")

    message = result.stdout.strip() or result.stderr.strip()
    if message and not suppress_message:
        print(message)


def drain_packets(client: JablotronUSBClient, *, timeout: float, prefix: str, verbose: bool) -> list[bytes]:
    packets = list(client.read_packets(timeout=timeout))
    if verbose:
        for packet in packets:
            print(prefix, describe_packet(packet, decode=True))
    return packets


def send_report(client: JablotronUSBClient, report_hex: str, *, verbose: bool) -> None:
    perform_send_raw_report(client, report_hex)
    if verbose:
        print("tx", report_hex[:6])


def enter_setup_mode(client: JablotronUSBClient, *, verbose: bool, initial_packets: list[bytes] | None = None) -> None:
    service_rights = False
    service_rights_at: float | None = None
    nudged_0f = False
    saw_1a0a = False
    sent_post_1a0a_520102 = False
    entered_setup = False
    deadline = time.time() + 15.0
    last_keepalive = 0.0

    while time.time() < deadline and not entered_setup:
        if initial_packets is not None:
            packets = initial_packets
            initial_packets = None
        else:
            packets = drain_packets(client, timeout=0.5, prefix="setup", verbose=verbose)
        now = time.time()

        for packet in packets:
            if packet.startswith(bytes.fromhex("801a0c")) and not service_rights:
                service_rights = True
                service_rights_at = time.time()
            elif packet.startswith(bytes.fromhex("80021a0a")):
                saw_1a0a = True
                send_report(client, REPORT_80010F, verbose=verbose)
                last_keepalive = time.time()
            elif packet.startswith(bytes.fromhex("800112")):
                entered_setup = True

        if service_rights and not saw_1a0a and not nudged_0f and service_rights_at and now - service_rights_at >= 0.35:
            send_report(client, REPORT_80010F, verbose=verbose)
            nudged_0f = True
        elif saw_1a0a and not sent_post_1a0a_520102 and now - last_keepalive >= 0.7:
            send_report(client, REPORT_520102, verbose=verbose)
            sent_post_1a0a_520102 = True
            last_keepalive = now
        elif sent_post_1a0a_520102 and now - last_keepalive >= 0.9:
            send_report(client, REPORT_520102, verbose=verbose)
            last_keepalive = now

    if verbose:
        print(
            "setup_state",
            {
                "service_rights": service_rights,
                "nudged_0f": nudged_0f,
                "saw_1a0a": saw_1a0a,
                "sent_post_1a0a_520102": sent_post_1a0a_520102,
                "entered_setup": entered_setup,
            },
        )

    if not entered_setup:
        raise SystemExit("Did not enter setup mode.")


def perform_import_accept_sequence(client: JablotronUSBClient, *, verbose: bool) -> None:
    send_report(client, REPORT_520102, verbose=verbose)
    time.sleep(0.2)
    drain_packets(client, timeout=1.0, prefix="p1", verbose=verbose)

    send_report(client, REPORT_520124, verbose=verbose)
    time.sleep(0.2)
    drain_packets(client, timeout=1.2, prefix="p2", verbose=verbose)

    send_report(client, REPORT_520102, verbose=verbose)
    time.sleep(0.05)
    send_report(client, REPORT_52010C, verbose=verbose)

    sent_800114 = False
    sent_80010f = False
    sent_post_520102 = False
    deadline = time.time() + 12.0
    while time.time() < deadline:
        packets = drain_packets(client, timeout=0.5, prefix="p3", verbose=verbose)
        if not packets:
            time.sleep(0.05)
            continue

        for packet in packets:
            if packet.startswith(bytes.fromhex("800117")) and not sent_800114:
                send_report(client, REPORT_800114, verbose=verbose)
                sent_800114 = True
            elif packet.startswith(bytes.fromhex("80021a0a")) and not sent_80010f:
                send_report(client, REPORT_80010F, verbose=verbose)
                sent_80010f = True
                time.sleep(0.8)
                send_report(client, REPORT_520102, verbose=verbose)
                sent_post_520102 = True

    if verbose:
        print(
            "accept_flags",
            {
                "sent_800114": sent_800114,
                "sent_80010f": sent_80010f,
                "sent_post_520102": sent_post_520102,
            },
        )


def apply_import_sector(
    *,
    sector_path: Path,
    import_path: Path,
    device: str,
    port: str,
    code: str,
    reset: bool,
    mount_tool: str,
    verbose: bool,
    verify_output: Path | None = None,
) -> ExportSnapshot | None:
    resolved_device = resolve_flexi_cfg_device(device)
    mountpoint = import_path.parent
    mount_device(resolved_device, mountpoint, mount_tool=mount_tool)
    unmounted = False
    try:
        serial_port = ensure_serial_port(port)
        client = JablotronUSBClient(serial_port)
        try:
            perform_login(client, code, reset=reset)
            time.sleep(0.7)
            pre_packets = drain_packets(client, timeout=1.0, prefix="pre", verbose=verbose)
            enter_setup_mode(client, verbose=verbose, initial_packets=pre_packets)
            stage_import(import_path, sector_path)
            unmount_device(resolved_device, mount_tool=mount_tool)
            unmounted = True
            perform_import_accept_sequence(client, verbose=verbose)
        finally:
            client.close()

        if verify_output is None:
            return None
        return pull_live_export_snapshot(
            output=verify_output,
            device=resolved_device,
            port=port,
            code=code,
            reset=reset,
        )
    finally:
        if unmounted:
            mount_device(resolved_device, mountpoint, mount_tool=mount_tool)
