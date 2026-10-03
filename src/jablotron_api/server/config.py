"""Server configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class PanelSettings:
    port: str = "auto"
    # No default: the panel code is installation-specific. The server
    # raises a clear error at startup in live mode if this is empty. It is
    # the code every session logs in with (status, control, reads).
    auth_code: str = field(default="", repr=False)
    # Optional: a second code used only for user writes. The panel takes
    # IMPORT.CFG writes only from a session logged in with service or ARC
    # rights; a master-rights login writes over HID instead (see
    # write_transport). Empty means user writes log in with auth_code.
    write_auth_code: str = field(default="", repr=False)
    # "auto" | "hid" | "storage". How user records reach the panel: "hid"
    # sends the msgpack record as a 0x1D HID packet (F-Link's path for a
    # master-rights login; no block device needed for the write), "storage"
    # stages it in IMPORT.CFG (F-Link's path for service/ARC rights). "auto"
    # picks storage when write_auth_code is set, else hid.
    write_transport: str = "auto"
    flexi_cfg_device: str = "auto"
    flexi_log_device: str = "auto"
    import_path: Path = Path("/mnt/flexi_cfg/IMPORT.CFG")
    mount_tool: str = "sudo"
    stage_mode: str = "filesystem"
    read_cleanup_mode: str = "auto"
    write_cleanup_mode: str = "auto"
    poll_interval_seconds: float = 1.0
    full_refresh_interval_seconds: float = 3600.0
    fast_status_timeout_seconds: float = 0.6
    full_status_timeout_seconds: float = 2.0
    reset: bool = True
    # How old a cached export catalog may be before a read pulls the panel
    # again. Finite by design: an unbounded default is what let a 52-hour-old
    # catalog be served as if it were current. Refreshes are demand-driven —
    # nothing in the server refreshes the catalog on a timer.
    catalog_max_age_seconds: float = 3600.0
    # User writes run inside the persistent status session (device-state
    # streaming keeps publishing during them). False restores the previous
    # behaviour: the status session is closed and a separate client logs in
    # for the write. A rollback switch, not a design option.
    in_session_config_ops: bool = True
    # How old the cached user table may be, counted from when its pull
    # started, for a user write to be validated against it instead of a fresh
    # panel read under the write lock. 0 means every write pulls first. A
    # failed write marks the cache dirty, so the next write pulls regardless.
    write_preflight_max_age_seconds: float = 60.0


@dataclass
class ServerSettings:
    host: str = os.getenv("JABLOTRON_API_HOST", "0.0.0.0")
    port: int = int(os.getenv("JABLOTRON_API_PORT", "8443"))
    db_path: Path = Path(os.getenv("JABLOTRON_API_DB_PATH", "/data/jablotron-api.db"))
    tls_certfile: str | None = os.getenv("JABLOTRON_API_TLS_CERTFILE")
    tls_keyfile: str | None = os.getenv("JABLOTRON_API_TLS_KEYFILE")
    tls_ca_certs: str | None = os.getenv("JABLOTRON_API_TLS_CA_CERTS")
    runtime_mode: str = os.getenv("JABLOTRON_API_RUNTIME_MODE", "live")
    # mTLS defaults on. The HA Add-on packaging needs to disable mTLS when
    # the server is bound to localhost or HA Supervisor's internal network
    # (mTLS would be friction without security benefit there). Override
    # with JABLOTRON_API_MTLS_REQUIRED=false in that environment.
    mtls_required: bool = os.getenv("JABLOTRON_API_MTLS_REQUIRED", "true").lower() not in {"0", "false", "no"}
    panel: PanelSettings = field(
        default_factory=lambda: PanelSettings(
            port=os.getenv("JABLOTRON_PANEL_PORT", "auto"),
            auth_code=os.getenv("JABLOTRON_PANEL_AUTH_CODE", ""),
            write_auth_code=os.getenv("JABLOTRON_PANEL_WRITE_AUTH_CODE", ""),
            write_transport=os.getenv("JABLOTRON_PANEL_WRITE_TRANSPORT", "auto"),
            flexi_cfg_device=os.getenv("JABLOTRON_PANEL_FLEXI_CFG_DEVICE", "auto"),
            flexi_log_device=os.getenv("JABLOTRON_PANEL_FLEXI_LOG_DEVICE", "auto"),
            import_path=Path(os.getenv("JABLOTRON_PANEL_IMPORT_PATH", "/mnt/flexi_cfg/IMPORT.CFG")),
            mount_tool=os.getenv("JABLOTRON_PANEL_MOUNT_TOOL", "sudo"),
            stage_mode=os.getenv("JABLOTRON_PANEL_STAGE_MODE", "filesystem"),
            read_cleanup_mode=os.getenv("JABLOTRON_PANEL_READ_CLEANUP_MODE", "auto"),
            write_cleanup_mode=os.getenv("JABLOTRON_PANEL_WRITE_CLEANUP_MODE", "auto"),
            poll_interval_seconds=float(os.getenv("JABLOTRON_PANEL_POLL_INTERVAL_SECONDS", "2")),
            full_refresh_interval_seconds=float(os.getenv("JABLOTRON_PANEL_FULL_REFRESH_INTERVAL_SECONDS", "3600")),
            fast_status_timeout_seconds=float(os.getenv("JABLOTRON_PANEL_FAST_STATUS_TIMEOUT_SECONDS", "0.6")),
            full_status_timeout_seconds=float(os.getenv("JABLOTRON_PANEL_FULL_STATUS_TIMEOUT_SECONDS", "2")),
            reset=os.getenv("JABLOTRON_PANEL_RESET", "true").lower() not in {"0", "false", "no"},
            catalog_max_age_seconds=float(
                os.getenv("JABLOTRON_PANEL_CATALOG_MAX_AGE_SECONDS", "3600")
            ),
            in_session_config_ops=os.getenv("JABLOTRON_PANEL_IN_SESSION_CONFIG_OPS", "true").lower()
            not in {"0", "false", "no"},
            write_preflight_max_age_seconds=float(
                os.getenv("JABLOTRON_PANEL_WRITE_PREFLIGHT_MAX_AGE_SECONDS", "60")
            ),
        )
    )
