"""Server configuration."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

@dataclass
class PanelSettings:
    port: str = "auto"
    auth_code: str = "1812"
    flexi_cfg_device: str = "auto"
    flexi_log_device: str = "auto"
    import_path: Path = Path("/mnt/flexi_cfg/IMPORT.CFG")
    mount_tool: str = "sudo"
    stage_mode: str = "filesystem"
    read_cleanup_mode: str = "auto"
    write_cleanup_mode: str = "auto"
    poll_interval_seconds: float = 15.0
    reset: bool = True


@dataclass
class ServerSettings:
    host: str = os.getenv("JABLOTRON_API_HOST", "0.0.0.0")
    port: int = int(os.getenv("JABLOTRON_API_PORT", "8443"))
    db_path: Path = Path(os.getenv("JABLOTRON_API_DB_PATH", "/data/jablotron-api.db"))
    tls_certfile: str | None = os.getenv("JABLOTRON_API_TLS_CERTFILE")
    tls_keyfile: str | None = os.getenv("JABLOTRON_API_TLS_KEYFILE")
    tls_ca_certs: str | None = os.getenv("JABLOTRON_API_TLS_CA_CERTS")
    runtime_mode: str = os.getenv("JABLOTRON_API_RUNTIME_MODE", "live")
    mtls_required: bool = True
    panel: PanelSettings = field(
        default_factory=lambda: PanelSettings(
            port=os.getenv("JABLOTRON_PANEL_PORT", "auto"),
            auth_code=os.getenv("JABLOTRON_PANEL_AUTH_CODE", "1812"),
            flexi_cfg_device=os.getenv("JABLOTRON_PANEL_FLEXI_CFG_DEVICE", "auto"),
            flexi_log_device=os.getenv("JABLOTRON_PANEL_FLEXI_LOG_DEVICE", "auto"),
            import_path=Path(os.getenv("JABLOTRON_PANEL_IMPORT_PATH", "/mnt/flexi_cfg/IMPORT.CFG")),
            mount_tool=os.getenv("JABLOTRON_PANEL_MOUNT_TOOL", "sudo"),
            stage_mode=os.getenv("JABLOTRON_PANEL_STAGE_MODE", "filesystem"),
            read_cleanup_mode=os.getenv("JABLOTRON_PANEL_READ_CLEANUP_MODE", "auto"),
            write_cleanup_mode=os.getenv("JABLOTRON_PANEL_WRITE_CLEANUP_MODE", "auto"),
            poll_interval_seconds=float(os.getenv("JABLOTRON_PANEL_POLL_INTERVAL_SECONDS", "15")),
            reset=os.getenv("JABLOTRON_PANEL_RESET", "true").lower() not in {"0", "false", "no"},
        )
    )
