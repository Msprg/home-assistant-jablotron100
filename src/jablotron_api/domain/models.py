"""Stable API models."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, Field


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


class Scope(StrEnum):
    SYSTEM_READ = "system:read"
    STATUS_READ = "status:read"
    EVENTS_READ = "events:read"
    CATALOG_READ = "catalog:read"
    CONFIG_READ = "config:read"
    USERS_READ = "users:read"
    USERS_CODES_READ = "users:codes:read"
    USERS_WRITE = "users:write"
    SECTIONS_CONTROL = "sections:control"
    PGS_CONTROL = "pgs:control"
    CODES_IMPERSONATE = "codes:impersonate"
    TOKENS_ADMIN = "tokens:admin"


DEFAULT_ADMIN_SCOPES = [
    scope.value
    for scope in (
        Scope.SYSTEM_READ,
        Scope.STATUS_READ,
        Scope.EVENTS_READ,
        Scope.CATALOG_READ,
        Scope.CONFIG_READ,
        Scope.USERS_READ,
        Scope.USERS_CODES_READ,
        Scope.USERS_WRITE,
        Scope.SECTIONS_CONTROL,
        Scope.PGS_CONTROL,
        Scope.CODES_IMPERSONATE,
        Scope.TOKENS_ADMIN,
    )
]


class ArmMode(StrEnum):
    AWAY = "away"
    HOME = "home"
    NIGHT = "night"


class SectionStatusModel(BaseModel):
    id: int
    name: str
    state: str | None
    pending: bool = False
    arming: bool = False
    triggered: bool = False
    problem: bool = False
    sabotage: bool = False
    fire: bool = False


class PGStatusModel(BaseModel):
    id: int
    name: str
    state: str | None


class DeviceStatusModel(BaseModel):
    id: int
    name: str
    kind: str | None = None
    section_id: int | None = None
    type_raw: int | None = None
    subtype_raw: int | None = None
    hardware_model: str | None = None
    inferred_device_type: str | None = None
    inferred_entity_type: str | None = None
    comment: str = ""
    state: str | None = None
    problem: bool | None = False
    battery_level: int | None = None
    battery_problem: bool | None = None
    signal_strength: int | None = None
    temperature: float | None = None
    battery_standby_voltage: float | None = None
    battery_load_voltage: float | None = None
    pulses: list[int] = Field(default_factory=list)
    connection: str | None = None
    wireless: bool | None = None


class UserModel(BaseModel):
    id: int
    name: str
    phone: str = ""
    code: str = ""
    cards: list[str] = Field(default_factory=list)
    comment: str = ""
    flags_raw: int | None = None
    access_raw: int | None = None
    section_ids: list[int] = Field(default_factory=list)
    pg_ids: list[int] = Field(default_factory=list)
    enabled: bool | None = None
    rights: str = ""
    time_limited_group_raw: int | None = None


class UserCreateModel(BaseModel):
    id: int
    name: str
    phone: str = ""
    code: str = ""
    card1: str = ""
    comment: str = ""
    flags_raw: int | None = None
    access_raw: int | None = None
    sections: list[int] = Field(default_factory=list)
    pgs: list[int] = Field(default_factory=list)
    time_limited_group_raw: int | None = None


class UserPatchModel(BaseModel):
    name: str | None = None
    phone: str | None = None
    code: str | None = None
    card1: str | None = None
    comment: str | None = None
    flags_raw: int | None = None
    access_raw: int | None = None
    sections: list[int] | None = None
    pgs: list[int] | None = None
    time_limited_group_raw: int | None = None


class EventRecordModel(BaseModel):
    timestamp: str | None = None
    kind: str | None = None
    text: str
    event_code: str | None = None
    source: str | None = None
    channel: str | None = None
    section: str | None = None
    raw: str | None = None


class ExportSectionModel(BaseModel):
    id: int
    display_id: int
    name: str
    comment: str = ""


class ExportPGModel(BaseModel):
    id: int
    display_id: int
    name: str
    comment: str = ""
    section_id: int | None = None


class InitialSetupRangeModel(BaseModel):
    first_id: int
    last_id: int
    count: int


class InitialSetupModel(BaseModel):
    source: str
    exact: bool = False
    sections: InitialSetupRangeModel | None = None
    devices: InitialSetupRangeModel | None = None
    users: InitialSetupRangeModel | None = None
    pgs: InitialSetupRangeModel | None = None
    system_name: str | None = None
    language: str | None = None
    code_length: int | None = None
    code_prefix: bool | None = None
    em_unique_enabled: bool | None = None
    notes: list[str] = Field(default_factory=list)


class RawCatalogCountsModel(BaseModel):
    sections: int
    devices: int
    users: int
    pgs: int


class BusStatusModel(BaseModel):
    bus_number: int
    voltage: float | None = None
    devices_loss_count: int | None = None


class CentralStatusModel(BaseModel):
    power_supply: bool | None = None
    battery_level: int | None = None
    battery_problem: bool | None = None
    battery_standby_voltage: float | None = None
    battery_load_voltage: float | None = None
    lan_connection: bool | None = None
    lan_ip: str | None = None
    gsm_signal: bool | None = None
    gsm_signal_strength: float | None = None
    buses: list[BusStatusModel] = Field(default_factory=list)
    last_authorized_user_or_device: str | None = None


class ExportCatalogModel(BaseModel):
    sections: list[ExportSectionModel]
    pgs: list[ExportPGModel]
    devices: list[DeviceStatusModel]
    users: list[UserModel]
    initial_setup: InitialSetupModel | None = None
    raw_counts: RawCatalogCountsModel | None = None
    sha256: str | None = None
    path: str | None = None


class PanelStatusModel(BaseModel):
    refreshed_at: datetime = Field(default_factory=utc_now)
    sections: list[SectionStatusModel] = Field(default_factory=list)
    pgs: list[PGStatusModel] = Field(default_factory=list)
    devices: list[DeviceStatusModel] = Field(default_factory=list)
    central: CentralStatusModel = Field(default_factory=CentralStatusModel)
    service_mode: bool = False
    source: str = "poll"


class ServerSystemModel(BaseModel):
    server_version: str
    panel_model: str | None = None
    panel_hardware_version: str | None = None
    panel_firmware_version: str | None = None
    panel_unique_id: str | None = None
    mtls_required: bool = True
    token_scopes: list[str] = Field(default_factory=list)
    poll_interval_seconds: float


class TokenCreateRequest(BaseModel):
    label: str
    scopes: list[str] = Field(default_factory=list)
    certificate_fingerprint: str | None = None
    allowed_user_ids: list[int] = Field(default_factory=list)


class TokenInfoModel(BaseModel):
    id: str
    label: str
    scopes: list[str]
    certificate_fingerprint: str | None = None
    allowed_user_ids: list[int] = Field(default_factory=list)
    created_at: datetime
    revoked_at: datetime | None = None
    last_used_at: datetime | None = None


class TokenCreateResponse(BaseModel):
    token: str
    token_info: TokenInfoModel


class AuthenticatedToken(BaseModel):
    id: str
    label: str
    scopes: list[str]
    certificate_fingerprint: str | None = None
    allowed_user_ids: list[int] = Field(default_factory=list)


class WebSocketEnvelope(BaseModel):
    sequence: int
    topic: str
    event: str
    timestamp: datetime = Field(default_factory=utc_now)
    payload: dict[str, Any]
