"""Pure device-type inference helpers extracted from the panel runtime.

These were previously inlined in `panel/runtime.py`. They are pure functions
over the export-catalog snapshot view of a device, so they live here for
isolated reuse and unit testing.
"""

from __future__ import annotations

from typing import Callable
import unicodedata

SYSTEM_OBJECT_IDS: frozenset[int] = frozenset({0, 233, 234, 235, 237})

DEVICE_TYPE_TO_ENTITY_TYPE: dict[str, str] = {
    "motion_detector": "device_state_motion",
    "window_opening_detector": "device_state_window",
    "door_opening_detector": "device_state_door",
    "keypad_with_door_opening_detector": "device_state_door",
    "garage_door_opening_detector": "device_state_garage_door",
    "glass_break_detector": "device_state_glass",
    "flood_detector": "device_state_moisture",
    "gas_detector": "device_state_gas",
    "smoke_detector": "device_state_smoke",
    "lock": "device_state_lock",
    "tamper": "device_state_tamper",
    "thermostat": "device_state_thermostat",
    "thermometer": "device_state_thermometer",
    "indoor_siren": "device_state_indoor_siren_button",
    "button": "device_state_button",
    "key_fob": "device_state_button",
    "valve": "device_state_valve",
    "custom": "device_state_custom",
}


def infer_device_type(
    *,
    name: str,
    hardware_model: str | None,
    type_raw: int | None,
    object_id: int,
) -> tuple[str | None, str | None]:
    hardware = (hardware_model or "").upper()
    lowered_name = name.lower()

    if object_id in SYSTEM_OBJECT_IDS:
        return None, None
    if hardware in {"120Z", "JA-120Z"}:
        return "bus_booster", None
    if hardware == "JA-114HN":
        return "io_module", None
    if hardware.startswith("JA-122E"):
        return "rfid_reader", None
    if hardware.startswith("JA-110P"):
        return "motion_detector", "device_state_motion"
    if hardware.startswith("JA-111M"):
        return "window_opening_detector", "device_state_window"
    if hardware.startswith("JA-110ST"):
        return "smoke_detector", "device_state_smoke"
    if hardware.startswith("JA-110F"):
        return "flood_detector", "device_state_moisture"
    if hardware.startswith("JA-110A") or hardware.startswith("JA-111A"):
        return "indoor_siren", "device_state_indoor_siren_button"
    if hardware.startswith("JA-111TH"):
        return "thermometer", "device_state_thermometer"
    if hardware.startswith("JA-110TP") or hardware.startswith("JA-150TP"):
        return "thermostat", "device_state_thermostat"
    if hardware.startswith("JA-154J"):
        return "key_fob", "device_state_button"
    if hardware.startswith("JA-111R"):
        return "radio_module", None
    if hardware.startswith("JA-11") and hardware.endswith("E"):
        if "vstup" in lowered_name or "door" in lowered_name or "dver" in lowered_name:
            return "keypad_with_door_opening_detector", "device_state_door"
        return "keypad", None
    if "garaz" in lowered_name or "garage" in lowered_name:
        return "garage_door_opening_detector", "device_state_garage_door"
    if "sklo" in lowered_name or "glass" in lowered_name:
        return "glass_break_detector", "device_state_glass"
    if "zamok" in lowered_name or "lock" in lowered_name:
        return "lock", "device_state_lock"
    if "tamper" in lowered_name or "sabot" in lowered_name:
        return "tamper", "device_state_tamper"
    if "ventil" in lowered_name or "valve" in lowered_name:
        return "valve", "device_state_valve"
    if "tlacid" in lowered_name or "button" in lowered_name:
        return "button", "device_state_button"
    if "sirena" in lowered_name or "siren" in lowered_name:
        return "indoor_siren", "device_state_indoor_siren_button"
    if "elektrom" in lowered_name or "meter" in lowered_name:
        return "electricity_meter_with_pulse_output", None
    if "dym" in lowered_name:
        return "smoke_detector", "device_state_smoke"
    if "plyn" in lowered_name:
        return "gas_detector", "device_state_gas"
    if "zapl" in lowered_name:
        return "flood_detector", "device_state_moisture"
    if "teplomer" in lowered_name:
        return "thermometer", "device_state_thermometer"
    if "termostat" in lowered_name:
        return "thermostat", "device_state_thermostat"
    if "magnet" in lowered_name or "okno" in lowered_name:
        return "window_opening_detector", "device_state_window"
    if "dver" in lowered_name or "door" in lowered_name or "vstup" in lowered_name or "branka" in lowered_name:
        return "door_opening_detector", "device_state_door"
    if type_raw == 45:
        return "flood_detector", "device_state_moisture"
    if type_raw == 3:
        return "smoke_detector", "device_state_smoke"
    if type_raw in {0, 1}:
        return "motion_detector", "device_state_motion"
    return "custom", "device_state_custom"


def normalized_name(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value or "")
    ascii_only = normalized.encode("ascii", "ignore").decode("ascii")
    return " ".join(ascii_only.lower().split())


def is_default_section_name(name: str, display_id: int) -> bool:
    normalized = normalized_name(name)
    return normalized in {f"section {display_id}", f"sekcia {display_id + 1}"}


def is_default_pg_name(name: str, display_id: int) -> bool:
    normalized = normalized_name(name)
    return normalized in {f"pg output {display_id}", f"pg vystup {display_id}"}


def tail_default_cutoff(
    names: list[tuple[int, str]],
    *,
    is_default: Callable[[str, int], bool],
    minimum_suffix: int = 8,
) -> int | None:
    if len(names) < minimum_suffix:
        return None
    for index, (display_id, name) in enumerate(names):
        suffix = names[index:]
        if len(suffix) < minimum_suffix:
            break
        if is_default(name, display_id) and all(
            is_default(item_name, item_display_id) for item_display_id, item_name in suffix
        ):
            return index
    return None
