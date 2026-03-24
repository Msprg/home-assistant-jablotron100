from __future__ import annotations

from homeassistant.components.diagnostics import async_redact_data
from homeassistant.core import HomeAssistant
from . import JablotronConfigEntry
from .const import CONF_API_TOKEN
from .api_runtime import Jablotron


async def async_get_config_entry_diagnostics(
	hass: HomeAssistant, config_entry: JablotronConfigEntry
) -> dict:
	jablotron_instance: Jablotron = config_entry.runtime_data

	central_unit = jablotron_instance.central_unit()

	return {
		"central_unit": {
			"model": central_unit.model,
			"firmware_version": central_unit.firmware_version,
			"hardware_version": central_unit.hardware_version,
		},
		"configuration": async_redact_data(config_entry.data, CONF_API_TOKEN),
		"options": dict(config_entry.options),
		"entities": {key.value: sorted(value.keys()) for key, value in jablotron_instance.entities.items() if value},
	}
