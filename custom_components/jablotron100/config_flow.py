from __future__ import annotations

from collections import OrderedDict
import logging

from homeassistant.config_entries import ConfigEntry, ConfigFlow, ConfigFlowResult, OptionsFlow
from homeassistant.core import callback
import voluptuous as vol

from .api_client import JablotronApiClient, JablotronApiError
from .const import (
    CONF_API_TOKEN,
    CONF_CONTROL_CODE,
    CONF_REQUIRE_CODE_TO_ARM,
    CONF_REQUIRE_CODE_TO_DISARM,
    CONF_SERVER_URL,
    CONF_TLS_CA_CERT,
    CONF_TLS_CLIENT_CERT,
    CONF_TLS_CLIENT_KEY,
    DEFAULT_CONF_REQUIRE_CODE_TO_ARM,
    DEFAULT_CONF_REQUIRE_CODE_TO_DISARM,
    DOMAIN,
    PartiallyArmingMode,
)

LOGGER = logging.getLogger(__name__)


class JablotronConfigFlow(ConfigFlow, domain=DOMAIN):
    _config_entry: ConfigEntry | None

    @staticmethod
    @callback
    def async_get_options_flow(config_entry: ConfigEntry) -> "JablotronOptionsFlow":
        return JablotronOptionsFlow(config_entry)

    async def async_step_user(self, user_input: dict | None = None) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            try:
                client = JablotronApiClient(
                    self.hass,
                    server_url=user_input[CONF_SERVER_URL],
                    api_token=user_input[CONF_API_TOKEN],
                    ca_cert=user_input.get(CONF_TLS_CA_CERT) or None,
                    client_cert=user_input.get(CONF_TLS_CLIENT_CERT) or None,
                    client_key=user_input.get(CONF_TLS_CLIENT_KEY) or None,
                )
                system = await client.get("/v1/system")
                unique_id = system.get("panel_unique_id") or user_input[CONF_SERVER_URL]
                await self.async_set_unique_id(unique_id)
                self._abort_if_unique_id_configured()
                return self.async_create_entry(
                    title=system.get("panel_model") or "Jablotron 100",
                    data={
                        CONF_SERVER_URL: user_input[CONF_SERVER_URL],
                        CONF_API_TOKEN: user_input[CONF_API_TOKEN],
                        CONF_TLS_CA_CERT: user_input.get(CONF_TLS_CA_CERT) or "",
                        CONF_TLS_CLIENT_CERT: user_input.get(CONF_TLS_CLIENT_CERT) or "",
                        CONF_TLS_CLIENT_KEY: user_input.get(CONF_TLS_CLIENT_KEY) or "",
                    },
                )
            except JablotronApiError as err:
                if err.status in {401, 403}:
                    errors["base"] = "invalid_auth"
                else:
                    LOGGER.warning("Jablotron API server request failed during config flow: %s", err)
                    errors["base"] = "cannot_connect"
            except Exception:
                LOGGER.exception("Jablotron API server connection test failed during config flow")
                errors["base"] = "cannot_connect"

        return self.async_show_form(
            step_id="user",
            data_schema=vol.Schema(
                {
                    vol.Required(CONF_SERVER_URL): str,
                    vol.Required(CONF_API_TOKEN): str,
                    vol.Optional(CONF_TLS_CA_CERT, default=""): str,
                    vol.Optional(CONF_TLS_CLIENT_CERT, default=""): str,
                    vol.Optional(CONF_TLS_CLIENT_KEY, default=""): str,
                }
            ),
            errors=errors,
        )


class JablotronOptionsFlow(OptionsFlow):
    def __init__(self, config_entry: ConfigEntry) -> None:
        self._config_entry = config_entry
        self._options = dict(config_entry.options)

    async def async_step_init(self, user_input: dict | None = None) -> ConfigFlowResult:
        if user_input is not None:
            return self.async_create_entry(title="", data=user_input)

        fields = OrderedDict()
        fields[vol.Required("partially_arming_mode", default=self._options.get("partially_arming_mode", PartiallyArmingMode.NIGHT_MODE.value))] = vol.In(
            [mode.value for mode in PartiallyArmingMode]
        )
        fields[vol.Optional(CONF_CONTROL_CODE, default=self._options.get(CONF_CONTROL_CODE, ""))] = str
        fields[vol.Required(CONF_REQUIRE_CODE_TO_DISARM, default=self._options.get(CONF_REQUIRE_CODE_TO_DISARM, DEFAULT_CONF_REQUIRE_CODE_TO_DISARM))] = bool
        fields[vol.Required(CONF_REQUIRE_CODE_TO_ARM, default=self._options.get(CONF_REQUIRE_CODE_TO_ARM, DEFAULT_CONF_REQUIRE_CODE_TO_ARM))] = bool

        return self.async_show_form(step_id="init", data_schema=vol.Schema(fields))
