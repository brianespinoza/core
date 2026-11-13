"""Application credentials platform for Model Context Protocol."""

from collections.abc import Generator
from contextlib import contextmanager
import contextvars
from dataclasses import dataclass
from typing import override

from homeassistant.components.application_credentials import (
    AuthorizationServer,
    ClientCredential,
)
from homeassistant.core import HomeAssistant
from homeassistant.helpers.config_entry_oauth2_flow import (
    AbstractOAuth2Implementation,
    LocalOAuth2ImplementationWithPkce,
)

CONF_ACTIVE_AUTHORIZATION_SERVER = "active_authorization_server"


@dataclass
class MCPAuthorizationServer(AuthorizationServer):
    """Authorization server for an MCP server."""

    resource: str | None = None
    """RFC 8707 resource indicator for the MCP server, if it has one."""


_mcp_context: contextvars.ContextVar[MCPAuthorizationServer] = contextvars.ContextVar(
    "mcp_authorization_server_context"
)


@contextmanager
def authorization_server_context(
    authorization_server: MCPAuthorizationServer,
) -> Generator[None]:
    """Context manager for setting the active authorization server."""
    token = _mcp_context.set(authorization_server)
    try:
        yield
    finally:
        _mcp_context.reset(token)


async def async_get_auth_implementation(
    hass: HomeAssistant, auth_domain: str, credential: ClientCredential
) -> AbstractOAuth2Implementation:
    """Return the auth implementation for the active authorization server."""
    if (authorization_server := _mcp_context.get(None)) is None:
        raise RuntimeError("No MCP authorization server set in context")
    return MCPOAuth2Implementation(hass, auth_domain, credential, authorization_server)


class MCPOAuth2Implementation(LocalOAuth2ImplementationWithPkce):
    """OAuth2 implementation for an MCP authorization server.

    The MCP authorization spec requires PKCE, and the RFC 8707 resource
    parameter in both authorization and token requests.
    """

    def __init__(
        self,
        hass: HomeAssistant,
        auth_domain: str,
        credential: ClientCredential,
        authorization_server: MCPAuthorizationServer,
    ) -> None:
        """Initialize the implementation."""
        super().__init__(
            hass,
            auth_domain,
            credential.client_id,
            authorization_server.authorize_url,
            authorization_server.token_url,
            credential.client_secret,
        )
        self._name = credential.name
        self.resource = authorization_server.resource

    @property
    @override
    def name(self) -> str:
        """Name of the implementation."""
        return self._name or self.client_id

    @property
    @override
    def extra_authorize_data(self) -> dict:
        """Extra data that needs to be appended to the authorize url."""
        data = super().extra_authorize_data
        if self.resource:
            data["resource"] = self.resource
        return data

    @override
    async def _token_request(self, data: dict) -> dict:
        """Make a token request, for the code exchange and for refreshes."""
        if self.resource:
            data = {**data, "resource": self.resource}
        return await super()._token_request(data)
