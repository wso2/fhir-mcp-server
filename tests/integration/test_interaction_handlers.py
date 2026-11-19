from unittest.mock import AsyncMock

import pytest

from fhir_mcp_server import server
from fhir_mcp_server.errors import FhirAuthenticationError
from fhir_mcp_server.oauth import ServerConfigs

BATCH = {
    "resourceType": "Bundle",
    "type": "batch",
    "entry": [{"request": {"method": "GET", "url": "Patient/123"}}],
}


class Tools:
    def __init__(self):
        """Initialize a registry for testing handlers without running an MCP server."""
        self.handlers = {}

    def tool(self, **kwargs):
        """Emulate the MCP registration decorator so tests can call handlers directly."""

        def decorate(function):
            """Capture a decorated handler under its tool name without wrapping execution."""
            self.handlers[function.__name__] = function
            return function

        return decorate


@pytest.fixture
def handlers(monkeypatch):
    """Register handlers with isolated settings and no deployment token."""
    cfg = ServerConfigs(
        _env_file=None,
        server_access_token="",
        server_disable_authorization=False,
        server_base_url="http://127.0.0.1:1/fhir",
    )
    monkeypatch.setattr(server, "configs", cfg)
    tools = Tools()
    server.register_mcp_tools(tools)
    return tools.handlers


async def test_missing_auth_is_typed_and_distinct_from_input_errors(handlers, monkeypatch):
    """Keep missing authentication distinct from malformed input and unrelated ValueErrors."""
    monkeypatch.setattr(server, "get_user_access_token", AsyncMock(return_value=None))
    with pytest.raises(FhirAuthenticationError):
        await server.get_async_fhir_client()
    result = await handlers["execute_bundle"](BATCH)
    assert result.isError
    assert result.structuredContent["error"]["kind"] == "authentication"
    invalid = await handlers["execute_bundle"]({**BATCH, "entry": []})
    assert invalid.structuredContent["error"]["kind"] == "validation"
    # A ValueError that is not an authentication failure is no longer reported as one.
    monkeypatch.setattr(
        server,
        "get_async_fhir_client",
        AsyncMock(side_effect=ValueError("not an auth error")),
    )
    existing = await handlers["read"]("Patient", "123")
    assert existing["issue"][0]["code"] == "exception"


async def test_validation_runs_before_identity(handlers, monkeypatch):
    """Reject invalid Bundles without resolving credentials or contacting the server."""
    identity = AsyncMock(side_effect=AssertionError("Must not resolve identity"))
    monkeypatch.setattr(server, "get_user_access_token", identity)
    for bundle in [
        {**BATCH, "type": "collection"},
        {**BATCH, "entry": []},
        {**BATCH, "entry": BATCH["entry"] * (server.configs.mcp_max_bundle_entries + 1)},
    ]:
        result = await handlers["execute_bundle"](bundle)
        assert result.isError
        assert result.structuredContent["error"]["kind"] == "validation"
        assert result.structuredContent["httpStatus"] is None
    identity.assert_not_awaited()


def test_positive_limits(monkeypatch):
    """Require strictly positive entry, operation and byte limits."""
    for key in (
        "FHIR_MCP_MAX_BUNDLE_ENTRIES",
        "FHIR_MCP_MAX_PATCH_OPERATIONS",
        "FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES",
        "FHIR_MCP_MAX_INTERACTION_RESPONSE_BYTES",
    ):
        monkeypatch.delenv(key, raising=False)
    defaults = ServerConfigs(_env_file=None)
    assert defaults.mcp_max_bundle_entries == 100
    assert defaults.mcp_max_patch_operations == 100
    for setting in (
        "mcp_max_bundle_entries",
        "mcp_max_patch_operations",
        "mcp_max_interaction_request_bytes",
        "mcp_max_interaction_response_bytes",
    ):
        with pytest.raises(ValueError):
            ServerConfigs(_env_file=None, **{setting: 0})
