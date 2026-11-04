from unittest.mock import AsyncMock

import pytest
from mcp.server.fastmcp.exceptions import ToolError

from fhir_mcp_server import server
from fhir_mcp_server.interactions import FhirAuthenticationError, FhirTransportError
from fhir_mcp_server.oauth import ServerConfigs, OAuthToken


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
    """Register write-enabled handlers with isolated settings and no deployment token."""
    cfg = ServerConfigs(
        _env_file=None,
        server_access_token="",
        server_disable_authorization=False,
        mcp_enable_write_tools=True,
        server_base_url="http://127.0.0.1:1/fhir",
    )
    monkeypatch.setattr(server, "configs", cfg)
    tools = Tools()
    server.register_mcp_tools(tools)
    return tools.handlers


async def test_direct_handlers_recheck_gate_before_identity(handlers, monkeypatch):
    """Verify every mutation handler rechecks the write gate before resolving credentials."""
    server.configs.mcp_enable_write_tools = False
    identity = AsyncMock(
        side_effect=AssertionError("Gate must run before identity lookup")
    )
    monkeypatch.setattr(server, "get_user_access_token", identity)
    calls = {
        "create": {"type": "Patient", "payload": {}},
        "update": {"type": "Patient", "id": "123", "payload": {}},
        "delete": {"type": "Patient", "id": "123"},
        "patch": {"type": "Patient", "id": "123", "payload": []},
        "execute_bundle": {
            "bundle": {"resourceType": "Bundle", "type": "batch", "entry": []}
        },
    }
    for name, args in calls.items():
        result = await handlers[name](**args)
        if name in ("patch", "execute_bundle"):
            assert result.isError and result.structuredContent["httpStatus"] is None
        else:
            assert result["issue"][0]["code"] == "forbidden"
    identity.assert_not_awaited()


async def test_missing_auth_typed_and_input_errors_not_forbidden(handlers, monkeypatch):
    """Keep missing authentication distinct from malformed input and unrelated ValueErrors."""
    monkeypatch.setattr(server, "get_user_access_token", AsyncMock(return_value=None))
    with pytest.raises(FhirAuthenticationError):
        await server.get_async_fhir_client()
    result = await handlers["patch"]("Patient", "123", [])
    assert result.structuredContent["error"]["kind"] == "authentication"
    invalid = await handlers["patch"]("Patient", "", [])
    assert invalid.structuredContent["error"]["kind"] == "validation"
    capabilities = await handlers["get_capabilities"]()
    assert capabilities["issue"][0]["code"] == "forbidden"
    monkeypatch.setattr(
        server,
        "get_async_fhir_client",
        AsyncMock(side_effect=ValueError("not an auth error")),
    )
    existing = await handlers["read"]("Patient", "123")
    assert existing["issue"][0]["code"] == "exception"


async def test_request_scoped_identity_and_metadata_timeout(handlers, monkeypatch):
    """Resolve metadata credentials anew for each call and forward the configured timeout."""
    context = AsyncMock(
        side_effect=[
            OAuthToken(access_token="first-dummy", token_type="Bearer"),
            OAuthToken(access_token="second-dummy", token_type="Bearer"),
        ]
    )
    monkeypatch.setattr(server, "get_user_access_token", context)
    metadata = AsyncMock(return_value={"rest": [{"mode": "server", "resource": []}]})
    monkeypatch.setattr(server, "get_capability_statement", metadata)
    await handlers["get_capabilities"]()
    await handlers["get_capabilities"]()
    assert [call.kwargs["access_token"] for call in metadata.await_args_list] == [
        "first-dummy",
        "second-dummy",
    ]
    assert all(
        call.kwargs["timeout"] == server.configs.mcp_request_timeout
        for call in metadata.await_args_list
    )


async def test_metadata_failure_is_not_auth_failure(handlers, monkeypatch):
    """Verify unexpected metadata failures remain internal errors rather than authentication
    failures.
    """
    server.configs.server_disable_authorization = True
    monkeypatch.setattr(server, "get_user_access_token", AsyncMock(return_value=None))
    monkeypatch.setattr(
        server,
        "get_capability_statement",
        AsyncMock(side_effect=ValueError("bad metadata")),
    )
    result = await handlers["get_capabilities"]()
    assert result["issue"][0]["code"] == "exception"


@pytest.mark.parametrize("kind,status", [
    ("upstream-http", 403), ("protocol", 200), ("network", None), ("timeout", None),
])
async def test_metadata_diagnostics_and_logs_preserve_category(
    handlers, monkeypatch, caplog, kind, status,
):
    """Expose failure category/status without logging upstream messages or bodies."""
    server.configs.server_disable_authorization = True
    monkeypatch.setattr(server, "get_user_access_token", AsyncMock(return_value=None))
    monkeypatch.setattr(server, "get_capability_statement", AsyncMock(side_effect=
        FhirTransportError(kind, "sensitive upstream details", status=status, uncertain=False)
    ))
    result = await handlers["get_capabilities"]()
    assert result["issue"][0]["code"] == "exception"
    diagnostics = result["issue"][0]["diagnostics"]
    assert kind in diagnostics and f"kind={kind}" in caplog.text
    if status is not None:
        assert f"HTTP {status}" in diagnostics
    assert f"status={status}" in caplog.text
    assert "sensitive" not in diagnostics + caplog.text


def test_defaults_off_and_positive_byte_limits(monkeypatch):
    """Require explicit write opt-in and strictly positive request and response byte limits."""
    for key in (
        "FHIR_MCP_ENABLE_WRITE_TOOLS",
        "FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES",
        "FHIR_MCP_MAX_INTERACTION_RESPONSE_BYTES",
    ):
        monkeypatch.delenv(key, raising=False)
    assert ServerConfigs(_env_file=None).mcp_enable_write_tools is False
    with pytest.raises(ValueError):
        ServerConfigs(_env_file=None, mcp_max_interaction_request_bytes=0)
    with pytest.raises(ValueError):
        ServerConfigs(_env_file=None, mcp_max_interaction_response_bytes=-1)


async def test_bundle_create_blocked_before_identity(handlers, monkeypatch):
    """Reject Bundle type or payload overrides before identity resolution, even with an
    operation.
    """
    identity = AsyncMock(side_effect=AssertionError("Must not resolve identity"))
    monkeypatch.setattr(server, "get_user_access_token", identity)
    for resource_type, payload in [
        ("Bundle", {}),
        ("Patient", {"resourceType": "Bundle"}),
        ("Bundle", {"resourceType": "Patient"}),
    ]:
        with pytest.raises(ToolError, match="Use execute_bundle"):
            await handlers["create"](resource_type, payload, operation="$anything")
    identity.assert_not_awaited()
