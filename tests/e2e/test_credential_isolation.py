"""Exercise the existing launcher against loopback only, using dummy secrets."""

from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from tests.e2e.conftest import RecordingFhirServer, run_mcp_server


async def test_anonymous_fixture_sends_no_authorization(monkeypatch):
    """Prove the shared anonymous fixture does not forward inherited deployment credentials."""
    monkeypatch.setenv("FHIR_SERVER_ACCESS_TOKEN", "dummy-parent-token")
    stub = RecordingFhirServer()
    stub.start()
    try:
        async with run_mcp_server(stub.base_url):
            async with streamable_http_client("http://localhost:8001/mcp/") as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()
                    result = await session.call_tool("read", {"type": "Patient", "id": "123"})
                    assert not result.isError
        assert len(stub.requests) == 1
        assert stub.requests[0][0] == "GET"
        assert stub.authorization_seen == [False]
    finally:
        stub.stop()
