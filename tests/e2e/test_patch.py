"""patch over MCP against a loopback FHIR recorder; no live credentials."""

import json

import pytest

from tests.e2e.conftest import RecordingFhirServer
from tests.e2e.test_execute_bundle import session_for, structured


@pytest.fixture
def stub():
    """Run a disposable loopback recorder and close it after the test."""
    server = RecordingFhirServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


async def test_schema_and_annotations(stub):
    """patch is listed with write annotations and an array payload."""
    async with session_for(stub) as session:
        listed = {t.name: t for t in (await session.list_tools()).tools}
        tool = listed["patch"]
        assert tool.outputSchema["properties"]["status"]
        assert tool.inputSchema["properties"]["payload"]["type"] == "array"
        assert tool.inputSchema["properties"]["prefer"]["default"] == "representation"
        assert tool.annotations.destructiveHint and tool.annotations.openWorldHint
        assert not tool.annotations.readOnlyHint and not tool.annotations.idempotentHint


async def test_precondition_no_body_and_stale_version(stub):
    """Send If-Match and keep both a bodyless success and a stale-version failure."""
    payload = [
        {"op": "replace", "path": "/active", "value": False},
        {"op": "add", "path": "/extension", "value": None},
    ]
    outcome = {
        "resourceType": "OperationOutcome",
        "issue": [{"severity": "error", "code": "conflict"}],
    }
    stub.queue(204, headers={"ETag": 'W/"8"'})
    stub.queue(412, outcome)
    async with session_for(stub) as session:
        args = {"type": "Patient", "id": "123", "payload": payload, "if_match": 'W/"7"'}
        first = await session.call_tool("patch", args)
        assert not first.isError
        assert structured(first)["response"] is None
        assert structured(first)["headers"]["etag"] == 'W/"8"'
        second = await session.call_tool("patch", args)
        assert second.isError and structured(second)["httpStatus"] == 412
        assert structured(second)["response"] == outcome
    assert stub.requests == [("PATCH", "/tenant/fhir/Patient/123")] * 2
    assert json.loads(stub.records[0]["body"]) == payload
    assert stub.records[0]["headers"]["If-Match"] == 'W/"7"'
    assert stub.records[0]["headers"]["Content-Type"] == "application/json-patch+json"


async def test_validation_diagnostics_with_positive_control(stub):
    """Reject invalid input before HTTP with a precise message, then prove valid input
    reaches the same stub.
    """
    async with session_for(stub, FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES="512") as session:
        for args, message in [
            ({"type": "Patient", "id": "", "payload": []}, "ID is required"),
            (
                {"type": "Patient", "id": "bad/id", "payload": []},
                "Invalid FHIR resource ID",
            ),
            (
                {
                    "type": "Patient",
                    "id": "123",
                    "payload": [{"op": "move", "path": "/x"}],
                },
                "requires a 'from' member",
            ),
            (
                {
                    "type": "Patient",
                    "id": "123",
                    "payload": [{"op": "copy", "path": "/x", "from": "x"}],
                },
                "patch 'from'",
            ),
            (
                {"type": "Patient", "id": "123", "payload": [], "if_match": "*"},
                "Wildcard If-Match",
            ),
            (
                {"type": "Patient", "id": "123", "payload": [], "if_match": "7"},
                'weak ETag (W/"7")',
            ),
            (
                {
                    "type": "Patient",
                    "id": "123",
                    "payload": [{"op": "add", "path": "/x", "value": "x" * 513}],
                },
                "byte limit",
            ),
        ]:
            result = await session.call_tool("patch", args)
            data = structured(result)
            assert result.isError and data["error"]["kind"] == "validation"
            assert message in data["error"]["message"]
        assert stub.requests == []
        result = await session.call_tool(
            "patch", {"type": "Patient", "id": "123", "payload": []}
        )
        assert not result.isError
    assert len(stub.requests) == 1


async def test_configured_operation_limit(stub):
    """Apply FHIR_MCP_MAX_PATCH_OPERATIONS before sending anything."""
    payload = [{"op": "remove", "path": "/x"}] * 3
    async with session_for(stub, FHIR_MCP_MAX_PATCH_OPERATIONS="2") as session:
        result = await session.call_tool(
            "patch", {"type": "Patient", "id": "123", "payload": payload}
        )
        assert result.isError
        assert structured(result)["error"]["message"] == "Too many patch operations."
    assert stub.requests == []
