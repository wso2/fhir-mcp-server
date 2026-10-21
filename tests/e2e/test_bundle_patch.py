"""MCP protocol checks against a loopback FHIR recorder; no live credentials."""

from contextlib import asynccontextmanager
import json

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from tests.e2e.conftest import RecordingFhirServer, run_mcp_server


@asynccontextmanager
async def session_for(stub, enabled=True, **settings):
    settings = {"FHIR_MCP_ENABLE_WRITE_TOOLS": str(enabled), **settings}
    async with run_mcp_server(stub.base_url + "/tenant/fhir", settings=settings):
        async with streamable_http_client("http://localhost:8001/mcp/") as (
            read,
            write,
            _,
        ):
            async with ClientSession(read, write) as session:
                await session.initialize()
                yield session


@pytest.fixture
def stub():
    server = RecordingFhirServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def structured(result):
    assert result.structuredContent == json.loads(result.content[0].text)
    return result.structuredContent


async def test_write_gate_and_protocol_schema(stub):
    writes = {"create", "update", "delete", "execute_bundle", "patch"}
    async with session_for(stub, enabled=False) as session:
        listed = await session.list_tools()
        assert not writes & {t.name for t in listed.tools}
        result = await session.call_tool(
            "patch", {"type": "Patient", "id": "123", "payload": []}
        )
        assert result.isError and not stub.requests
    async with session_for(stub) as session:
        listed = {t.name: t for t in (await session.list_tools()).tools}
        assert writes <= listed.keys()
        for name in ("patch", "execute_bundle"):
            tool = listed[name]
            assert tool.outputSchema["properties"]["status"]
            assert (
                tool.inputSchema["properties"]["prefer"]["default"] == "representation"
            )
            assert tool.annotations.destructiveHint and tool.annotations.openWorldHint
            assert (
                not tool.annotations.readOnlyHint
                and not tool.annotations.idempotentHint
            )
        assert listed["patch"].inputSchema["properties"]["payload"]["type"] == "array"


async def test_bundle_single_post_preserves_full_response_and_batch_failure(stub):
    request = {
        "resourceType": "Bundle",
        "type": "batch",
        "entry": [
            {
                "request": {
                    "method": "GET",
                    "url": "/Patient?_revinclude=Observation:patient&_revinclude=Encounter:patient",
                }
            },
            {"request": {"method": "DELETE", "url": "Patient/123"}},
        ],
    }
    response = {
        "resourceType": "Bundle",
        "type": "batch-response",
        "entry": [
            {
                "response": {"status": "200"},
                "resource": {
                    "resourceType": "Bundle",
                    "total": 0,
                    "entry": [],
                    "link": [
                        {"relation": "next", "url": "https://example.invalid/next"}
                    ],
                },
            },
            {
                "response": {
                    "status": "403",
                    "outcome": {
                        "resourceType": "OperationOutcome",
                        "issue": [{"code": "forbidden"}],
                    },
                }
            },
        ],
    }
    stub.queue(200, response)
    async with session_for(
        stub, FHIR_SERVER_ACCESS_TOKEN="dummy-bundle-token"
    ) as session:
        result = await session.call_tool(
            "execute_bundle", {"bundle": request, "prefer": "minimal"}
        )
        data = structured(result)
        assert result.isError and data["status"] == "partial"
        assert data["response"] == response
        assert data["summary"] == {
            "entries": 2,
            "succeeded": 1,
            "failed": 1,
            "pending": 0,
            "unknown": 0,
        }
    assert stub.requests == [("POST", "/tenant/fhir")]
    record = stub.records[0]
    sent = json.loads(record["body"])
    assert (
        sent["entry"][0]["request"]["url"] == request["entry"][0]["request"]["url"][1:]
    )
    assert record["headers"]["Authorization"] == "Bearer dummy-bundle-token"
    assert record["headers"]["Prefer"] == "return=minimal"


async def test_patch_precondition_no_body_and_stale_version(stub):
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


async def test_validation_blocks_requests_with_positive_control(stub):
    async with session_for(stub) as session:
        for args in [
            {"type": "Patient", "id": "", "payload": []},
            {"type": "Patient", "id": "../admin", "payload": []},
            {
                "type": "Patient",
                "id": "123",
                "payload": [{"op": "replace", "path": "/x"}],
            },
        ]:
            result = await session.call_tool("patch", args)
            assert (
                result.isError and structured(result)["error"]["kind"] == "validation"
            )
        for url in [
            "https://example.invalid/Patient",
            "//other/Patient",
            "Patient/%252fadmin",
            "Patient/123?_summary=true",
        ]:
            result = await session.call_tool(
                "execute_bundle",
                {
                    "bundle": {
                        "resourceType": "Bundle",
                        "type": "batch",
                        "entry": [{"request": {"method": "GET", "url": url}}],
                    }
                },
            )
            assert result.isError
        assert stub.requests == []
        result = await session.call_tool(
            "patch", {"type": "Patient", "id": "123", "payload": []}
        )
        assert not result.isError
    assert len(stub.requests) == 1


async def test_bundle_create_rejected_and_system_capabilities_compact(stub):
    metadata = {
        "resourceType": "CapabilityStatement",
        "fhirVersion": "4.0.1",
        "patchFormat": ["application/json-patch+json"],
        "rest": [
            {"mode": "client", "resource": []},
            {
                "mode": "server",
                "interaction": [{"code": "transaction"}],
                "operation": [
                    {"name": f"operation-{i}", "documentation": "x" * 100}
                    for i in range(600)
                ],
                "resource": [
                    {
                        "type": "Patient",
                        "versioning": "versioned-update",
                        "conditionalCreate": True,
                        "operation": [{"name": "resource-operation"}],
                    }
                ],
            },
        ],
    }
    for _ in range(3):
        stub.queue(200, metadata)
    async with session_for(
        stub, FHIR_SERVER_ACCESS_TOKEN="dummy-metadata-token"
    ) as session:
        for args in [
            {
                "type": "Bundle",
                "payload": {"resourceType": "Bundle", "type": "batch", "entry": []},
            },
            {"type": "Bundle", "payload": {"type": "transaction", "entry": []}},
            {"type": "Bundle", "payload": {"resourceType": "Patient"}},
            {
                "type": "Patient",
                "payload": {"resourceType": "Bundle", "type": "collection"},
            },
        ]:
            result = await session.call_tool("create", args)
            assert result.isError
            assert "execute_bundle" in result.content[0].text
        assert stub.requests == []
        result = await session.call_tool("get_capabilities", {})
        body = json.loads(result.content[0].text)
        assert body["resourceTypes"] == ["Patient"] and body["interaction"] == [
            {"code": "transaction"}
        ]
        assert body["operationCount"] == 600 and "operation" not in body
        assert len(result.content[0].text) < 1000
        result = await session.call_tool(
            "get_capabilities", {"include_operations": True}
        )
        body = json.loads(result.content[0].text)
        assert len(body["operation"]) == body["operationCount"] == 600
        result = await session.call_tool("get_capabilities", {"type": "Patient"})
        body = json.loads(result.content[0].text)
        assert (
            body["conditionalCreate"] is True
            and body["versioning"] == "versioned-update"
        )
        assert body["patchFormat"] == metadata["patchFormat"]
        assert body["operation"] == [
            {"name": "resource-operation", "documentation": None}
        ]
        # Positive control: ordinary create still reaches its resource endpoint.
        result = await session.call_tool(
            "create", {"type": "Patient", "payload": {"active": True}}
        )
        assert not result.isError
    assert len(stub.requests) == 4
    assert (
        stub.requests[-1][0] == "POST"
        and stub.requests[-1][1].rstrip("/") == "/tenant/fhir/Patient"
    )
    assert stub.records[0]["headers"]["Authorization"] == "Bearer dummy-metadata-token"


async def test_validation_diagnostics_and_unknown_bundle_mode(stub):
    async with session_for(stub) as session:
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
                {"type": "Patient", "id": "123", "payload": [], "if_match": "bad/tag"},
                'weak ETag (W/"7")',
            ),
        ]:
            result = await session.call_tool("patch", args)
            assert result.isError and message in structured(result)["error"]["message"]
        for mode in ["collection", "document", None]:
            result = await session.call_tool(
                "execute_bundle",
                {"bundle": {"resourceType": "Bundle", "type": mode, "entry": []}},
            )
            body = structured(result)
            assert (
                result.isError
                and body["interaction"] is None
                and body["httpStatus"] is None
            )
            assert "Only transaction or batch" in body["error"]["message"]
        assert stub.requests == []


async def test_protocol_errors_limits_and_pending(stub):
    args = {
        "bundle": {
            "resourceType": "Bundle",
            "type": "transaction",
            "entry": [{"request": {"method": "GET", "url": "Patient/123"}}],
        }
    }
    inconsistent = {
        "resourceType": "Bundle",
        "type": "transaction-response",
        "entry": [{"response": {"status": "403"}}],
    }
    stub.queue(200, inconsistent)
    stub.queue(202)
    stub.queue(200, b'{"truncated":')
    stub.queue(200, b"x" * 513)
    async with session_for(
        stub,
        FHIR_MCP_MAX_INTERACTION_RESPONSE_BYTES="512",
        FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES="512",
    ) as session:
        result = await session.call_tool("execute_bundle", args)
        assert result.isError and structured(result)["status"] == "unknown"
        assert structured(result)["response"] == inconsistent
        result = await session.call_tool("execute_bundle", args)
        assert not result.isError and structured(result)["status"] == "pending"
        result = await session.call_tool("execute_bundle", args)
        assert result.isError and structured(result)["error"]["kind"] == "protocol"
        result = await session.call_tool("execute_bundle", args)
        assert (
            result.isError
            and structured(result)["error"]["kind"] == "response-too-large"
        )
        assert structured(result)["httpStatus"] == 200
        result = await session.call_tool(
            "patch",
            {
                "type": "Patient",
                "id": "123",
                "payload": [{"op": "add", "path": "/x", "value": "x" * 513}],
            },
        )
        assert result.isError and structured(result)["error"]["kind"] == "validation"
    assert len(stub.requests) == 4
