"""execute_bundle over MCP against a loopback FHIR recorder; no live credentials."""

from contextlib import asynccontextmanager
import json

import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from tests.e2e.conftest import RecordingFhirServer, run_mcp_server


@asynccontextmanager
async def session_for(stub, **settings):
    """Yield an initialized MCP session backed by an isolated loopback FHIR stub."""
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
    """Run a disposable loopback recorder and close it after the test."""
    server = RecordingFhirServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def structured(result):
    """Assert text and structured MCP payloads agree, then return the structured result."""
    assert result.structuredContent == json.loads(result.content[0].text)
    return result.structuredContent


def get_bundle(kind="batch", url="Patient/123"):
    return {
        "resourceType": "Bundle",
        "type": kind,
        "entry": [{"request": {"method": "GET", "url": url}}],
    }


async def test_schema_and_annotations(stub):
    """execute_bundle is listed alongside the existing tools, with write annotations."""
    async with session_for(stub) as session:
        listed = {t.name: t for t in (await session.list_tools()).tools}
        assert {"create", "update", "delete", "execute_bundle"} <= listed.keys()
        tool = listed["execute_bundle"]
        assert tool.outputSchema["properties"]["status"]
        assert tool.inputSchema["properties"]["prefer"]["default"] == "representation"
        assert tool.annotations.destructiveHint and tool.annotations.openWorldHint
        assert not tool.annotations.readOnlyHint and not tool.annotations.idempotentHint


async def test_single_post_preserves_full_response_and_partial_batch(stub):
    """One Bundle POST retains nested results and repeated queries; a partly failed batch is
    reported through status, not isError.
    """
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
        assert not result.isError and data["status"] == "partial"
        assert data["error"]["kind"] == "batch-entry-failure"
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


async def test_validation_blocks_requests_with_positive_control(stub):
    """Reject invalid Bundles before HTTP, then prove a valid Bundle reaches the same stub."""
    stub.queue(
        200,
        {
            "resourceType": "Bundle",
            "type": "batch-response",
            "entry": [{"response": {"status": "200"}}],
        },
    )
    async with session_for(stub) as session:
        for url in [
            "https://example.invalid/Patient",
            "//other/Patient",
            "Patient/%252fadmin",
            "Patient/123?_summary=true",
        ]:
            result = await session.call_tool(
                "execute_bundle", {"bundle": get_bundle(url=url)}
            )
            assert result.isError
            assert structured(result)["error"]["kind"] == "validation"
        result = await session.call_tool(
            "execute_bundle", {"bundle": {**get_bundle(), "entry": []}}
        )
        assert result.isError and "at least one entry" in structured(result)["error"]["message"]
        assert stub.requests == []
        result = await session.call_tool("execute_bundle", {"bundle": get_bundle()})
        assert not result.isError and structured(result)["status"] == "success"
    assert len(stub.requests) == 1


async def test_unsupported_bundle_type(stub):
    """Report a null interaction and a clear message for Bundle types other than
    transaction or batch.
    """
    async with session_for(stub) as session:
        for mode in ["collection", "document", None]:
            result = await session.call_tool(
                "execute_bundle", {"bundle": get_bundle(kind=mode)}
            )
            body = structured(result)
            assert (
                result.isError
                and body["interaction"] is None
                and body["httpStatus"] is None
            )
            assert "Only transaction or batch" in body["error"]["message"]
        assert stub.requests == []


async def test_configured_entry_limit(stub):
    """Apply FHIR_MCP_MAX_BUNDLE_ENTRIES before sending anything."""
    bundle = get_bundle()
    bundle["entry"] *= 3
    async with session_for(stub, FHIR_MCP_MAX_BUNDLE_ENTRIES="2") as session:
        result = await session.call_tool("execute_bundle", {"bundle": bundle})
        assert result.isError
        assert structured(result)["error"]["message"] == "Too many Bundle entries."
    assert stub.requests == []


async def test_uncertain_pending_and_oversized_outcomes(stub):
    """Preserve unknown, pending and oversized response outcomes through MCP without
    marking them as errors, and reject oversized requests before sending.
    """
    args = {"bundle": get_bundle(kind="transaction")}
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
        assert not result.isError and structured(result)["status"] == "unknown"
        assert structured(result)["response"] == inconsistent
        result = await session.call_tool("execute_bundle", args)
        assert not result.isError and structured(result)["status"] == "pending"
        result = await session.call_tool("execute_bundle", args)
        assert structured(result)["status"] == "unknown"
        assert structured(result)["error"]["kind"] == "protocol"
        result = await session.call_tool("execute_bundle", args)
        data = structured(result)
        assert data["status"] == "unknown" and data["error"]["kind"] == "response-too-large"
        assert data["httpStatus"] == 200
        large = get_bundle()
        large["entry"] = [
            {
                "request": {"method": "POST", "url": "Patient"},
                "resource": {"resourceType": "Patient", "id": "x" * 600},
            }
        ]
        result = await session.call_tool("execute_bundle", {"bundle": large})
        assert result.isError and structured(result)["error"]["kind"] == "validation"
    assert len(stub.requests) == 4
