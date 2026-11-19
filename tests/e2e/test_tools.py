# Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

import pytest
import json
import logging
import pytest_asyncio
import asyncio
import uuid

from typing import Dict
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from contextlib import asynccontextmanager

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - [MCP CLIENT] %(message)s",
)

logger: logging.Logger = logging.getLogger(__name__)


@asynccontextmanager
async def create_mcp_session():
    async with streamable_http_client("http://localhost:8001/mcp/") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


@pytest.mark.asyncio
async def test_tool_get_capabilities(mcp_server) -> None:
    request_payload: Dict[str, str] = {"type": "Patient"}
    logger.info(f"[TOOL REQUEST] get_capabilities: {request_payload}")
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="get_capabilities", arguments=request_payload
            )

            response: Dict = await extract_resource(tool_result)
            assert response.get("type") == "Patient", f"type is not Patient: {response}"
            assert response.get("searchParam"), f"searchParam is empty: {response}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for get_capabilities response from MCP server",
            exc_info=ex,
        )
        raise


@pytest_asyncio.fixture
async def resource_tag(mcp_server):
    tag = uuid.uuid4().hex
    logger.info("Live test resource identifier: %s", tag)
    try:
        yield tag
    finally:
        await delete_tagged(tag)


@pytest_asyncio.fixture
async def patient_id(resource_tag) -> str:
    response = await call_tool(
        "create", {"type": "Patient", "payload": tagged_patient(resource_tag)}
    )
    assert response.get("resourceType") == "Patient", f"Not a Patient: {response}"
    assert response.get("id"), f"Patient ID missing: {response}"
    assert response.get("gender") == "male", f"Unexpected Patient: {response}"
    return response["id"]


@pytest.mark.asyncio
async def test_tool_read(mcp_server, patient_id):
    request_payload = {"type": "Patient", "id": patient_id}
    logger.debug("[TEST REQUEST] read:", request_payload)
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="read", arguments=request_payload
            )

            response: Dict = await extract_resource(tool_result)
            assert (
                response is not None
                and response.get("resourceType") == "Patient"
                and response.get("id") == patient_id
                and response.get("gender") == "male"
            ), f"Invalid Patient resource in read result: {response}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for read response from MCP server",
            exc_info=ex,
        )
        raise


@pytest.mark.asyncio
async def test_tool_search(mcp_server, patient_id):
    request_payload = {"type": "Patient", "searchParam": {"_id": patient_id}}
    logger.debug("[TEST REQUEST] search:", request_payload)
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="search", arguments=request_payload
            )

            response: Dict = await extract_resource(tool_result)
            assert (
                response is not None
                and response.get("entry")[0].get("resource").get("resourceType") == "Patient"
                and response.get("entry")[0].get("resource").get("id") == patient_id
            ), f"No Patient resource in read result: {response}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for search response from MCP server",
            exc_info=ex,
        )
        raise


@pytest.mark.asyncio
async def test_tool_search_condition_count(mcp_server):
    request_payload = {
        "type": "Condition",
        "searchParam": {
            "code": "http://snomed.info/sct|204256004",
            "_summary": "count",
            "_total": "estimate"
        }
    }
    logger.info("[TEST REQUEST] search Condition count:", request_payload)
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="search", arguments=request_payload
            )
            response: Dict = await extract_resource(tool_result)
            assert response.get("resourceType") == "Bundle", f"Not a Bundle: {response}"
            assert response.get("type") == "searchset", f"Not a searchset: {response}"
            assert "total" in response, f"No total count in response: {response}"
            assert isinstance(response["total"], int), f"Total is not int: {response}"
            # Optionally check for SUBSETTED tag
            tags = response.get("meta", {}).get("tag", [])
            assert any(tag.get("code") == "SUBSETTED" for tag in tags), f"Missing SUBSETTED tag: {tags}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for Condition count search response from MCP server",
            exc_info=ex,
        )
        raise


@pytest.mark.asyncio
async def test_tool_update(mcp_server, patient_id):
    patient = await call_tool("read", {"type": "Patient", "id": patient_id})
    patient["gender"] = "female"
    request_payload = {"type": "Patient", "id": patient_id, "payload": patient}
    logger.debug("[TOOL REQUEST] update:", request_payload)
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="update", arguments=request_payload
            )

            response: Dict = await extract_resource(tool_result)
            assert (
                response is not None
                and response.get("resourceType") == "Patient"
                and response.get("id") == patient_id
                and response.get("gender") == "female"
            ), f"Patient resource is not updated: {response}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for create response from MCP server",
            exc_info=ex,
        )
        raise


@pytest.mark.asyncio
async def test_tool_delete(mcp_server, patient_id):
    request_payload = {"type": "Patient", "id": patient_id}
    logger.debug("[TOOL REQUEST] delete:", request_payload)
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="delete", arguments=request_payload
            )
            response: Dict = await extract_resource(tool_result)
            assert response is not None, f"Delete operation failed: {response}"

            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="read", arguments=request_payload
            )
            response: Dict = await extract_resource(tool_result)
            assert (
                response is not None
                and response.get("resourceType") == "OperationOutcome"
                and not response.get("id")
            ), f"Patient resource is not deleted: {response}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for create response from MCP server",
            exc_info=ex,
        )
        raise


# ---------------------------------------------------------------------------
# Live execute_bundle tests against public HAPI FHIR
#
# Each test tags its resources with a unique identifier and deletes them
# afterwards, so reruns and concurrent runs do not interfere.
# ---------------------------------------------------------------------------

TEST_IDENTIFIER_SYSTEM = "urn:fhir-mcp-server:e2e"


def tagged_patient(tag: str) -> Dict:
    return {
        "resourceType": "Patient",
        "identifier": [{"system": TEST_IDENTIFIER_SYSTEM, "value": tag}],
        "gender": "male",
        "name": [{"family": f"TestFamily-{tag}"}],
    }


def tagged_observation(tag: str, subject_reference: str) -> Dict:
    return {
        "resourceType": "Observation",
        "identifier": [{"system": TEST_IDENTIFIER_SYSTEM, "value": tag}],
        "status": "final",
        "code": {"text": f"Test observation {tag}"},
        "subject": {"reference": subject_reference},
    }


def entry_status(entry: Dict) -> int:
    """Return the numeric status of a response Bundle entry, e.g. 201 from '201 Created'."""
    return int(entry["response"]["status"].split()[0])


def entry_id(entry: Dict) -> str:
    """Return the logical id from a response entry's location, e.g. 'Patient/1/_history/1'."""
    return entry["response"]["location"].split("/")[1]


async def call_tool_result(tool: str, arguments: Dict) -> types.CallToolResult:
    """Call a tool and return the raw result, including results with isError set."""
    logger.debug(f"[TEST REQUEST] {tool}: {arguments}")
    async with create_mcp_session() as mcp_session:
        return await mcp_session.call_tool(name=tool, arguments=arguments)


def structured(tool_result: types.CallToolResult) -> Dict:
    """Assert the text and structured payloads agree, then return the structured result."""
    assert tool_result.structuredContent == json.loads(tool_result.content[0].text)
    return tool_result.structuredContent


async def delete_resource(reference: str) -> None:
    """Delete one test resource and confirm the server accepted the deletion."""
    bundle = {
        "resourceType": "Bundle",
        "type": "batch",
        "entry": [{"request": {"method": "DELETE", "url": reference}}],
    }
    result = structured(await call_tool_result("execute_bundle", {"bundle": bundle}))
    status = entry_status(result["response"]["entry"][0])
    assert 200 <= status < 300 or status in (404, 410), (
        f"Cleanup of {reference} failed: {result}"
    )


async def tagged_ids(resource_type: str, tag: str) -> list[str]:
    """Find only resources carrying this test's exact identifier; fail on invalid searches."""
    response = await call_tool(
        "search",
        {"type": resource_type, "searchParam": {
            "identifier": f"{TEST_IDENTIFIER_SYSTEM}|{tag}", "_count": "100"
        }},
    )
    assert response.get("resourceType") == "Bundle" and response.get("type") == "searchset", (
        f"Cleanup search failed for {resource_type}"
    )
    assert not any(link.get("relation") == "next" for link in response.get("link", [])), (
        "Cleanup search was paginated; refusing incomplete cleanup"
    )
    entries = response.get("entry", [])
    assert isinstance(entries, list), "Invalid cleanup search entries"
    identifiers = []
    for entry in entries:
        resource = entry.get("resource", {})
        assert resource.get("resourceType") == resource_type and resource.get("id"), (
            "Unexpected resource in cleanup search"
        )
        assert any(
            identifier.get("system") == TEST_IDENTIFIER_SYSTEM
            and identifier.get("value") == tag
            for identifier in resource.get("identifier", [])
        ), "Refusing to delete a resource without the exact test identifier"
        identifiers.append(resource["id"])
    return identifiers


async def delete_tagged(tag: str) -> list[str]:
    """Find and delete every resource carrying the test tag, Observations before Patients.

    Each deletion is a separate request that completes before the next starts, so a
    Patient is deleted only after the Observations referencing it are gone. Returns
    the references that were found.
    """
    found = [f"Observation/{id}" for id in await tagged_ids("Observation", tag)]
    found += [f"Patient/{id}" for id in await tagged_ids("Patient", tag)]
    for reference in found:
        await delete_resource(reference)
    remaining = {
        kind: await tagged_ids(kind, tag) for kind in ("Observation", "Patient")
    }
    assert not any(remaining.values()), f"Test resources remain after cleanup: {remaining}"
    return found


@pytest.mark.asyncio
async def test_tool_execute_bundle_transaction(mcp_server, resource_tag):
    tag = resource_tag
    patient_urn = f"urn:uuid:{uuid.uuid4()}"
    bundle = {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "fullUrl": patient_urn,
                "resource": tagged_patient(tag),
                "request": {"method": "POST", "url": "Patient"},
            },
            {
                "resource": tagged_observation(tag, patient_urn),
                "request": {"method": "POST", "url": "Observation"},
            },
        ],
    }
    tool_result = await call_tool_result("execute_bundle", {"bundle": bundle})
    result = structured(tool_result)
    assert not tool_result.isError, f"Transaction failed: {result}"
    assert result["interaction"] == "transaction"
    assert result["status"] == "success"
    assert result["httpStatus"] == 200
    assert result["response"]["type"] == "transaction-response"

    entries = result["response"]["entry"]
    assert [entry_status(e) for e in entries] == [201, 201], f"Unexpected statuses: {result}"
    patient_id, observation_id = entry_id(entries[0]), entry_id(entries[1])

    # The server resolved the urn:uuid reference to the new Patient.
    observation = await call_tool("read", {"type": "Observation", "id": observation_id})
    assert observation["subject"]["reference"] == f"Patient/{patient_id}"


@pytest.mark.asyncio
async def test_tool_execute_bundle_transaction_rolls_back(mcp_server, resource_tag):
    tag = resource_tag
    bundle = {
        "resourceType": "Bundle",
        "type": "transaction",
        "entry": [
            {
                "resource": tagged_patient(tag),
                "request": {"method": "POST", "url": "Patient"},
            },
            # The Observation refers to a deliberately nonexistent Patient.
            {
                "resource": tagged_observation(tag, f"Patient/missing-{tag[:16]}"),
                "request": {"method": "POST", "url": "Observation"},
            },
        ],
    }
    tool_result = await call_tool_result("execute_bundle", {"bundle": bundle})
    result = structured(tool_result)
    assert tool_result.isError, f"Transaction unexpectedly succeeded: {result}"
    assert result["status"] == "failure"
    assert result["httpStatus"] >= 400
    assert not await tagged_ids("Observation", tag), "Failed transaction left an Observation"
    assert not await tagged_ids("Patient", tag), "Failed transaction left a Patient"


@pytest.mark.asyncio
async def test_tool_execute_bundle_batch_partial(mcp_server, resource_tag):
    tag = resource_tag
    bundle = {
        "resourceType": "Bundle",
        "type": "batch",
        "entry": [
            {
                "resource": tagged_patient(tag),
                "request": {"method": "POST", "url": "Patient"},
            },
            {"request": {"method": "GET", "url": f"Patient/missing-{tag[:16]}"}},
        ],
    }
    tool_result = await call_tool_result("execute_bundle", {"bundle": bundle})
    result = structured(tool_result)
    entries = result["response"]["entry"]
    assert result["interaction"] == "batch"
    assert result["httpStatus"] == 200
    assert result["status"] == "partial", f"Expected a partial batch: {result}"
    # A partial batch is reported through status, not isError, so that clients that
    # retry errored calls do not replay the entry that succeeded.
    assert not tool_result.isError
    assert [entry_status(e) for e in entries] == [201, 404], f"Unexpected statuses: {result}"
    assert result["summary"]["succeeded"] == 1 and result["summary"]["failed"] == 1


async def extract_resource(tool_result: types.CallToolResult) -> Dict:
    logger.debug(f"[TOOL RESULT] : {tool_result!r}")
    assert tool_result is not None
    assert not tool_result.isError
    assert tool_result.content, "No content in the tool result"

    text: str | None = None
    for content in tool_result.content:
        if isinstance(content, types.TextContent) and getattr(content, "text", None):
            text = content.text
            break
    assert text, "No text content in tool_result"

    return json.loads(text)


# ---------------------------------------------------------------------------
# Path-traversal regression tests
#
# These use the same MCP client -> MCP server -> FHIR tool path as the tests
# above, but the MCP server is started against a local recording FHIR stub
# (`mcp_server_with_recording_fhir`) instead of the live public server. The MCP
# server runs in a separate process, so the stub is the boundary at which
# "was an outbound FHIR request made?" can be observed.
#
# `tests/unit/test_utils.py::TestPathParameterValidation` already covers which
# ids and operations the validators accept. What these tests add is that each
# guarded tool actually *calls* those validators, and does so *before* any
# request reaches the FHIR server.
# ---------------------------------------------------------------------------

# `read`, `update` and `delete` interpolate an id into the request path;
# `create` has no id, so only its operation is guarded.
ID_GUARDED_TOOLS = ["read", "update", "delete"]
OPERATION_GUARDED_TOOLS = ["read", "update", "delete", "create"]

SAMPLE_PAYLOAD = {"resourceType": "Patient", "gender": "male"}
VALID_ID = "123"

EXPECTED_METHOD = {"read": "GET", "create": "POST", "update": "PUT", "delete": "DELETE"}


def build_arguments(tool: str, id: str = VALID_ID, operation: str = "") -> Dict:
    """Build the minimum valid argument set for a tool, less what's under test."""
    arguments: Dict = {"type": "Patient"}
    if tool in ID_GUARDED_TOOLS:
        arguments["id"] = id
    if tool in ("create", "update"):
        arguments["payload"] = SAMPLE_PAYLOAD
    if operation:
        arguments["operation"] = operation
    return arguments


def assert_is_invalid_outcome(resource: Dict) -> None:
    assert (
        resource.get("resourceType") == "OperationOutcome"
    ), f"Expected an OperationOutcome, got: {resource}"

    issues = resource.get("issue") or []
    assert issues, f"OperationOutcome carried no issue: {resource}"
    assert any(
        issue.get("severity") == "error" and issue.get("code") == "invalid"
        for issue in issues
    ), f"Expected an error/invalid issue, got: {issues}"


async def call_tool(tool: str, arguments: Dict) -> Dict:
    logger.debug(f"[TEST REQUEST] {tool}: {arguments}")
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name=tool, arguments=arguments
            )
            return await extract_resource(tool_result)
    except asyncio.TimeoutError as ex:
        logger.error(
            f"[TOOL RESPONSE] Timeout waiting for {tool} response from MCP server",
            exc_info=ex,
        )
        raise



@pytest.mark.asyncio
@pytest.mark.parametrize("tool", ID_GUARDED_TOOLS)
@pytest.mark.parametrize(
    "traversing_id",
    [
        # Satisfies the FHIR spec's own id regex ([A-Za-z0-9\-\.]{1,64}) and is
        # caught only by the explicit dot-segment check.
        pytest.param("..", id="bare-dot-segment"),
        pytest.param("../../etc/passwd", id="relative-traversal"),
        pytest.param("%2e%2e%2fPatient", id="percent-encoded-traversal"),
    ],
)
async def test_traversing_id_is_blocked_before_any_http_request(
    mcp_server_with_recording_fhir, tool, traversing_id
):
    fhir_requests = mcp_server_with_recording_fhir.requests

    response: Dict = await call_tool(tool, build_arguments(tool, id=traversing_id))

    assert_is_invalid_outcome(response)
    assert fhir_requests == [], (
        f"'{tool}' with traversing id {traversing_id!r} made "
        f"outbound FHIR request(s): {fhir_requests}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", OPERATION_GUARDED_TOOLS)
async def test_traversing_operation_is_blocked_before_any_http_request(
    mcp_server_with_recording_fhir, tool
):
    fhir_requests = mcp_server_with_recording_fhir.requests

    response: Dict = await call_tool(
        tool, build_arguments(tool, operation="../../../metadata")
    )

    assert_is_invalid_outcome(response)
    assert fhir_requests == [], (
        f"'{tool}' with traversing operation made "
        f"outbound FHIR request(s): {fhir_requests}"
    )


@pytest.mark.asyncio
@pytest.mark.parametrize("tool", OPERATION_GUARDED_TOOLS)
async def test_valid_input_reaches_the_fhir_server(
    mcp_server_with_recording_fhir, tool
):
    """Guards the two tests above against passing vacuously.

    Well-formed input must still reach the FHIR server. If this fails, the
    stub is no longer observing that tool's requests and its "no request was
    made" assertions prove nothing.
    """
    fhir_requests = mcp_server_with_recording_fhir.requests

    await call_tool(tool, build_arguments(tool))

    assert len(fhir_requests) == 1, (
        f"Expected exactly one outbound FHIR request from '{tool}', "
        f"recorded: {fhir_requests}"
    )

    method, path = fhir_requests[0]
    assert method == EXPECTED_METHOD[tool], (
        f"Expected a {EXPECTED_METHOD[tool]} from '{tool}', got {method}"
    )

    expected_path = "/Patient" if tool == "create" else f"/Patient/{VALID_ID}"
    assert path.startswith(expected_path), f"Unexpected request path: {path}"
