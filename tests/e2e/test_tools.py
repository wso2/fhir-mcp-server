# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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
async def patient_id(mcp_server) -> str | None:
    suffix = uuid.uuid4().hex[:8]
    request_payload = {
        "type": "Patient",
        "payload": {
            "resourceType": "Patient",
            "gender": "male",
            "name": {
                "family": f"TestFamily-{suffix}",
                "given": [f"TestGiven-{suffix}"],
            },
        },
    }
    logger.debug("[TOOL REQUEST] create:", request_payload)
    try:
        async with create_mcp_session() as mcp_session:
            tool_result: types.CallToolResult = await mcp_session.call_tool(
                name="create", arguments=request_payload
            )

            response: Dict = await extract_resource(tool_result)
            assert (
                response.get("resourceType") == "Patient"
            ), f"type is not Patient: {response}"
            assert response.get("id"), f"id is missing in Patient resource: {response}"
            assert (
                response.get("gender") == "male"
            ), f"gender field is invalid in Patient resource: {response}"
            return response.get("id")
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for create response from MCP server",
            exc_info=ex,
        )
        raise


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
    request_payload = {
        "type": "Patient",
        "id": patient_id,
        "payload": {
            "resourceType": "Patient",
            "gender": "female",
            "name": {"family": "TestFamily", "given": ["TestGiven"]},
        },
    }
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
