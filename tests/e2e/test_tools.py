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

from typing import Dict
import mcp.types as types
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from contextlib import asynccontextmanager

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - [MCP CLIENT] %(message)s",
)

logger: logging.Logger = logging.getLogger(__name__)


@asynccontextmanager
async def create_mcp_session():
    async with streamablehttp_client("http://localhost:8001/mcp/") as (read, write, _):
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
    request_payload = {
        "type": "Patient",
        "payload": {
            "resourceType": "Patient",
            "gender": "male",
            "name": {"family": "TestFamily", "given": ["TestGiven"]},
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
                and response.get("resourceType") == "Patient"
                and response.get("id") == patient_id
            ), f"No Patient resource in read result: {response}"
    except asyncio.TimeoutError as ex:
        logger.error(
            "[TOOL RESPONSE] Timeout waiting for search response from MCP server",
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
            assert response is not None, f"Delete operation failed: {delete_response}"

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
