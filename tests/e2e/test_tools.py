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


@asynccontextmanager
async def create_mcp_session_token_efficient():
    async with streamablehttp_client("http://localhost:8002/mcp/") as (read, write, _):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session


def extract_token_efficient_text(tool_result: types.CallToolResult) -> str:
    """Return raw text from a token-efficient tool result and assert it is not JSON."""
    assert tool_result is not None
    assert not tool_result.isError
    text = next(
        (c.text for c in tool_result.content if isinstance(c, types.TextContent) and c.text),
        None,
    )
    assert text, "No text content in token-efficient tool_result"
    with pytest.raises(json.JSONDecodeError):
        json.loads(text)
    return text


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
            "name": [{"prefix": ["Mr."], "family": f"TestFamily-{suffix}", "given": ["TestGiven"]}],
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
        },
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


@pytest_asyncio.fixture
async def te_patient(mcp_server_token_efficient) -> tuple[str, str] | None:
    """Create a Patient via the token-efficient server and return (id, compacted_name)."""
    suffix = uuid.uuid4().hex[:8]
    family = f"TestFamily-{suffix}"
    given, prefix = "TestGiven", "Mr."
    async with create_mcp_session_token_efficient() as session:
        tool_result = await session.call_tool("create", {
            "type": "Patient",
            "payload": {
                "resourceType": "Patient",
                "gender": "male",
                "name": [{"prefix": [prefix], "family": family, "given": [given]}],
            },
        })
        text = extract_token_efficient_text(tool_result)
        compacted_name = f"{prefix} {given} {family}"
        assert compacted_name in text, f"Compacted name missing from create response: {text[:300]}"
        # extract id from "id: <value>" line
        pid = next(
            line.split(": ", 1)[1].strip().strip('"')
            for line in text.splitlines()
            if line.startswith("id: ")
        )
        return pid, compacted_name


class TestTokenEfficientOutput:
    """
    Verifies the three properties of token-efficient output mode:
      1. Toon format  — key: value syntax, not JSON
      2. Metadata stripped — 'meta' and 'text' fields absent
      3. Complex types compacted — HumanName flattened to a single string
    """

    @pytest.mark.asyncio
    async def test_get_capabilities(self, mcp_server_token_efficient) -> None:
        logger.info("[TOOL REQUEST] token-efficient get_capabilities: Patient")
        async with create_mcp_session_token_efficient() as session:
            tool_result = await session.call_tool("get_capabilities", {"type": "Patient"})
            text = extract_token_efficient_text(tool_result)
            # toon format
            assert "type: Patient" in text, f"Missing 'type: Patient': {text[:300]}"
            assert "searchParam" in text, f"Missing searchParam: {text[:300]}"
            # no JSON braces/brackets at the top level
            assert not text.strip().startswith("{"), f"Output looks like JSON: {text[:300]}"

    @pytest.mark.asyncio
    async def test_create(self, te_patient) -> None:
        pid, compacted_name = te_patient
        logger.info(f"[TOOL REQUEST] token-efficient create verified: Patient/{pid}")
        # Fixture already asserts create output — just verify the returned values are usable
        assert pid, "Patient ID missing"
        assert compacted_name.startswith("Mr."), f"Unexpected compacted name: {compacted_name}"

    @pytest.mark.asyncio
    async def test_search(self, mcp_server_token_efficient, te_patient) -> None:
        pid, compacted_name = te_patient
        logger.info(f"[TOOL REQUEST] token-efficient search: Patient _id={pid}")
        async with create_mcp_session_token_efficient() as session:
            tool_result = await session.call_tool("search", {
                "type": "Patient",
                "searchParam": {"_id": pid},
            })
            text = extract_token_efficient_text(tool_result)
            # toon format — Bundle with entry list
            assert "resourceType: Bundle" in text, f"Missing Bundle: {text[:300]}"
            assert "entry[" in text, f"Entry list not in toon format: {text[:300]}"
            assert pid in text, f"Patient ID not found: {text[:300]}"
            # HumanName compacted
            assert compacted_name in text, f"Compacted name not found: {text[:300]}"
            # metadata stripped
            assert "meta:" not in text, f"meta should be stripped: {text[:300]}"

    @pytest.mark.asyncio
    async def test_read(self, mcp_server_token_efficient, te_patient) -> None:
        pid, compacted_name = te_patient
        logger.info(f"[TOOL REQUEST] token-efficient read: Patient/{pid}")
        async with create_mcp_session_token_efficient() as session:
            tool_result = await session.call_tool("read", {"type": "Patient", "id": pid})
            text = extract_token_efficient_text(tool_result)
            # toon format
            assert "resourceType: Patient" in text, f"Missing resourceType: {text[:300]}"
            assert pid in text, f"Missing id: {text[:300]}"
            assert "gender: male" in text, f"Missing gender: {text[:300]}"
            # HumanName compacted
            assert compacted_name in text, f"Compacted name not found: {text[:300]}"
            # metadata stripped
            assert "meta:" not in text, f"meta should be stripped: {text[:300]}"
            assert "\ntext:" not in text, f"text should be stripped: {text[:300]}"

    @pytest.mark.asyncio
    async def test_update(self, mcp_server_token_efficient, te_patient) -> None:
        pid, _ = te_patient
        logger.info(f"[TOOL REQUEST] token-efficient update: Patient/{pid}")
        async with create_mcp_session_token_efficient() as session:
            tool_result = await session.call_tool("update", {
                "type": "Patient",
                "id": pid,
                "payload": {
                    "resourceType": "Patient",
                    "gender": "female",
                    "name": [{"prefix": ["Ms."], "family": "TestFamily", "given": ["TestGiven"]}],
                },
            })
            text = extract_token_efficient_text(tool_result)
            # toon format + updated fields
            assert "resourceType: Patient" in text, f"Missing resourceType: {text[:300]}"
            assert "gender: female" in text, f"Gender not updated: {text[:300]}"
            # HumanName compacted with new prefix
            assert "name[1]: Ms. TestGiven TestFamily" in text, f"Name not compacted: {text[:300]}"
            # metadata stripped
            assert "meta:" not in text, f"meta should be stripped: {text[:300]}"

    @pytest.mark.asyncio
    async def test_delete(self, mcp_server_token_efficient, te_patient) -> None:
        pid, _ = te_patient
        logger.info(f"[TOOL REQUEST] token-efficient delete: Patient/{pid}")
        async with create_mcp_session_token_efficient() as session:
            tool_result = await session.call_tool("delete", {"type": "Patient", "id": pid})
            text = extract_token_efficient_text(tool_result)
            assert text is not None, "Delete returned no output"

            # Verify deleted — read should return an OperationOutcome in toon format
            tool_result = await session.call_tool("read", {"type": "Patient", "id": pid})
            text = extract_token_efficient_text(tool_result)
            assert "resourceType: OperationOutcome" in text, f"Expected OperationOutcome after delete: {text[:300]}"
            assert "meta:" not in text, f"meta should be stripped from OperationOutcome: {text[:300]}"


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
