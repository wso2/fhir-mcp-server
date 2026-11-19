"""Offline regression tests for cleanup used by the live MCP tests."""

import asyncio
import json
from unittest.mock import AsyncMock, call

import pytest
from mcp.types import CallToolResult, TextContent

from tests.e2e import test_tools as live


@pytest.mark.parametrize("failure", [None, "setup", "assertion"])
async def test_resource_fixture_always_cleans_its_tag(monkeypatch, failure):
    cleanup = AsyncMock()
    monkeypatch.setattr(live, "delete_tagged", cleanup)
    fixture = live.resource_tag.__wrapped__(None)
    tag = await anext(fixture)
    try:
        if failure == "setup":
            monkeypatch.setattr(live, "call_tool", AsyncMock(side_effect=asyncio.TimeoutError))
            with pytest.raises(asyncio.TimeoutError):
                await live.patient_id.__wrapped__(tag)
        elif failure == "assertion":
            with pytest.raises(AssertionError, match="test failed"):
                await fixture.athrow(AssertionError("test failed"))
    finally:
        await fixture.aclose()
    cleanup.assert_awaited_once_with(tag)


async def test_cleanup_orders_deletions_and_verifies_absence(monkeypatch):
    search = AsyncMock(side_effect=[["o"], ["p"], [], []])
    delete = AsyncMock()
    monkeypatch.setattr(live, "tagged_ids", search)
    monkeypatch.setattr(live, "delete_resource", delete)
    assert await live.delete_tagged("run-tag") == ["Observation/o", "Patient/p"]
    assert delete.await_args_list == [call("Observation/o"), call("Patient/p")]
    assert search.await_args_list == [
        call("Observation", "run-tag"), call("Patient", "run-tag"),
        call("Observation", "run-tag"), call("Patient", "run-tag"),
    ]


async def test_cleanup_already_deleted_resources(monkeypatch):
    monkeypatch.setattr(live, "tagged_ids", AsyncMock(return_value=[]))
    delete = AsyncMock()
    monkeypatch.setattr(live, "delete_resource", delete)
    assert await live.delete_tagged("run-tag") == []
    delete.assert_not_awaited()


async def test_cleanup_detects_remaining_resources(monkeypatch):
    monkeypatch.setattr(live, "tagged_ids", AsyncMock(side_effect=[[], ["p"], [], ["p"]]))
    monkeypatch.setattr(live, "delete_resource", AsyncMock())
    with pytest.raises(AssertionError, match="remain after cleanup"):
        await live.delete_tagged("run-tag")


@pytest.mark.parametrize("status", [204, 404, 410, 500])
async def test_delete_accepts_absence_but_reports_server_failure(monkeypatch, status):
    data = {"response": {"entry": [{"response": {"status": str(status)}}]}}
    result = CallToolResult(
        content=[TextContent(type="text", text=json.dumps(data))],
        structuredContent=data,
    )
    monkeypatch.setattr(live, "call_tool_result", AsyncMock(return_value=result))
    if status == 500:
        with pytest.raises(AssertionError, match="Cleanup"):
            await live.delete_resource("Patient/owned")
    else:
        await live.delete_resource("Patient/owned")


@pytest.mark.parametrize("response", [
    {"resourceType": "OperationOutcome"},
    {"resourceType": "Bundle", "type": "searchset", "entry": None},
    {"resourceType": "Bundle", "type": "searchset",
     "link": [{"relation": "next", "url": "https://example.invalid/next"}]},
    {"resourceType": "Bundle", "type": "searchset", "entry": [
        {"resource": {"resourceType": "Observation", "id": "unrelated", "identifier": [
            {"system": live.TEST_IDENTIFIER_SYSTEM, "value": "different-run"}]}}]},
])
async def test_cleanup_rejects_unusable_or_unowned_search_results(monkeypatch, response):
    monkeypatch.setattr(live, "call_tool", AsyncMock(return_value=response))
    delete = AsyncMock()
    monkeypatch.setattr(live, "delete_resource", delete)
    with pytest.raises(AssertionError):
        await live.delete_tagged("run-tag")
    delete.assert_not_awaited()


async def test_search_selects_only_exact_test_identifier(monkeypatch):
    patient = live.tagged_patient("run-tag")
    patient["id"] = "owned"
    search = AsyncMock(return_value={
        "resourceType": "Bundle", "type": "searchset", "entry": [{"resource": patient}]
    })
    monkeypatch.setattr(live, "call_tool", search)
    assert await live.tagged_ids("Patient", "run-tag") == ["owned"]
    assert search.await_args.args[1]["searchParam"]["identifier"] == (
        live.TEST_IDENTIFIER_SYSTEM + "|run-tag"
    )
