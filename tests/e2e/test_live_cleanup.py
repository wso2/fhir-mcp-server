"""Offline checks that live-test cleanup deletes only owned resources and reports failure."""

from unittest.mock import AsyncMock

import pytest

from tests.e2e import test_tools as live


@pytest.mark.parametrize("severity", ["information", "error", "fatal", None])
async def test_cleanup_uses_delete_and_checks_outcome(monkeypatch, severity):
    delete = AsyncMock(return_value={
        "resourceType": "OperationOutcome", "issue": [{"severity": severity}]
    })
    monkeypatch.setattr(live, "call_tool", delete)
    if severity == "information":
        await live.delete_resource("Patient/owned")
    else:
        with pytest.raises(AssertionError, match="Cleanup"):
            await live.delete_resource("Patient/owned")
    delete.assert_awaited_once_with("delete", {"type": "Patient", "id": "owned"})


async def test_cleanup_detects_remaining_resources(monkeypatch):
    monkeypatch.setattr(live, "tagged_ids", AsyncMock(side_effect=[[], ["p"], [], ["p"]]))
    monkeypatch.setattr(live, "delete_resource", AsyncMock())
    with pytest.raises(AssertionError, match="remain after cleanup"):
        await live.delete_tagged("run-tag")


@pytest.mark.parametrize("tag", ["run-tag", "different-run"])
async def test_cleanup_checks_exact_ownership_before_deleting(monkeypatch, tag):
    patient = live.tagged_patient(tag)
    patient["id"] = "owned"
    search = AsyncMock(side_effect=[
        {"resourceType": "Bundle", "type": "searchset"},
        {"resourceType": "Bundle", "type": "searchset", "entry": [{"resource": patient}]},
        {"resourceType": "Bundle", "type": "searchset"},
        {"resourceType": "Bundle", "type": "searchset"},
    ])
    delete = AsyncMock()
    monkeypatch.setattr(live, "call_tool", search)
    monkeypatch.setattr(live, "delete_resource", delete)
    if tag == "run-tag":
        assert await live.delete_tagged("run-tag") == ["Patient/owned"]
        delete.assert_awaited_once_with("Patient/owned")
    else:
        with pytest.raises(AssertionError, match="exact test identifier"):
            await live.delete_tagged("run-tag")
        delete.assert_not_awaited()
    assert search.await_args_list[1].args[1]["searchParam"]["identifier"] == (
        live.TEST_IDENTIFIER_SYSTEM + "|run-tag"
    )
