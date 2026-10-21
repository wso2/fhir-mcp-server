"""Opt-in MCP acceptance against a disposable Aidbox sandbox, never public HAPI."""

import json
import os
from urllib.parse import urlsplit
from uuid import uuid4

import httpx
import pytest
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

from tests.e2e.conftest import run_mcp_server

pytestmark = pytest.mark.skipif(
    os.getenv("FHIR_TEST_AIDBOX_ENABLE") != "true",
    reason="Requires explicit Aidbox sandbox opt-in, URL and restricted token.",
)


def transaction(entries, kind="transaction"):
    return {"resourceType": "Bundle", "type": kind, "entry": entries}


def put(resource):
    return {
        "request": {
            "method": "PUT",
            "url": resource["resourceType"] + "/" + resource["id"],
        },
        "resource": resource,
    }


def parameters_patch(resource_id, value):
    return {
        "request": {"method": "PATCH", "url": "Patient/" + resource_id},
        "resource": {
            "resourceType": "Parameters",
            "parameter": [
                {
                    "name": "operation",
                    "part": [
                        {"name": "type", "valueCode": "replace"},
                        {"name": "path", "valueString": "Patient.active"},
                        {"name": "value", "valueBoolean": value},
                    ],
                }
            ],
        },
    }


async def test_aidbox_bundle_patch_acceptance():
    base = os.environ.get("FHIR_TEST_AIDBOX_URL", "").rstrip("/")
    token = os.environ.get("FHIR_TEST_AIDBOX_TOKEN", "")
    if not base or not token:
        pytest.fail("Set FHIR_TEST_AIDBOX_URL and FHIR_TEST_AIDBOX_TOKEN explicitly.")
    parsed = urlsplit(base)
    if parsed.scheme not in ("http", "https") or parsed.hostname in (
        "hapi.fhir.org",
        "server.fire.ly",
    ):
        pytest.fail(
            "Use a dedicated Aidbox sandbox, never a public demonstration server."
        )
    if (
        parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or not base.endswith("/fhir")
    ):
        pytest.fail("Expected a credential-free Aidbox URL ending in /fhir.")
    native = base[:-5]
    run_id = "mcp-accept-" + uuid4().hex
    patient_id, observation_id = run_id + "-p", run_id + "-o"
    cleanup = [("Patient", patient_id), ("Observation", observation_id)]
    evidence = {}
    async with httpx.AsyncClient(
        headers={"Authorization": "Bearer " + token},
        timeout=30,
        follow_redirects=False,
        trust_env=False,
    ) as http:
        # Verify the dedicated client's boundaries before any successful clinical write.
        for resource in ("Client", "AccessPolicy", "User"):
            denied = await http.put(
                native + "/" + resource + "/" + run_id,
                json={"resourceType": resource, "id": run_id},
            )
            if denied.status_code != 403:
                pytest.fail(
                    "Sandbox identity unexpectedly permits administrative writes."
                )
        denied = await http.put(
            base + "/Condition/" + run_id,
            json={"resourceType": "Condition", "id": run_id},
        )
        if denied.status_code != 403:
            pytest.fail(
                "Sandbox identity must exclude Condition writes for these tests."
            )
        metadata = (await http.get(base + "/metadata")).json()
        evidence["server"] = metadata.get("software", {})
        try:
            async with run_mcp_server(
                base,
                settings={
                    "FHIR_SERVER_ACCESS_TOKEN": token,
                    "FHIR_MCP_ENABLE_WRITE_TOOLS": "True",
                },
            ):
                async with streamable_http_client("http://localhost:8001/mcp/") as (
                    read,
                    write,
                    _,
                ):
                    async with ClientSession(read, write) as session:
                        await session.initialize()

                        async def execute(
                            entries, kind="transaction", prefer="representation"
                        ):
                            result = await session.call_tool(
                                "execute_bundle",
                                {
                                    "bundle": transaction(entries, kind),
                                    "prefer": prefer,
                                },
                            )
                            assert result.structuredContent == json.loads(
                                result.content[0].text
                            )
                            return result, result.structuredContent

                        async def read_patient(pid=patient_id):
                            return await http.get(base + "/Patient/" + pid)

                        patient = {
                            "resourceType": "Patient",
                            "id": patient_id,
                            "active": True,
                            "identifier": [
                                {"system": "urn:fhir-mcp:acceptance", "value": run_id}
                            ],
                        }
                        full_url = "urn:uuid:" + str(uuid4())
                        patient_entry = put(patient)
                        patient_entry["fullUrl"] = full_url
                        observation = {
                            "resourceType": "Observation",
                            "id": observation_id,
                            "status": "final",
                            "code": {"text": "Synthetic acceptance check"},
                            "subject": {"reference": full_url},
                        }
                        result, data = await execute([patient_entry, put(observation)])
                        assert not result.isError and data["status"] == "success"
                        observed = (
                            await http.get(base + "/Observation/" + observation_id)
                        ).json()
                        assert observed["subject"]["reference"].endswith(
                            "Patient/" + patient_id
                        )
                        evidence["linked_transaction"] = data["httpStatus"]

                        forbidden = {
                            "request": {"method": "GET", "url": "Condition?_count=0"}
                        }
                        for kind in ("transaction", "batch"):
                            pid = run_id + (
                                "-rollback" if kind == "transaction" else "-batch"
                            )
                            cleanup.append(("Patient", pid))
                            result, data = await execute(
                                [
                                    put(
                                        {
                                            "resourceType": "Patient",
                                            "id": pid,
                                            "active": True,
                                        }
                                    ),
                                    forbidden,
                                ],
                                kind,
                            )
                            assert result.isError
                            existing = await read_patient(pid)
                            if kind == "transaction":
                                assert (
                                    data["status"] == "failure"
                                    and existing.status_code == 404
                                )
                            else:
                                assert (
                                    data["status"] == "partial"
                                    and data["summary"]["succeeded"] == 1
                                )
                                assert existing.status_code == 200
                            evidence[kind + "_failure"] = data["httpStatus"]

                        # Conditional POST retries should find the same uniquely identified Patient.
                        conditional = {
                            "request": {
                                "method": "POST",
                                "url": "Patient",
                                "ifNoneExist": "identifier=urn:fhir-mcp:acceptance%7C"
                                + run_id,
                            },
                            "resource": {k: v for k, v in patient.items() if k != "id"},
                        }
                        for _ in range(2):
                            result, _data = await execute([conditional])
                            assert not result.isError
                        matches = (
                            await http.get(
                                base + "/Patient",
                                params={
                                    "identifier": "urn:fhir-mcp:acceptance|" + run_id
                                },
                            )
                        ).json()
                        for match in matches.get("entry", []):
                            cleanup.append(("Patient", match["resource"]["id"]))
                        assert len(matches.get("entry", [])) == 1

                        original = await read_patient()
                        etag = original.headers["etag"]
                        args = {
                            "type": "Patient",
                            "id": patient_id,
                            "if_match": etag,
                            "payload": [
                                {"op": "replace", "path": "/active", "value": False}
                            ],
                        }
                        result = await session.call_tool("patch", args)
                        data = result.structuredContent
                        assert not result.isError and data["headers"]["etag"] != etag
                        current = (await read_patient()).json()
                        assert (
                            current["active"] is False
                            and current["identifier"] == patient["identifier"]
                        )
                        args["payload"][0]["value"] = True
                        stale = await session.call_tool("patch", args)
                        assert (
                            stale.isError
                            and stale.structuredContent["httpStatus"] == 412
                        )
                        assert (await read_patient()).json()["active"] is False
                        evidence["stale_if_match"] = stale.structuredContent[
                            "httpStatus"
                        ]

                        result = await session.call_tool(
                            "patch",
                            {
                                "type": "Patient",
                                "id": patient_id,
                                "payload": [
                                    {"op": "test", "path": "/active", "value": True},
                                    {"op": "replace", "path": "/active", "value": True},
                                ],
                            },
                        )
                        assert (
                            result.isError
                            and (await read_patient()).json()["active"] is False
                        )
                        evidence["failed_patch_test"] = result.structuredContent[
                            "httpStatus"
                        ]

                        result, data = await execute(
                            [parameters_patch(patient_id, True)]
                        )
                        evidence["parameters_patch"] = data["httpStatus"]
                        assert (
                            not result.isError
                            and (await read_patient()).json()["active"] is True
                        )
                        result, data = await execute(
                            [parameters_patch(patient_id, False), forbidden]
                        )
                        assert (
                            result.isError
                            and (await read_patient()).json()["active"] is True
                        )

                        result = await session.call_tool(
                            "patch",
                            {
                                "type": "Patient",
                                "id": patient_id,
                                "prefer": "minimal",
                                "payload": [
                                    {"op": "replace", "path": "/active", "value": False}
                                ],
                            },
                        )
                        data = result.structuredContent
                        assert (
                            not result.isError
                            and (await read_patient()).json()["active"] is False
                        )
                        evidence["minimal_patch"] = {
                            "status": data["httpStatus"],
                            "has_body": data["response"] is not None,
                        }
                        result, data = await execute(
                            [
                                {
                                    "request": {
                                        "method": "GET",
                                        "url": "Patient/" + patient_id,
                                    }
                                }
                            ],
                            "batch",
                            "minimal",
                        )
                        assert not result.isError
                        evidence["minimal_batch_get_has_resource"] = (
                            "resource" in data["response"]["entry"][0]
                        )
                        # Characterize the server's preference behavior; do not fabricate missing content.
                        result, data = await execute(
                            [
                                {
                                    "request": {
                                        "method": "GET",
                                        "url": "Patient/" + patient_id,
                                    }
                                }
                            ],
                            "batch",
                        )
                        assert (
                            not result.isError
                            and data["response"]["entry"][0]["resource"]["id"]
                            == patient_id
                        )
        finally:
            # Dependents first; delete only IDs belonging to this run.
            for resource_type, resource_id in sorted(
                set(cleanup), key=lambda item: item[0] == "Patient"
            ):
                response = await http.get(
                    base + "/" + resource_type + "/" + resource_id
                )
                if response.status_code == 200:
                    deleted = await http.delete(
                        base + "/" + resource_type + "/" + resource_id
                    )
                    assert deleted.status_code in (200, 204)
                absent = await http.get(base + "/" + resource_type + "/" + resource_id)
                assert absent.status_code in (404, 410)
    print("Aidbox acceptance evidence:", json.dumps(evidence, sort_keys=True))
