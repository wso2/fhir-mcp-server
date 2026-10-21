import socket

import pytest

from fhir_mcp_server.fhir_http import send_fhir_request
from fhir_mcp_server.interactions import FhirTransportError
from fhir_mcp_server.oauth import ServerConfigs
from fhir_mcp_server.utils import get_capability_statement
from tests.e2e.conftest import RecordingFhirServer


@pytest.fixture
def stub():
    server = RecordingFhirServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def config(stub, **kwargs):
    return ServerConfigs(
        _env_file=None, server_base_url=stub.base_url + "/tenant/fhir/", **kwargs
    )


async def test_exact_requests_header_isolation_and_response_allowlist(stub):
    stub.queue(
        204,
        headers={
            "ETag": 'W/"2"',
            "Set-Cookie": "do-not-return",
            "Authorization": "do-not-return",
        },
    )
    result = await send_fhir_request(
        config(stub),
        "dummy-first",
        "PATCH",
        "Patient/123",
        b"[]",
        content_type="application/json-patch+json",
        if_match='W/"1"',
        prefer="minimal",
    )
    assert result.status == 204 and not result.has_body
    assert result.headers == {"etag": 'W/"2"', "content-type": "application/fhir+json"}
    await send_fhir_request(
        config(stub), None, "POST", "", b'{"resourceType":"Bundle"}'
    )
    first, second = stub.records
    assert first["path"] == "/tenant/fhir/Patient/123"
    assert first["body"] == b"[]"
    assert first["headers"]["Authorization"] == "Bearer dummy-first"
    assert first["headers"]["If-Match"] == 'W/"1"'
    assert first["headers"]["Prefer"] == "return=minimal"
    assert first["headers"]["Content-Type"] == "application/json-patch+json"
    assert second["path"] == "/tenant/fhir"
    assert (
        "Authorization" not in second["headers"] and "If-Match" not in second["headers"]
    )


async def test_mutation_and_metadata_never_follow_redirects(stub):
    target = RecordingFhirServer()
    target.start()
    try:
        stub.queue(307, headers={"Location": target.base_url + "/collect"})
        response = await send_fhir_request(
            config(stub), "dummy", "PATCH", "Patient/123", b"[]"
        )
        assert response.status == 307
        stub.queue(302, headers={"Location": target.base_url + "/metadata"})
        with pytest.raises(FhirTransportError):
            await get_capability_statement(
                stub.base_url + "/metadata", "dummy", timeout=2
            )
        assert target.requests == []
        assert len(stub.requests) == 2
        assert stub.records[1]["headers"]["Authorization"] == "Bearer dummy"
    finally:
        target.stop()


@pytest.mark.parametrize(
    "status,body",
    [
        (412, {"resourceType": "OperationOutcome", "issue": [{"code": "conflict"}]}),
        (403, b"<html>not echoed</html>"),
        (200, b'{"truncated":'),
        (200, b'{"nonfinite":NaN}'),
    ],
)
async def test_raw_status_body_and_invalid_json(stub, status, body):
    stub.queue(status, body)
    result = await send_fhir_request(config(stub), None, "PATCH", "Patient/123", b"[]")
    assert result.status == status
    assert result.body == (body if isinstance(body, dict) else None)
    assert result.body_is_json == isinstance(body, dict)
    assert len(stub.requests) == 1


async def test_size_limit_is_unknown_with_observed_status(stub):
    stub.queue(200, b"x" * 101, {"ETag": 'W/"9"'})
    with pytest.raises(FhirTransportError) as caught:
        await send_fhir_request(
            config(stub, mcp_max_interaction_response_bytes=100),
            None,
            "PATCH",
            "Patient/123",
            b"[]",
        )
    assert caught.value.kind == "response-too-large" and caught.value.uncertain
    assert caught.value.status == 200 and caught.value.headers["etag"] == 'W/"9"'
    assert len(stub.requests) == 1


@pytest.mark.parametrize(
    "status,delay,kind", [(0, 0, "network"), (200, 1.3, "timeout")]
)
async def test_no_retry_on_disconnect_or_timeout(stub, status, delay, kind):
    stub.queue(status, b"", delay=delay)
    with pytest.raises(FhirTransportError) as caught:
        await send_fhir_request(
            config(stub, mcp_request_timeout=1), None, "PATCH", "Patient/123", b"[]"
        )
    assert caught.value.kind == kind and caught.value.uncertain
    assert len(stub.requests) == 1


async def test_refused_connection_is_not_dispatched():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        # Bound but not listening: prevent another process from taking this port.
        cfg = ServerConfigs(
            _env_file=None, server_base_url=f"http://127.0.0.1:{port}/fhir"
        )
        with pytest.raises(FhirTransportError) as caught:
            await send_fhir_request(cfg, None, "PATCH", "Patient/123", b"[]")
    assert caught.value.kind == "network" and not caught.value.uncertain
