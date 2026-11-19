import socket

import pytest

from fhir_mcp_server.errors import FhirInputError, FhirTransportError
from fhir_mcp_server.fhir_http import send_fhir_request
from fhir_mcp_server.oauth import ServerConfigs
from tests.e2e.conftest import RecordingFhirServer

BUNDLE = b'{"resourceType":"Bundle","type":"batch","entry":[]}'


@pytest.fixture
def stub():
    """Run a disposable loopback recorder and close it after the test."""
    server = RecordingFhirServer()
    server.start()
    try:
        yield server
    finally:
        server.stop()


def config(stub, **kwargs):
    """Build isolated transport settings targeting the loopback recorder under a tenant prefix."""
    return ServerConfigs(
        _env_file=None, server_base_url=stub.base_url + "/tenant/fhir/", **kwargs
    )


async def send(cfg, access_token=None, prefer="representation"):
    """Send one Bundle POST to the configured base."""
    return await send_fhir_request(
        cfg, access_token, "POST", "", BUNDLE, prefer=prefer, tool="execute_bundle"
    )


async def test_exact_requests_header_isolation_and_response_allowlist(stub):
    """Verify the exact URL and payload, per-call credentials and filtered response headers."""
    stub.queue(
        200,
        b'{"resourceType":"Bundle","type":"batch-response"}',
        headers={
            "Location": "Patient/1",
            "Set-Cookie": "do-not-return",
            "Authorization": "do-not-return",
        },
    )
    result = await send(config(stub), "dummy-first", prefer="minimal")
    assert result.status == 200 and result.body_is_json
    assert result.headers == {
        "location": "Patient/1",
        "content-type": "application/fhir+json",
    }
    await send(config(stub))
    first, second = stub.records
    assert first["path"] == "/tenant/fhir"
    assert first["body"] == BUNDLE
    assert first["headers"]["Authorization"] == "Bearer dummy-first"
    assert first["headers"]["Prefer"] == "return=minimal"
    assert first["headers"]["Content-Type"] == "application/fhir+json"
    assert "Authorization" not in second["headers"]


async def test_redirects_are_not_followed(stub):
    """A redirect is returned as is, so credentials are never forwarded to another server."""
    target = RecordingFhirServer()
    target.start()
    try:
        stub.queue(307, headers={"Location": target.base_url + "/collect"})
        response = await send(config(stub), "dummy")
        assert response.status == 307
        assert target.requests == []
        assert len(stub.requests) == 1
    finally:
        target.stop()


async def test_request_byte_limit_blocks_dispatch_and_accepts_exact_boundary(stub):
    body = '{"resourceType":"Patient","name":[{"text":"é"}]}'.encode("utf-8")
    with pytest.raises(FhirInputError, match="byte limit"):
        await send_fhir_request(
            config(stub, mcp_max_interaction_request_bytes=len(body) - 1),
            None, "POST", "", body, tool="execute_bundle",
        )
    assert stub.requests == []
    await send_fhir_request(
        config(stub, mcp_max_interaction_request_bytes=len(body)),
        None, "POST", "", body, tool="execute_bundle",
    )
    assert len(stub.records) == 1
    assert stub.records[0]["body"] == body


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
    """Preserve upstream statuses while distinguishing valid JSON from unreadable response
    bodies.
    """
    stub.queue(status, body)
    result = await send(config(stub))
    assert result.status == status
    assert result.body == (body if isinstance(body, dict) else None)
    assert result.body_is_json == isinstance(body, dict)
    assert len(stub.requests) == 1


async def test_size_limit_is_unknown_with_observed_status(stub):
    """Retain observed headers and status when an oversized response leaves write completion
    uncertain.
    """
    stub.queue(200, b"x" * 101, {"Location": "Patient/9"})
    with pytest.raises(FhirTransportError) as caught:
        await send(config(stub, mcp_max_interaction_response_bytes=100))
    assert caught.value.kind == "response-too-large" and caught.value.uncertain
    assert caught.value.status == 200
    assert caught.value.headers["location"] == "Patient/9"
    assert len(stub.requests) == 1


@pytest.mark.parametrize(
    "status,delay,kind", [(0, 0, "network"), (200, 1.3, "timeout")]
)
async def test_no_retry_on_disconnect_or_timeout(stub, status, delay, kind):
    """Prove a timeout or post-dispatch disconnect produces an uncertain result without replay."""
    stub.queue(status, b"", delay=delay)
    with pytest.raises(FhirTransportError) as caught:
        await send(config(stub, mcp_request_timeout=1))
    assert caught.value.kind == kind and caught.value.uncertain
    assert len(stub.requests) == 1


async def test_refused_connection_is_not_dispatched():
    """Classify refusal on a reserved non-listening port as a definite pre-dispatch failure."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
        # Bound but not listening: prevent another process from taking this port.
        cfg = ServerConfigs(
            _env_file=None, server_base_url=f"http://127.0.0.1:{port}/fhir"
        )
        with pytest.raises(FhirTransportError) as caught:
            await send(cfg)
    assert caught.value.kind == "network" and not caught.value.uncertain
