from copy import deepcopy
import json

import pytest

from fhir_mcp_server.errors import FhirInputError
from fhir_mcp_server.interactions import (
    FhirInteractionResult,
    classify_response,
    serialize_request,
    validate_bundle,
    validate_bundle_request_url,
    validate_instance,
)
from fhir_mcp_server.fhir_http import FhirHttpResponse, request_url


def validate(value, max_entries=100, max_patch_operations=100):
    """Validate a Bundle with the default limits unless overridden."""
    return validate_bundle(value, max_entries, max_patch_operations)


def bundle(
    method="GET", url="Patient/123", resource=None, kind="transaction", **request
):
    """Build a single-entry Bundle for route, precondition and response-classification tests."""
    entry = {"request": {"method": method, "url": url, **request}}
    if resource is not None:
        entry["resource"] = resource
    return {"resourceType": "Bundle", "type": kind, "entry": [entry]}


@pytest.mark.parametrize(
    "url",
    [
        "https://evil/Patient",
        "//evil/Patient",
        "../Patient",
        "/../Patient",
        "Patient/%2e%2e",
        "Patient/%252e%252e",
        "Patient\\123",
        "Patient//123",
        "Patient/..",
        "Patient/123?x=1",
        "Patient#frag",
        "Patient?x=%xy",
        "Patient?x=\n",
        "Patient?",
        "",
        "/",
        "Patient/$everything",
        "Patient/1/_history/1",
        " Patient",
        "Patient%2f123",
        "Patient/123 ",
    ],
)
def test_url_boundary(url):
    """Reject absolute URLs, traversal, unsupported routes and malformed query syntax."""
    with pytest.raises(FhirInputError):
        validate_bundle_request_url(url)


@pytest.mark.parametrize(
    "url",
    [
        "Patient/123",
        "/Patient/123",
        "Patient",
        "Observation?patient=Patient/123&_include=Observation:patient&_include:iterate=Encounter:location",
        "Patient?identifier=https%3A%2F%2Fexample.org%7C123&_revinclude=Observation:patient&_revinclude=Encounter:patient",
    ],
)
def test_queries_preserved(url):
    """Preserve complex search criteria while stripping only the allowed leading slash."""
    assert validate_bundle_request_url(url)[0] == url.lstrip("/")


@pytest.mark.parametrize(
    "base",
    [
        "file:///tmp",
        "http://user:secret@host/fhir",
        "https://host/fhir?x=1",
        "https://host/fhir#x",
        "http:///fhir",
        "http://host:bad/fhir",
        "http://host\n/fhir",
    ],
)
def test_invalid_configured_base(base):
    """Reject non-HTTP, credential-bearing or otherwise ambiguous configured base URLs."""
    with pytest.raises(FhirInputError):
        request_url(base, "")


def test_exact_base_and_prefix():
    """Preserve tenant prefixes and post Bundles to the exact normalized FHIR base."""
    assert request_url("https://host/tenant/fhir/", "") == "https://host/tenant/fhir"
    assert (
        request_url("https://host/tenant/fhir", "Patient/123")
        == "https://host/tenant/fhir/Patient/123"
    )


@pytest.mark.parametrize(
    "method,url,resource",
    [
        ("GET", "Patient", None),
        ("GET", "Patient/123", None),
        ("POST", "Patient", {"resourceType": "Patient"}),
        ("PUT", "Patient/123", {"resourceType": "Patient", "id": "123"}),
        ("PUT", "Patient?identifier=urn:test|1", {"resourceType": "Patient"}),
        ("DELETE", "Patient/123", None),
        ("DELETE", "Patient?identifier=x", None),
        ("PATCH", "Patient/123", {"resourceType": "Parameters", "parameter": []}),
    ],
)
def test_supported_routes(method, url, resource):
    """Accept the documented method, route and resource combinations without altering them."""
    value = bundle(method, url, resource)
    assert validate(value) == value


@pytest.mark.parametrize(
    "method,url,resource",
    [
        ("HEAD", "Patient/123", None),
        ("DELETE", "Patient", None),
        ("PUT", "Patient", {"resourceType": "Patient"}),
        ("POST", "Patient/123", {"resourceType": "Patient"}),
        ("POST", "Patient?x=1", {"resourceType": "Patient"}),
        ("PATCH", "Patient?x=1", {"resourceType": "Parameters", "parameter": []}),
        ("POST", "Patient", {"resourceType": "Observation"}),
        ("PUT", "Patient/123", {"resourceType": "Patient", "id": "456"}),
        ("GET", "Patient", {"resourceType": "Patient"}),
        ("PATCH", "Patient/123", {"resourceType": "Binary", "data": "abc"}),
    ],
)
def test_rejected_routes(method, url, resource):
    """Reject unsupported methods, broad writes and bodies that conflict with their routes."""
    with pytest.raises(FhirInputError):
        validate(bundle(method, url, resource))


def test_bundle_preservation_and_normalization():
    """Normalize copied request URLs without mutating input or losing resource values."""
    value = bundle(
        "POST",
        "/Patient",
        {
            "resourceType": "Patient",
            "active": False,
            "extension": [{"valueString": None}],
        },
    )
    value["entry"][0]["fullUrl"] = "urn:uuid:11111111-1111-1111-1111-111111111111"
    before = deepcopy(value)
    result = validate(value)
    assert value == before
    result["entry"][0]["request"]["url"] = "/Patient"
    assert result == value


def test_batch_reference_check_is_exact_and_only_reference_values():
    """Reject only cross-entry POST URN references, allowing unrelated URLs and self-references."""
    value = bundle("POST", "Patient", {"resourceType": "Patient"}, "batch")
    value["entry"][0]["fullUrl"] = "urn:uuid:example"
    second = {
        "request": {"method": "POST", "url": "Observation"},
        "resource": {
            "resourceType": "Observation",
            "subject": {"reference": "urn:uuid:example"},
        },
    }
    value["entry"].append(second)
    with pytest.raises(FhirInputError):
        validate(value)
    value["type"] = "transaction"
    assert validate(value) == value
    value["type"] = "batch"
    second["resource"]["subject"] = {
        "url": "urn:uuid:example",
        "reference": "urn:uuid:example-other",
    }
    assert validate(value) == value
    value["entry"][0]["resource"]["link"] = [
        {"other": {"reference": "urn:uuid:example"}}
    ]
    assert validate(value) == value  # self-reference is not rejected


def test_limits():
    """Enforce byte and entry limits, finite JSON and nonempty IDs."""
    raw = serialize_request({"value": "é"}, 100)
    assert len(raw) > len(raw.decode())
    assert serialize_request({"value": "é"}, len(raw)) == raw
    for payload, limit in [
        ({"value": "é"}, len(raw) - 1),
        ({"value": float("nan")}, 100),
    ]:
        with pytest.raises(FhirInputError):
            serialize_request(payload, limit)
    with pytest.raises(FhirInputError):
        validate_instance("Patient", "")
    value = bundle()
    value["entry"] *= 101
    with pytest.raises(FhirInputError):
        validate(value)


def test_entry_and_patch_operation_limits_are_configurable():
    """Apply the configured entry and Parameters operation limits instead of fixed values."""
    value = bundle()
    value["entry"] *= 3
    assert validate(value, max_entries=3) == value
    with pytest.raises(FhirInputError) as caught:
        validate(value, max_entries=2)
    assert caught.value.code == "too-costly"
    operation = {"name": "operation", "part": [{"name": "type", "valueCode": "delete"}]}
    patch = bundle(
        "PATCH",
        "Patient/123",
        {"resourceType": "Parameters", "parameter": [operation] * 2},
    )
    assert validate(patch, max_patch_operations=2) == patch
    with pytest.raises(FhirInputError):
        validate(patch, max_patch_operations=1)


def test_empty_bundle_rejected():
    """Reject a Bundle without entries instead of sending it to the server."""
    with pytest.raises(FhirInputError) as caught:
        validate({"resourceType": "Bundle", "type": "batch", "entry": []})
    assert caught.value.code == "required"


@pytest.mark.parametrize(
    "preconditions",
    [
        {"headers": {}},
        {"ifMatch": "bad"},
        {"ifModifiedSince": "2026-02-31T00:00:00Z"},
        {"ifNoneMatch": "x\r\ny"},
    ],
)
def test_request_preconditions_rejected(preconditions):
    """Reject method-incompatible preconditions, invalid instants and header control characters."""
    with pytest.raises(FhirInputError):
        validate(bundle(**preconditions))


@pytest.mark.parametrize(
    "kind,statuses,expected,error",
    [
        ("batch", ["200", "404 Not Found"], "partial", "batch-entry-failure"),
        ("batch", ["404", "403"], "failure", "batch-entry-failure"),
        ("batch", ["202", "403"], "partial", "batch-entry-failure"),
        ("batch", ["202", "200"], "pending", None),
        ("transaction", ["201", "403"], "unknown", "protocol"),
        ("transaction", ["200", "204 No Content"], "success", None),
        ("batch", ["nonsense", "200"], "unknown", "protocol"),
        ("batch", ["200"], "unknown", "protocol"),
        ("batch", ["304", "200"], "unknown", "protocol"),
    ],
)
def test_bundle_classification(kind, statuses, expected, error):
    """Classify mixed, pending and malformed entry statuses while preserving the entire response."""
    request = bundle(kind=kind)
    request["entry"] *= 2
    response = {
        "resourceType": "Bundle",
        "type": kind + "-response",
        "entry": [
            {
                "response": {"status": status},
                "extension": [{"url": "urn:test", "valueBoolean": False}],
            }
            for status in statuses
        ],
    }
    result = classify_response(
        kind, FhirHttpResponse(200, {}, response, True, True), bundle=request
    )
    assert result.status == expected
    assert (result.error.kind if result.error else None) == error
    assert result.response == response
    assert (
        json.loads(result.as_mcp().content[0].text) == result.as_mcp().structuredContent
    )


@pytest.mark.parametrize(
    "status,is_error",
    [
        ("success", False),
        ("pending", False),
        ("partial", False),
        ("unknown", False),
        ("failure", True),
    ],
)
def test_only_failure_sets_is_error(status, is_error):
    """Report partial, pending and unknown outcomes through status, so a client that retries
    errored calls does not replay writes that may already have been applied.
    """
    result = FhirInteractionResult(interaction="batch", status=status).as_mcp()
    assert result.isError is is_error
    assert result.structuredContent["status"] == status


def test_conditional_304_and_empty_response_bundle():
    """Accept conditional not-modified entries and transaction responses without entries."""
    request = bundle(ifNoneMatch='W/"7"')
    response = {
        "resourceType": "Bundle",
        "type": "transaction-response",
        "entry": [{"response": {"status": "304"}}],
    }
    assert (
        classify_response(
            "transaction",
            FhirHttpResponse(200, {}, response, True, True),
            bundle=request,
        ).status
        == "success"
    )
    request["entry"] = []
    response.pop("entry")
    assert (
        classify_response(
            "transaction",
            FhirHttpResponse(200, {}, response, True, True),
            bundle=request,
        ).status
        == "success"
    )


def test_parameters_envelope_preserves_nested_values_and_defers_semantics():
    """Validate Parameters structure while preserving nested values and deferring FHIRPath
    evaluation.
    """
    resource = {
        "resourceType": "Parameters",
        "parameter": [
            {
                "name": "operation",
                "part": [
                    {"name": "type", "valueCode": "server-must-validate-this"},
                    {
                        "name": "value",
                        "part": [
                            {
                                "name": "coding",
                                "valueCoding": {"system": "urn:test", "code": "0"},
                            }
                        ],
                    },
                ],
            }
        ],
    }
    value = bundle("PATCH", "Patient/123", resource, ifMatch='W/"7"')
    assert validate(value) == value
    for bad in [
        {"resourceType": "Parameters"},
        {"resourceType": "Parameters", "parameter": [None]},
        {
            "resourceType": "Parameters",
            "parameter": [{"name": "operation", "part": [1]}],
        },
        {"resourceType": "Parameters", "parameter": resource["parameter"] * 101},
    ]:
        with pytest.raises(FhirInputError):
            validate(bundle("PATCH", "Patient/123", bad))


def test_fullurl_and_entry_envelopes():
    """Reject malformed or versioned fullUrls and invalid Bundle entry envelopes."""
    for full_url in [
        "Patient/123",
        "https://example.org/Patient/123/_history/2",
        "urn:uuid:x\n",
        "http://[bad",
    ]:
        value = bundle()
        value["entry"][0]["fullUrl"] = full_url
        with pytest.raises(FhirInputError):
            validate(value)
    for bad in [
        None,
        {},
        {"resourceType": "Bundle", "type": "collection", "entry": []},
        {"resourceType": "Bundle", "type": "batch", "entry": [None]},
        {
            "resourceType": "Bundle",
            "type": "batch",
            "entry": [{"request": {}, "response": {}}],
        },
    ]:
        with pytest.raises(FhirInputError):
            validate(bad)
    value = bundle("GET", "Patient", ifModifiedSince="2026-10-20T12:01:02Z")
    value["entry"][0]["fullUrl"] = "https://example.org/Patient/123"
    assert validate(value) == value


def test_if_none_exist_is_criteria_and_preconditions_preserved():
    """Preserve conditional-create criteria while rejecting URLs and malformed percent escapes."""
    value = bundle(
        "POST",
        "Patient",
        {"resourceType": "Patient"},
        ifNoneExist="identifier=https://example.org/id%7Cx",
    )
    assert validate(value) == value
    for invalid in [
        "https://evil/Patient?identifier=x",
        "?identifier=x",
        "identifier=x%GG",
    ]:
        with pytest.raises(FhirInputError):
            validate(
                bundle(
                    "POST", "Patient", {"resourceType": "Patient"}, ifNoneExist=invalid
                )
            )


@pytest.mark.parametrize(
    "body",
    [
        {"resourceType": "Bundle", "type": "batch-response", "entry": []},
        {"resourceType": "Bundle", "type": "transaction-response", "entry": None},
        {"resourceType": "OperationOutcome", "issue": None},
        {"resourceType": "OperationOutcome", "issue": "invalid"},
    ],
)
def test_malformed_success_is_unknown_not_an_exception(body):
    """Return a protocol-unknown result for malformed success bodies instead of crashing."""
    result = classify_response(
        "transaction", FhirHttpResponse(200, {}, body, True, True), bundle=bundle()
    )
    assert result.status == "unknown" and result.error.kind == "protocol"


@pytest.mark.parametrize(
    "value,message",
    [
        ("", "ID is required"),
        ("x/y", "Invalid FHIR resource ID"),
        ("..", "Invalid FHIR resource ID"),
        (123, "must be a string"),
    ],
)
def test_resource_id_diagnostics(value, message):
    """Distinguish absent, malformed and non-string resource IDs in validation messages."""
    with pytest.raises(FhirInputError) as caught:
        validate_instance("Patient", value)
    assert message in str(caught.value)
