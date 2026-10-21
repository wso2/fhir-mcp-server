from copy import deepcopy
import json

import pytest

from fhir_mcp_server.interactions import (
    FhirInputError,
    classify_response,
    serialize_request,
    validate_bundle,
    validate_bundle_request_url,
    validate_if_match,
    validate_instance,
    validate_patch,
)
from fhir_mcp_server.fhir_http import FhirHttpResponse, request_url


def bundle(
    method="GET", url="Patient/123", resource=None, kind="transaction", **request
):
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
    with pytest.raises(FhirInputError):
        request_url(base, "")


def test_exact_base_and_prefix():
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
    value = bundle(method, url, resource)
    assert validate_bundle(value) == value


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
    with pytest.raises(FhirInputError):
        validate_bundle(bundle(method, url, resource))


def test_bundle_preservation_and_normalization():
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
    result = validate_bundle(value)
    assert value == before
    result["entry"][0]["request"]["url"] = "/Patient"
    assert result == value


def test_batch_reference_check_is_exact_and_only_reference_values():
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
        validate_bundle(value)
    value["type"] = "transaction"
    assert validate_bundle(value) == value
    value["type"] = "batch"
    second["resource"]["subject"] = {
        "url": "urn:uuid:example",
        "reference": "urn:uuid:example-other",
    }
    assert validate_bundle(value) == value
    value["entry"][0]["resource"]["link"] = [
        {"other": {"reference": "urn:uuid:example"}}
    ]
    assert validate_bundle(value) == value  # self-reference is not rejected


@pytest.mark.parametrize("value", [None, False, 0, "", [], {}, "é"])
def test_patch_values_and_extra_members_preserved(value):
    payload = [
        {"op": "add", "path": "/a~1b/~0", "value": value, "extra": 1},
        {"op": "copy", "path": "", "from": "/a"},
        {"op": "remove", "path": "/b"},
        {"op": "move", "path": "/c", "from": "/b"},
        {"op": "test", "path": "/c", "value": value},
        {"op": "replace", "path": "/c", "value": value},
    ]
    validate_patch(payload)
    assert json.loads(serialize_request(payload, 10000)) == payload


@pytest.mark.parametrize(
    "payload",
    [
        {},
        [None],
        [{"op": "add", "path": "/x"}],
        [{"op": "remove", "path": "x"}],
        [{"op": "copy", "path": "/x"}],
        [{"op": "remove", "path": "/x~2"}],
        [{"op": "bad", "path": ""}],
        [{"op": "remove", "path": "/x"}] * 101,
    ],
)
def test_invalid_patch(payload):
    with pytest.raises(FhirInputError):
        validate_patch(payload)


def test_limits_and_headers():
    raw = serialize_request({"value": "é"}, 100)
    assert len(raw) > len(raw.decode())
    assert serialize_request({"value": "é"}, len(raw)) == raw
    for payload, limit in [
        ({"value": "é"}, len(raw) - 1),
        ({"value": float("nan")}, 100),
    ]:
        with pytest.raises(FhirInputError):
            serialize_request(payload, limit)
    validate_patch([])
    for valid in ['W/"7"', '"7"', "7"]:
        validate_if_match(valid)
    for invalid in ["*", "", "..", 'W/".."', 'W/"7"\r\nx:y']:
        with pytest.raises(FhirInputError):
            validate_if_match(invalid)
    with pytest.raises(FhirInputError):
        validate_instance("Patient", "")
    value = bundle()
    value["entry"] *= 101
    with pytest.raises(FhirInputError):
        validate_bundle(value)


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
    with pytest.raises(FhirInputError):
        validate_bundle(bundle(**preconditions))


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


def test_conditional_304_and_empty_bundle():
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


@pytest.mark.parametrize(
    "status,body,is_json,has_body,expected",
    [
        (204, None, False, False, "success"),
        (202, None, False, False, "pending"),
        (412, {"resourceType": "OperationOutcome"}, True, True, "failure"),
        (200, {"resourceType": "Patient", "id": "123"}, True, True, "success"),
        (200, {"resourceType": "Patient", "id": "456"}, True, True, "unknown"),
        (200, None, False, True, "unknown"),
        (500, None, False, True, "failure"),
        (
            200,
            {"resourceType": "OperationOutcome", "issue": [{"severity": "error"}]},
            True,
            True,
            "failure",
        ),
    ],
)
def test_patch_outcomes(status, body, is_json, has_body, expected):
    result = classify_response(
        "patch",
        FhirHttpResponse(status, {"etag": 'W/"8"'}, body, is_json, has_body),
        resource_type="Patient",
        resource_id="123",
    )
    assert result.status == expected
    assert result.httpStatus == status
    assert result.headers["etag"] == 'W/"8"'


def test_parameters_envelope_preserves_nested_values_and_defers_semantics():
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
    assert validate_bundle(value) == value
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
            validate_bundle(bundle("PATCH", "Patient/123", bad))


def test_fullurl_and_entry_envelopes():
    for full_url in [
        "Patient/123",
        "https://example.org/Patient/123/_history/2",
        "urn:uuid:x\n",
        "http://[bad",
    ]:
        value = bundle()
        value["entry"][0]["fullUrl"] = full_url
        with pytest.raises(FhirInputError):
            validate_bundle(value)
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
            validate_bundle(bad)
    value = bundle("GET", "Patient", ifModifiedSince="2026-10-20T12:01:02Z")
    value["entry"][0]["fullUrl"] = "https://example.org/Patient/123"
    assert validate_bundle(value) == value


def test_if_none_exist_is_criteria_and_preconditions_preserved():
    value = bundle(
        "POST",
        "Patient",
        {"resourceType": "Patient"},
        ifNoneExist="identifier=https://example.org/id%7Cx",
    )
    assert validate_bundle(value) == value
    for invalid in [
        "https://evil/Patient?identifier=x",
        "?identifier=x",
        "identifier=x%GG",
    ]:
        with pytest.raises(FhirInputError):
            validate_bundle(
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
    with pytest.raises(FhirInputError) as caught:
        validate_instance("Patient", value)
    assert message in str(caught.value)


@pytest.mark.parametrize(
    "value,message",
    [
        ("", "cannot be empty"),
        ("*", "Wildcard"),
        ("7\r\nx:y", "control characters"),
        (123, "must be a string"),
        ('W/".."', 'weak ETag (W/"7")'),
    ],
)
def test_if_match_diagnostics(value, message):
    with pytest.raises(FhirInputError) as caught:
        validate_if_match(value)
    assert message in str(caught.value)
