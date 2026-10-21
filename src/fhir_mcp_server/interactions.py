"""FHIR interaction contracts and validation; no network or resource evaluation."""

from copy import deepcopy
from datetime import datetime
import json
import re
from typing import Any, Literal
from urllib.parse import urlsplit

from mcp.types import CallToolResult, TextContent
from pydantic import BaseModel, Field

MAX_BUNDLE_ENTRIES = 100
MAX_PATCH_OPERATIONS = 100
RESOURCE_TYPE = re.compile(r"[A-Za-z]{1,64}")
RESOURCE_ID = re.compile(r"[A-Za-z0-9.-]{1,64}")
CONTROL = re.compile(r"[\x00-\x1f\x7f]")
BAD_PERCENT = re.compile(r"%(?![0-9a-fA-F]{2})")


class FhirInputError(Exception):
    def __init__(self, message: str, code: str = "invalid"):
        super().__init__(message)
        self.code = code


class FhirAuthenticationError(Exception):
    pass


class FhirTransportError(Exception):
    def __init__(
        self,
        kind: str,
        message: str,
        *,
        status: int | None = None,
        headers: dict[str, str] | None = None,
        uncertain: bool = True,
    ):
        super().__init__(message)
        self.kind = kind
        self.status = status
        self.headers = headers or {}
        self.uncertain = uncertain


class InteractionSummary(BaseModel):
    entries: int
    succeeded: int = 0
    failed: int = 0
    pending: int = 0
    unknown: int = 0


class InteractionError(BaseModel):
    kind: Literal[
        "validation",
        "authentication",
        "upstream-http",
        "batch-entry-failure",
        "network",
        "timeout",
        "protocol",
        "response-too-large",
    ]
    message: str
    outcome: dict[str, Any] | None = None


class FhirInteractionResult(BaseModel):
    interaction: Literal["transaction", "batch", "patch"] | None
    httpStatus: int | None = None
    status: Literal["success", "partial", "failure", "pending", "unknown"]
    headers: dict[str, str] = Field(default_factory=dict)
    response: Any = None
    summary: InteractionSummary | None = None
    error: InteractionError | None = None

    def as_mcp(self) -> CallToolResult:
        data = self.model_dump(mode="json")
        return CallToolResult(
            content=[
                TextContent(type="text", text=json.dumps(data, ensure_ascii=False))
            ],
            structuredContent=data,
            isError=self.status in ("failure", "partial", "unknown"),
        )


def local_failure(
    interaction: str | None, kind: str, message: str, code: str = "invalid"
) -> FhirInteractionResult:
    return FhirInteractionResult(
        interaction=interaction,
        status="failure",
        error=InteractionError(
            kind=kind,
            message=message,
            outcome={
                "resourceType": "OperationOutcome",
                "issue": [{"severity": "error", "code": code, "diagnostics": message}],
            },
        ),
    )


def serialize_request(body: Any, limit: int) -> bytes:
    try:
        encoded = json.dumps(
            body, ensure_ascii=False, allow_nan=False, separators=(",", ":")
        ).encode("utf-8")
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise FhirInputError("Request must contain valid finite JSON values.") from None
    if len(encoded) > limit:
        raise FhirInputError("Request exceeds the configured byte limit.", "too-costly")
    return encoded


def validate_instance(resource_type: str, resource_id: str) -> None:
    if not isinstance(resource_type, str) or not RESOURCE_TYPE.fullmatch(resource_type):
        raise FhirInputError("Invalid FHIR resource type.")
    if not isinstance(resource_id, str):
        raise FhirInputError("FHIR resource ID must be a string.")
    if not resource_id:
        raise FhirInputError("FHIR resource ID is required.", "required")
    if not RESOURCE_ID.fullmatch(resource_id) or not resource_id.strip("."):
        raise FhirInputError(
            "Invalid FHIR resource ID: use 1-64 letters, digits, hyphens or dots; "
            "an ID cannot consist only of dots."
        )


def validate_prefer(prefer: str) -> None:
    if prefer not in ("minimal", "representation"):
        raise FhirInputError("Prefer must be minimal or representation.")


def validate_if_match(value: str | None) -> None:
    if value is None:
        return
    if not isinstance(value, str):
        raise FhirInputError(
            "If-Match must be a string containing one server version ETag."
        )
    if not value:
        raise FhirInputError(
            "If-Match cannot be empty; omit it for an unconditional PATCH."
        )
    if CONTROL.search(value):
        raise FhirInputError("If-Match must not contain control characters.")
    if value == "*":
        raise FhirInputError(
            "Wildcard If-Match is not supported; supply the resource's version ETag."
        )
    # Aidbox emits a bare version token; preserve it as returned by that server.
    match = re.fullmatch(r'(?:W/)?"([A-Za-z0-9.-]{1,64})"|([A-Za-z0-9.-]{1,64})', value)
    if not match or not (match[1] or match[2]).strip("."):
        raise FhirInputError(
            'Invalid If-Match: use one weak ETag (W/"7"), quoted ETag ("7"), '
            "or bare Aidbox version token (7). The version must be 1-64 letters, "
            "digits, hyphens or dots, not only dots; multiple tags are not supported."
        )


def validate_pointer(value: Any, member: str = "path") -> None:
    if not isinstance(value, str):
        raise FhirInputError(f"Patch '{member}' must be a JSON Pointer string.")
    if (value and not value.startswith("/")) or re.search(r"~(?![01])", value):
        raise FhirInputError(
            f"Invalid JSON Pointer in patch '{member}': use an empty string or a "
            "path starting with '/', with '~' escaped as '~0' or '~1'."
        )


def validate_patch(payload: Any) -> None:
    if not isinstance(payload, list):
        raise FhirInputError("JSON Patch must be an array of operation objects.")
    if len(payload) > MAX_PATCH_OPERATIONS:
        raise FhirInputError("Too many patch operations.", "too-costly")
    for item in payload:
        if not isinstance(item, dict) or item.get("op") not in (
            "add",
            "remove",
            "replace",
            "move",
            "copy",
            "test",
        ):
            raise FhirInputError("Unsupported or missing JSON Patch operation.")
        if "path" not in item:
            raise FhirInputError(
                "Patch operation requires a 'path' member.", "required"
            )
        validate_pointer(item["path"])
        if item["op"] in ("add", "replace", "test") and "value" not in item:
            raise FhirInputError("Patch operation requires a value member.")
        if item["op"] in ("move", "copy"):
            if "from" not in item:
                raise FhirInputError(
                    "Patch move/copy requires a 'from' member.", "required"
                )
            validate_pointer(item["from"], "from")


def validate_query(query: str) -> None:
    if not query or CONTROL.search(query) or BAD_PERCENT.search(query) or "#" in query:
        raise FhirInputError("Invalid or empty query criteria.")


def validate_bundle_request_url(value: Any) -> tuple[str, str, str | None, bool]:
    if (
        not isinstance(value, str)
        or not value
        or CONTROL.search(value)
        or "\\" in value
        or "#" in value
    ):
        raise FhirInputError("Invalid Bundle request URL.")
    if value.startswith("//"):
        raise FhirInputError("Bundle URLs must be relative to the FHIR base.")
    normalized = value[1:] if value.startswith("/") else value
    path, delimiter, query = normalized.partition("?")
    pieces = path.split("/")
    if len(pieces) not in (1, 2) or not RESOURCE_TYPE.fullmatch(pieces[0]):
        raise FhirInputError("Unsupported Bundle route.", "not-supported")
    instance_id = pieces[1] if len(pieces) == 2 else None
    if instance_id is not None:
        validate_instance(pieces[0], instance_id)
        if delimiter:
            raise FhirInputError(
                "Instance queries are not supported in Bundles.", "not-supported"
            )
    if delimiter:
        validate_query(query)
    return normalized, pieces[0], instance_id, bool(delimiter)


def validate_parameters(resource: Any) -> None:
    if not isinstance(resource, dict) or resource.get("resourceType") != "Parameters":
        raise FhirInputError(
            "Bundle PATCH requires FHIRPath Parameters; Binary and other formats are not supported.",
            "not-supported",
        )
    operations = resource.get("parameter")
    if not isinstance(operations, list):
        raise FhirInputError("PATCH Parameters requires a parameter array.")
    if len(operations) > MAX_PATCH_OPERATIONS:
        raise FhirInputError("Too many patch operation parameters.", "too-costly")
    for operation in operations:
        if (
            not isinstance(operation, dict)
            or operation.get("name") != "operation"
            or not isinstance(operation.get("part"), list)
            or not all(isinstance(part, dict) for part in operation["part"])
        ):
            raise FhirInputError(
                "Each PATCH parameter must be an operation with a part array of objects."
            )


def reference_values(value: Any):
    if isinstance(value, dict):
        for key, child in value.items():
            if key == "reference" and isinstance(child, str):
                yield child
            yield from reference_values(child)
    elif isinstance(value, list):
        for child in value:
            yield from reference_values(child)


def validate_bundle(bundle: Any) -> dict[str, Any]:
    if not isinstance(bundle, dict) or bundle.get("resourceType") != "Bundle":
        raise FhirInputError(
            "Expected a FHIR Bundle object with resourceType 'Bundle'."
        )
    if bundle.get("type") not in ("transaction", "batch"):
        raise FhirInputError(
            "Only transaction or batch Bundles can be executed.", "not-supported"
        )
    if not isinstance(bundle.get("entry"), list):
        raise FhirInputError("Bundle.entry must be an array.")
    if len(bundle["entry"]) > MAX_BUNDLE_ENTRIES:
        raise FhirInputError("Too many Bundle entries.", "too-costly")
    outbound = deepcopy(bundle)
    preconditions = {
        "GET": {"ifNoneMatch", "ifModifiedSince"},
        "POST": {"ifNoneExist"},
        "PUT": {"ifMatch", "ifNoneMatch"},
        "DELETE": {"ifMatch"},
        "PATCH": {"ifMatch"},
    }
    urns: dict[str, set[int]] = {}
    for index, entry in enumerate(outbound["entry"]):
        if (
            not isinstance(entry, dict)
            or "response" in entry
            or "search" in entry
            or not isinstance(entry.get("request"), dict)
        ):
            raise FhirInputError(
                "Each entry requires a request and must not contain response or search fields."
            )
        request = entry["request"]
        method = request.get("method")
        if not isinstance(method, str) or method not in preconditions:
            raise FhirInputError("Unsupported Bundle request method.", "not-supported")
        allowed = {"method", "url", "id", "extension"} | preconditions[method]
        allowed |= {"_" + key for key in allowed if key not in ("extension", "id")}
        if set(request) - allowed:
            raise FhirInputError(
                "Unsupported request field or precondition for this method."
            )
        normalized, resource_type, instance_id, query = validate_bundle_request_url(
            request.get("url")
        )
        request["url"] = normalized
        if method == "POST" and (instance_id or query):
            raise FhirInputError(
                "POST requires a resource-type route.", "not-supported"
            )
        if method in ("PUT", "DELETE") and not instance_id and not query:
            raise FhirInputError(
                "PUT/DELETE requires an instance or conditional criteria.",
                "not-supported",
            )
        if method == "PATCH" and not instance_id:
            raise FhirInputError(
                "Bundle PATCH requires an instance route.", "not-supported"
            )
        for name in preconditions[method] & request.keys():
            value = request[name]
            if not isinstance(value, str) or not value or CONTROL.search(value):
                raise FhirInputError("Invalid request precondition.")
            if name == "ifNoneExist":
                validate_query(value)
                if "=" not in value or not re.fullmatch(
                    r"[A-Za-z_][A-Za-z0-9_.:-]*", value.split("=", 1)[0]
                ):
                    raise FhirInputError(
                        "ifNoneExist must contain query criteria, not a URL."
                    )
            if name == "ifModifiedSince":
                if not re.fullmatch(
                    r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})",
                    value,
                ):
                    raise FhirInputError("ifModifiedSince must be a FHIR instant.")
                try:
                    datetime.fromisoformat(value.replace("Z", "+00:00"))
                except ValueError:
                    raise FhirInputError(
                        "ifModifiedSince must be a valid instant."
                    ) from None
        resource = entry.get("resource")
        if method in ("GET", "DELETE") and "resource" in entry:
            raise FhirInputError(
                "GET and DELETE entries must not have a resource body."
            )
        if method in ("POST", "PUT"):
            if (
                not isinstance(resource, dict)
                or resource.get("resourceType") != resource_type
            ):
                raise FhirInputError("Resource body type must match the request route.")
            if (
                method == "PUT"
                and instance_id
                and "id" in resource
                and resource["id"] != instance_id
            ):
                raise FhirInputError("Resource body ID must match the PUT route.")
        if method == "PATCH":
            validate_parameters(resource)
        if "fullUrl" in entry:
            full_url = entry["fullUrl"]
            if (
                not isinstance(full_url, str)
                or not full_url
                or re.search(r"[\s\\]", full_url)
                or CONTROL.search(full_url)
                or BAD_PERCENT.search(full_url)
            ):
                raise FhirInputError("fullUrl must be a version-independent URI.")
            try:
                parts = urlsplit(full_url)
            except ValueError:
                raise FhirInputError("Invalid fullUrl URI.") from None
            if not parts.scheme or parts.fragment or "/_history/" in parts.path:
                raise FhirInputError("fullUrl must be a version-independent URI.")
            if method == "POST" and full_url.startswith(("urn:uuid:", "urn:oid:")):
                urns.setdefault(full_url, set()).add(index)
    if bundle["type"] == "batch":
        for index, entry in enumerate(outbound["entry"]):
            if any(
                urns.get(reference, set()) - {index}
                for reference in reference_values(entry.get("resource"))
            ):
                raise FhirInputError(
                    "Batch entries must not reference another POST entry's URN; use a transaction."
                )
    return outbound


def classify_response(
    interaction: str,
    http: Any,
    *,
    bundle: dict | None = None,
    resource_type: str | None = None,
    resource_id: str | None = None,
) -> FhirInteractionResult:
    result = FhirInteractionResult(
        interaction=interaction,
        httpStatus=http.status,
        status="success",
        headers=http.headers,
        response=http.body,
    )

    def fail(kind: str, message: str, status: str = "unknown") -> FhirInteractionResult:
        result.status = status
        result.error = InteractionError(kind=kind, message=message)
        return result

    if not 200 <= http.status < 300:
        return fail(
            "upstream-http",
            "FHIR server rejected the request; inspect HTTP status and response.",
            "failure",
        )
    if http.status == 202:
        result.status = "pending"
        return result
    body = http.body
    outcome = isinstance(body, dict) and body.get("resourceType") == "OperationOutcome"
    if outcome and not isinstance(body.get("issue"), list):
        return fail(
            "protocol",
            "Malformed OperationOutcome; reconcile server state before retrying.",
        )
    if outcome and any(
        isinstance(i, dict) and i.get("severity") in ("error", "fatal")
        for i in body["issue"]
    ):
        return fail(
            "upstream-http",
            "FHIR server returned an error OperationOutcome.",
            "failure",
        )
    if not http.body_is_json and http.has_body:
        return fail(
            "protocol",
            "FHIR server returned an unreadable success body; reconcile server state before retrying.",
        )
    if interaction == "patch":
        if not http.has_body:
            return result
        if (
            outcome
            and isinstance(body.get("issue"), list)
            and body["issue"]
            and all(
                isinstance(i, dict) and i.get("severity") in ("information", "warning")
                for i in body["issue"]
            )
        ):
            return result
        if (
            isinstance(body, dict)
            and body.get("resourceType") == resource_type
            and body.get("id") == resource_id
        ):
            return result
        return fail(
            "protocol",
            "PATCH returned an unexpected resource; reconcile server state before retrying.",
        )
    if (
        not isinstance(body, dict)
        or body.get("resourceType") != "Bundle"
        or body.get("type") != interaction + "-response"
    ):
        return fail(
            "protocol",
            "Expected a matching response Bundle; reconcile server state before retrying.",
        )
    entries = body.get("entry", [])
    expected = bundle["entry"]
    if not isinstance(entries, list):
        return fail("protocol", "Response Bundle entry must be an array.")
    summary = InteractionSummary(entries=len(expected))
    result.summary = summary
    malformed = len(entries) != len(expected)
    summary.unknown = max(0, len(expected) - len(entries))
    for index, entry in enumerate(entries):
        response = entry.get("response") if isinstance(entry, dict) else None
        raw = response.get("status") if isinstance(response, dict) else None
        match = (
            re.match(r"^([1-5][0-9]{2})(?:\s|$)", raw) if isinstance(raw, str) else None
        )
        if not match:
            summary.unknown += 1
            malformed = True
            continue
        status = int(match[1])
        request = expected[index]["request"] if index < len(expected) else {}
        conditional_read = request.get("method") == "GET" and any(
            k in request for k in ("ifNoneMatch", "ifModifiedSince")
        )
        if status == 202:
            summary.pending += 1
        elif 200 <= status < 300 or (status == 304 and conditional_read):
            summary.succeeded += 1
        else:
            summary.failed += 1
            if status == 304:
                malformed = True
    if malformed or (interaction == "transaction" and summary.failed):
        return fail(
            "protocol",
            "Response Bundle has inconsistent entry outcomes; reconcile server state before retrying.",
        )
    if summary.failed:
        return fail(
            "batch-entry-failure",
            "Inspect each entry outcome; do not replay successful entries.",
            "partial" if summary.succeeded or summary.pending else "failure",
        )
    if summary.pending:
        result.status = "pending"
    return result
