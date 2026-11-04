# Bundle execution and JSON PATCH

## Enable writes

Set `FHIR_MCP_ENABLE_WRITE_TOOLS=True` and restart the MCP server after configuring
a FHIR identity with the required resource permissions. The default is `False`:
`create`, `update`, `delete`, `execute_bundle` and `patch` are absent from discovery
and also check the setting inside their handlers. Existing deployments that need
CRUD writes must explicitly opt in after upgrading.

This switch controls these five tools, not server authorization. Existing custom
GET operations may have server-defined effects. FHIR access policies remain the
permission boundary. Incoming MCP authorization and upstream credentials keep
their existing settings and behavior.

## Execute a transaction or batch

Call `execute_bundle` with a complete Bundle and optional `prefer`:

```json
{
  "bundle": {
    "resourceType": "Bundle",
    "type": "transaction",
    "entry": [
      {
        "fullUrl": "urn:uuid:8f7d9077-b261-4fce-b9fd-3100d134c001",
        "resource": {"resourceType": "Patient", "active": true},
        "request": {"method": "POST", "url": "Patient"}
      },
      {
        "resource": {
          "resourceType": "Observation",
          "status": "final",
          "code": {"text": "Example observation"},
          "subject": {"reference": "urn:uuid:8f7d9077-b261-4fce-b9fd-3100d134c001"}
        },
        "request": {"method": "POST", "url": "Observation"}
      }
    ]
  }
}
```

A **transaction** asks the FHIR server to commit every entry atomically. A **batch**
executes independent entries and can have mixed results. Both send one POST to the
configured FHIR base. The adapter does not split, reorder, retry or simulate them.
For batch, do not reference a resource that another entry must first create. The
adapter detects some URN `reference` dependencies; it cannot prove independence.

Supported entry routes:

| Method | Route | Body |
|---|---|---|
| GET | `Type`, `Type?criteria`, `Type/id` | None |
| POST | `Type` | Matching FHIR resource; optional `request.ifNoneExist` |
| PUT | `Type/id`, `Type?criteria` | Matching FHIR resource |
| DELETE | `Type/id`, `Type?criteria` | None |
| PATCH | `Type/id` | FHIRPath Parameters envelope |

Type searches preserve repeated parameters, `_include`, `_revinclude`, `:iterate`
and chained keys. Only one leading `/` is normalized. Absolute URLs, traversal,
percent-encoded path segments, operations, history, compartments, HEAD and
instance queries such as `Patient/123?_summary=true` are rejected. Search values
may contain URLs and encoded characters. Resource references and `fullUrl` are
data; the server resolves them.

`create` rejects Bundles, whether selected by `type="Bundle"` or supplied as a
Bundle payload. Use `execute_bundle` for transaction/batch execution. Other Bundle
types are not supported through `create`. This is an intentional compatibility
change: fhirpy previously routed unsaved Bundles to the base, bypassing the new
route, entry-count and dependency checks. Rejection sets MCP `isError=true` and
sends no upstream request. Ordinary resource creation remains unchanged.

## Patch a resource

```json
{
  "type": "Patient",
  "id": "example-patient",
  "if_match": "W/\"7\"",
  "payload": [
    {"op": "test", "path": "/active", "value": true},
    {"op": "replace", "path": "/active", "value": false}
  ]
}
```

Use the real resource ID and version from your server. The tool sends HTTP PATCH
with `application/json-patch+json`. It preserves all six JSON Patch operations,
operation order, additional members and explicit null values. It validates
structure and JSON Pointer syntax; the server evaluates paths and changes.

`if_match` is optional. Supplying the actual ETag protects a change based on an
earlier read. Weak tags (`W/"7"`), quoted tags (`"7"`) and Aidbox's bare version
tokens (`7`) are accepted and sent unchanged. Wildcards, multiple tags, control
characters and invalid version IDs are rejected. A 412 does not trigger a retry;
read the latest resource and reassess the intended change. Omitting `if_match`
makes the PATCH unconditional.

Both tools accept `prefer="representation"` (default) or `"minimal"`, mapped to
`Prefer: return=...`. This preference applies to write representations, not GET
results under the FHIR specification. The tested Aidbox build nevertheless omits GET
resources from batch responses with `minimal`; use the default `representation`
when you need those resources. The adapter preserves this observed server behavior.
The server may return no representation even when one was requested.

Direct FHIRPath, Merge Patch, XML and Binary-wrapped JSON Patch are not supported.
Inside a Bundle, PATCH accepts a Parameters resource containing `operation`
parameters with `part` arrays. Semantic validation belongs to the server.

## Interpret results

Both tools return the same object as MCP structured content and JSON text:

```json
{
  "interaction": "patch",
  "httpStatus": 204,
  "status": "success",
  "headers": {"etag": "W/\"8\""},
  "response": null,
  "summary": null,
  "error": null
}
```

| Field | Meaning |
|---|---|
| `interaction` | `transaction`, `batch` or `patch`; null when the submitted Bundle type cannot select an execution mode |
| `httpStatus` | Actual HTTP status, or null if none was observed |
| `status` | `success`, `partial`, `failure`, `pending` or `unknown` |
| `headers` | Selected lowercase response headers, including ETag and Location; no cookies |
| `response` | Complete parsed upstream JSON, including response-only entries and nested Bundles |
| `summary` | Bundle entry counts: `entries`, `succeeded`, `failed`, `pending`, `unknown` |
| `error` | Stable adapter `kind`, generic `message`, optional local OperationOutcome |

MCP `isError` is true for failure, partial and unknown outcomes. An HTTP 200 batch
can still contain failures. Read individual `entry.response.status` values and do
not replay successful entries. A transaction response with inconsistent entry
outcomes is `unknown`, not a claim of partial commit or rollback. HTTP/entry 202
means pending; there is no asynchronous-job poller.

Timeouts, disconnects, malformed success bodies and oversized responses may happen
after a write commits. Reconcile current server state before retrying. The adapter
never synthesizes a rollback guarantee and never automatically resends mutations.
Non-JSON bodies are not echoed; their HTTP status and selected headers remain
available. SDK argument-schema errors can use the SDK's own MCP error format.

Limits default to 100 Bundle entries, 100 patch operations, 1 MiB serialized input
and 8 MiB decoded response bytes. Configure the byte limits with
`FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES` and
`FHIR_MCP_MAX_INTERACTION_RESPONSE_BYTES`; both must be positive. Timeout uses
`FHIR_MCP_REQUEST_TIMEOUT`. Larger transactions are rejected, not split.

## Discover capabilities

`get_capabilities()` returns system interactions, FHIR version, patch formats,
an `operationCount` and resource type names. The potentially large system operation
list is omitted unless you pass `include_operations=true`. `get_capabilities(type="Patient")` retains
resource metadata and adds patch formats, versioning and conditional-operation
support when advertised. Discovery uses caller credentials and timeout and refuses
redirects. Results are advisory, not authorization or a mandatory round trip before
every write.
