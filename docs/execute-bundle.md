# Executing transaction and batch Bundles

`execute_bundle` sends a FHIR `transaction` or `batch` Bundle to the FHIR server base in
one request and returns the server's complete response, with each entry's outcome.

## Example

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

A **transaction** is processed atomically: every entry succeeds or none does. A
**batch** processes its entries independently, so some can succeed while others fail.
The tool sends the Bundle in one POST to the configured FHIR base. It does not split,
reorder, retry or simulate it.

Batch entries must not depend on each other; the server may process them in any order.
The tool scans string values under `reference` keys in entry resources and rejects
references to another POST entry's `fullUrl` beginning with `urn:uuid:` or `urn:oid:`.
It does not detect references to PUT entries, references in other fields such as
`Attachment.url`, or every other dependency. Use a transaction for related changes.

`prefer` is optional: `representation` (default) or `minimal`, sent as the
`Prefer: return=...` header. Servers may return less than requested.

## Supported entries

| Method | Route | Body |
|---|---|---|
| GET | `Type`, `Type?criteria`, `Type/id` | None |
| POST | `Type` | Resource of that type; optional `request.ifNoneExist` |
| PUT | `Type/id`, `Type?criteria` | Resource of that type |
| DELETE | `Type/id`, `Type?criteria` | None |
| PATCH | `Type/id` | FHIRPath Patch `Parameters` resource |

Search criteria are passed through unchanged, including repeated parameters,
`_include`, `_revinclude`, `:iterate` and chained parameters. A single leading `/` is
removed. The tool rejects absolute URLs, path traversal, percent-encoded path segments,
operations (`$...`), history, compartments, HEAD and instance queries such as
`Patient/123?_summary=true`. For PATCH entries it checks the shape of the `Parameters`
resource; the server evaluates the FHIRPath. The server resolves references and
`fullUrl` values.

A Bundle must contain at least one entry.

## Results

The tool returns a result object, not a Bundle. The same object is sent as MCP
structured content and as JSON text:

```json
{
  "interaction": "batch",
  "httpStatus": 200,
  "status": "partial",
  "headers": {"content-type": "application/fhir+json"},
  "response": {"resourceType": "Bundle", "type": "batch-response", "entry": ["..."]},
  "summary": {"entries": 2, "succeeded": 1, "failed": 1, "pending": 0, "unknown": 0},
  "error": {"kind": "batch-entry-failure", "message": "Inspect each entry outcome; do not replay successful entries."}
}
```

| Field | Meaning |
|---|---|
| `interaction` | `transaction` or `batch`; null when the Bundle type is neither |
| `httpStatus` | HTTP status returned by the server, or null if none was received |
| `status` | `success`, `partial`, `failure`, `pending` or `unknown` |
| `headers` | Selected response headers, such as `location` and `etag`; never cookies |
| `response` | The server's complete JSON response, usually the response Bundle |
| `summary` | Entry counts: `entries`, `succeeded`, `failed`, `pending`, `unknown` |
| `error` | Error `kind` and `message`, with an OperationOutcome for input errors |

| `status` | Meaning | MCP `isError` |
|---|---|---|
| `success` | Every entry succeeded | false |
| `partial` | A batch with failed entries and at least one successful or pending entry | false |
| `pending` | The request or at least one entry was accepted for asynchronous processing (HTTP 202), with no failed entries | false |
| `unknown` | The outcome cannot be determined, for example after a timeout or an inconsistent response | false |
| `failure` | Nothing was applied: the input was rejected, or the server rejected the request | true |

Only `failure` sets MCP `isError`. A `partial`, `pending` or `unknown` result may include
writes that were applied, and some MCP clients retry calls that return errors, which
would repeat those writes. Check `status` and each entry's `response.status` instead,
and do not resend entries that succeeded.

A transaction response whose entries are inconsistent with an atomic outcome is
reported as `unknown`. A timeout, a dropped connection, an unreadable success response
or an oversized response can happen after the server has applied the request; read the
current server state before retrying. The tool never retries a request itself. There is
no polling for asynchronous (`pending`) requests.

## Limits

| Setting | Default | Applies to |
|---|---|---|
| `FHIR_MCP_MAX_BUNDLE_ENTRIES` | `100` | Entries in one Bundle |
| `FHIR_MCP_MAX_PATCH_OPERATIONS` | `100` | Operations in one PATCH entry's `Parameters` |
| `FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES` | `1048576` (1 MiB) | Serialized Bundle size |
| `FHIR_MCP_MAX_INTERACTION_RESPONSE_BYTES` | `8388608` (8 MiB) | Response body size |

All limits must be positive. A Bundle over a limit is rejected, not split. The request
timeout is `FHIR_MCP_REQUEST_TIMEOUT` and covers the whole exchange. Redirects are not
followed, so credentials are never forwarded to another host.
