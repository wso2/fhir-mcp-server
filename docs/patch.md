# Patching a resource with JSON Patch

`patch` applies a JSON Patch (RFC 6902) to one resource with the FHIR `patch`
interaction: `PATCH [base]/{type}/{id}` with `Content-Type: application/json-patch+json`.

## Example

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

All six operations are supported: `add`, `remove`, `replace`, `move`, `copy` and `test`.
The tool keeps their order, any additional members and explicit `null` values. It checks
the structure of each operation and the JSON Pointer syntax of `path` and `from`; the
server evaluates the paths and applies the changes. A failing `test` operation makes the
server reject the whole patch.

## Concurrency with If-Match

`if_match` is optional. Pass the resource's current version from an earlier read, as a
weak ETag (`W/"7"`) or a strong one (`"7"`), and it is sent unchanged as the `If-Match`
header. FHIR represents a resource version as a weak ETag, `W/"` + `meta.versionId` +
`"`. If the resource has changed since, the server rejects the patch: the FHIR
specification uses HTTP 412. Read the
resource again and reassess the change instead of retrying. Without `if_match` the patch
is applied to whatever version is current, which can be unsafe for edits to array
elements by index.

Wildcards (`*`), multiple tags and unquoted values are rejected.

`prefer` is optional: `representation` (default) or `minimal`, sent as the
`Prefer: return=...` header.

## Results

`patch` returns the same result object as `execute_bundle` (see
[Executing transaction and batch Bundles](execute-bundle.md#results)), with
`interaction` set to `patch` and no `summary`. `response` holds the patched resource
when the server returns one. `headers` includes `etag` when the server sends it.
Otherwise, use `response.meta.versionId` if a resource containing that field is
returned. A successful response may contain neither an ETag nor a resource body,
especially with `prefer: "minimal"`; read the resource again to obtain its version.

| `status` | Meaning | MCP `isError` |
|---|---|---|
| `success` | The patch was applied | false |
| `pending` | The server accepted the request for asynchronous processing (HTTP 202) | false |
| `unknown` | The outcome cannot be determined, for example after a timeout or when the server returns a different resource | false |
| `failure` | The patch was not applied: the input was rejected, or the server rejected the request | true |

After a timeout or an `unknown` result the patch may have been applied; read the resource
before retrying.

## Limits

The number of operations is limited by `FHIR_MCP_MAX_PATCH_OPERATIONS` (default `100`)
and the serialized size by `FHIR_MCP_MAX_INTERACTION_REQUEST_BYTES`. The response size
limit and timeout are the same as for `execute_bundle`.

JSON Patch is the only format supported directly. FHIRPath Patch (`Parameters`) is
supported inside Bundles through `execute_bundle`. Merge Patch, XML and JSON Patch
wrapped in a `Binary` resource are not supported.
