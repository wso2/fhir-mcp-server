# Local Aidbox integration client

The local MCP connection uses Aidbox `Client/fhir-mcp-writer`, provisioned on
2026-10-20. It replaces the root bearer token previously used by this checkout.

## Permissions

`AccessPolicy/fhir-mcp-writer-resources` grants FHIR search, read, version read,
create, update, JSON PATCH and delete for Patient, Observation, Encounter,
Organization, Location and Questionnaire. Conditional update, patch and delete
routes are also permitted for those types. The policy matches the specific client,
operation IDs and resource types; it is not an unrestricted `allow` policy.

`AccessPolicy/fhir-mcp-writer-bundles` permits the `/fhir` Bundle execution route.
Aidbox checks each entry's permissions as well. Both transaction and batch are
permitted. Direct native Aidbox CRUD routes are not granted.

These are resource-type permissions across the local dataset, not permissions
limited to a patient or a record owner. Search inclusion traversal has not been
audited as a data-isolation boundary. Existing global Aidbox policies still apply.
Direct reads and writes to Client, AccessPolicy and User were denied in setup
checks; direct Condition search was also denied.

## Credentials and renewal

- `.aidbox-client.env` stores `AIDBOX_CLIENT_ID` and `AIDBOX_CLIENT_SECRET`.
- `.env` stores `FHIR_SERVER_ACCESS_TOKEN` and the existing connection settings.
- Both files are ignored by Git. Do not copy their contents into documentation.
- The client supports only the `client_credentials` grant and issues JWT access
  tokens with a configured 24-hour lifetime. MCP does not renew these automatically.

From the project directory, obtain a new token before starting MCP:

```powershell
.\.venv\Scripts\python.exe scripts\refresh-aidbox-token.py
.\.venv\Scripts\python.exe -m fhir_mcp_server --transport streamable-http
```

Stop the existing MCP process before starting another listener on port 8000.
Renewal changes `.env`; an already running server must be restarted to load it.
The helper is deliberately restricted to this local Aidbox URL, disables redirects
and proxy environment inheritance, checks one allowed and one denied request,
and prints no credentials. It does not require the root secret.

MCP remains bound to `127.0.0.1:8000`, with incoming MCP authentication disabled.
Local callers share the dedicated client's permissions.

## Live verification

Direct Aidbox checks using this client confirmed:

- Patient create, read, update and delete succeeded.
- JSON PATCH with a current `If-Match` succeeded; repeating the old version
  precondition returned HTTP 412.
- A permitted two-entry transaction succeeded.
- A transaction containing a Patient write and a forbidden Condition read returned
  HTTP 400 with an OperationOutcome `forbidden` issue; the Patient was absent.
- The equivalent batch returned HTTP 200 with entry statuses 201 and 403; its
  successful Patient write persisted.
- A batch containing a Client read returned 403 for that entry. The transaction
  equivalent returned HTTP 400 with a `forbidden` issue.
- All disposable Patient records were deleted; their history may remain in Aidbox.
- After restart, MCP Patient search worked and an administrative read returned an
  error without a resource. The existing MCP reports upstream 403 as a generic
  `exception` OperationOutcome, which should be improved during transport work.

The initial checks used direct HTTP. Subsequent opt-in acceptance also verified the
implemented MCP tools, including Parameters patches, rollback after PATCH and
return preferences. Writes require `FHIR_MCP_ENABLE_WRITE_TOOLS=True`; the default
remains false. See [the tool guide](bundle-and-patch.md).

See [the implementation design](bundle-and-patch-design.md) for the proposed tools.
