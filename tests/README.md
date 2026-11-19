# FHIR MCP Server Test Suite

Run commands from the repository root with the project dependencies installed.
The suite includes unit tests, HTTP transport tests, and MCP end-to-end tests.
Some tests contact a public server and create resources; select the offline suite
for routine development.

## Offline suite

```bash
PYTHONPATH=src python -m pytest tests/ -k "not test_tool_"
```

PowerShell:

```powershell
$env:PYTHONPATH = "src"
.venv\Scripts\python.exe -m pytest tests/ -k "not test_tool_"
```

The offline suite includes real loopback HTTP and MCP connections to recording
FHIR stubs. External dependencies in other unit/integration tests are mocked.
The e2e launcher clears inherited FHIR settings and overrides credentials from
`.env` so deployment credentials cannot be sent to test servers.

## Test organization

- `tests/unit/`: configuration, authentication helpers, response filtering,
  interaction validation and result classification.
- `tests/integration/test_fhir_http.py`: exact HTTP requests, byte limits,
  redirects, timeouts and disconnects against a local recorder.
- `tests/integration/test_interaction_handlers.py`: tool validation and authentication.
- `tests/e2e/test_execute_bundle.py`: Bundle calls over MCP against a local FHIR stub.
- `tests/e2e/test_credential_isolation.py`: anonymous test-server requests carry no Authorization header.
- `tests/e2e/test_live_cleanup.py`: offline checks of live-test cleanup, including failures and ownership checks.
- `tests/e2e/test_tools.py`: live `test_tool_*` cases and offline path-validation regressions.

Only live cases use names containing `test_tool_`. Do not use that substring for
a new offline test: the standard offline selection would silently exclude it.
Inspect selection with `python -m pytest tests/ --collect-only -k "test_tool_"`.

## Live tests

```bash
PYTHONPATH=src python -m pytest tests/e2e/test_tools.py -k "test_tool_"
```

These tests use the public HAPI FHIR R4 server at `https://hapi.fhir.org/baseR4`.
The Bundle cases cover linked-resource transactions, rollback and partial batches.
All write tests use a unique identifier under `urn:fhir-mcp-server:e2e` and log
that identifier. Updates preserve it. Fixture teardown runs after setup or test
failures, finds only exact identifier matches, deletes Observations before
Patients, and verifies that both searches return no resources. Already-deleted
resources are tolerated; failed searches, failed deletions and remaining resources
fail cleanup. A lost connection can still prevent cleanup; retain the logged
identifier and reconcile only that run's resources before claiming cleanup succeeded.

## Coverage and dependencies

`pytest.ini` enables coverage reporting. Use the output of the current run;
coverage depends on the selected tests, and MCP subprocess execution is not
automatically included in the parent process's coverage. The server is exercised
both by handler tests and by MCP e2e tests.

Install the project's test dependencies with `pip install -e ".[test]"`.
