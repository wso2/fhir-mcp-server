"""Test subprocess settings without contacting any FHIR server."""

import json
import subprocess
import sys

import pytest

from tests.e2e.conftest import build_mcp_test_environment


@pytest.mark.parametrize("inherited_credentials", [False, True])
def test_e2e_subprocess_does_not_load_deployment_credentials(
    tmp_path, monkeypatch, inherited_credentials
):
    credential_names = (
        "FHIR_SERVER_ACCESS_TOKEN", "FHIR_SERVER_CLIENT_ID",
        "FHIR_SERVER_CLIENT_SECRET", "FHIR_SERVER_SCOPES",
    )
    (tmp_path / ".env").write_text(
        "\n".join(f'{key}="dummy-file-value"' for key in credential_names),
        encoding="utf-8",
    )
    for key in credential_names:
        if inherited_credentials:
            monkeypatch.setenv(key, "dummy-parent-value")
        else:
            monkeypatch.delenv(key, raising=False)
    env = build_mcp_test_environment("http://127.0.0.1:12345/fhir")
    probe = """
import json
from fhir_mcp_server.oauth.types import ServerConfigs
c = ServerConfigs()
print(json.dumps({
    "has_credentials": any([c.server_access_token, c.server_client_id,
                            c.server_client_secret, c.server_scopes]),
    "base_url": c.server_base_url,
    "anonymous": c.server_disable_authorization,
}))
"""
    result = subprocess.run(
        [sys.executable, "-c", probe], cwd=tmp_path, env=env,
        capture_output=True, text=True, check=True, timeout=20,
    )
    assert json.loads(result.stdout) == {
        "has_credentials": False,
        "base_url": "http://127.0.0.1:12345/fhir",
        "anonymous": True,
    }
