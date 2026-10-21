"""Renew this checkout's local Aidbox service token without printing credentials."""

from datetime import datetime, timedelta, timezone
from pathlib import Path
import sys

from dotenv import dotenv_values, set_key
import httpx


ROOT = Path(__file__).resolve().parents[1]
ENV_FILE = ROOT / ".env"
CREDENTIAL_FILE = ROOT / ".aidbox-client.env"
AIDBOX_URL = "http://127.0.0.1:8080"


def main() -> None:
    settings = dotenv_values(ENV_FILE, interpolate=False)
    credentials = dotenv_values(CREDENTIAL_FILE, interpolate=False)
    if settings.get("FHIR_SERVER_BASE_URL", "").rstrip("/") != AIDBOX_URL + "/fhir":
        raise RuntimeError("This helper requires the local Aidbox FHIR URL in .env.")
    client_id = credentials.get("AIDBOX_CLIENT_ID")
    secret = credentials.get("AIDBOX_CLIENT_SECRET")
    if client_id != "fhir-mcp-writer" or not secret:
        raise RuntimeError("Dedicated client credentials are missing from .aidbox-client.env.")

    with httpx.Client(timeout=30, follow_redirects=False, trust_env=False) as client:
        response = client.post(
            AIDBOX_URL + "/auth/token",
            auth=(client_id, secret),
            data={"grant_type": "client_credentials"},
        )
        if response.status_code != 200:
            raise RuntimeError(f"Token issuance failed (HTTP {response.status_code}).")
        payload = response.json()
        token = payload.get("access_token")
        if not isinstance(token, str) or not token:
            raise RuntimeError("Token endpoint returned no access token.")
        headers = {"Authorization": "Bearer " + token}
        allowed = client.get(AIDBOX_URL + "/fhir/Patient?_count=0", headers=headers)
        denied = client.get(AIDBOX_URL + "/Client/root", headers=headers)
        if allowed.status_code != 200 or denied.status_code != 403:
            raise RuntimeError("Dedicated client permission checks failed; .env was not changed.")

    set_key(ENV_FILE, "FHIR_SERVER_ACCESS_TOKEN", token)
    expires_in = payload.get("expires_in")
    print("Dedicated Aidbox token saved to ignored .env; credentials were not printed.")
    if isinstance(expires_in, (int, float)) and expires_in > 0:
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=expires_in)
        print(f"Token expires approximately {expires_at.isoformat()}.")
    else:
        print("Client policy sets a 24-hour token lifetime; response omitted expires_in.")
    print("Restart the MCP server to load the new token.")


if __name__ == "__main__":
    try:
        main()
    except (httpx.HTTPError, OSError, ValueError):
        # Do not emit response bodies, parsed credentials or HTTP debug tracebacks.
        sys.exit("Token renewal failed; check local Aidbox availability and credential file format.")
    except RuntimeError as exc:
        sys.exit(str(exc))
