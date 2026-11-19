# Copyright (c) 2025-2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain a copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

"""Bounded, single-attempt HTTP transport for FHIR writes. Redirects are not followed."""

import asyncio
from dataclasses import dataclass
import json
import logging
import time
from urllib.parse import urlsplit

import httpx
from mcp.shared._httpx_utils import create_mcp_http_client

from fhir_mcp_server.errors import FhirInputError, FhirTransportError
from fhir_mcp_server.oauth import ServerConfigs

logger = logging.getLogger(__name__)
RESPONSE_HEADERS = {
    "etag",
    "location",
    "last-modified",
    "content-location",
    "preference-applied",
    "retry-after",
    "content-type",
}


@dataclass
class FhirHttpResponse:
    status: int
    headers: dict[str, str]
    body: object = None
    body_is_json: bool = False
    has_body: bool = False


def request_url(base: str, relative_path: str) -> str:
    """Validate the configured HTTP(S) base and append an already validated resource path."""
    try:
        parts = urlsplit(base)
        if (
            parts.scheme not in ("http", "https")
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in base)
            or "\\" in base
        ):
            raise ValueError
        _ = parts.port
    except ValueError:
        raise FhirInputError(
            "Configured FHIR base URL must be HTTP(S), without credentials, query or fragment."
        ) from None
    return base.rstrip("/") + ("/" + relative_path if relative_path else "")


def parse_json(body: bytes) -> tuple[object, bool]:
    """Parse a JSON body, rejecting nonfinite constants. Return (value, is_json)."""

    def reject_constant(value):
        raise ValueError("Nonfinite JSON constant")

    try:
        return json.loads(body, parse_constant=reject_constant), True
    except (ValueError, UnicodeError, RecursionError):
        return None, False


async def send_fhir_request(
    config: ServerConfigs,
    access_token: str | None,
    method: str,
    relative_path: str,
    body: bytes,
    *,
    content_type: str = "application/fhir+json",
    prefer: str = "representation",
    tool: str,
    count: int = 0,
) -> FhirHttpResponse:
    """Send one bounded write request without redirects or retries.

    Return the observed status, allowlisted headers and parsed JSON body. A failure after
    the request was sent is uncertain, because the server may have applied it.
    """
    if len(body) > config.mcp_max_interaction_request_bytes:
        raise FhirInputError("Request exceeds the configured byte limit.", "too-costly")
    url = request_url(config.server_base_url, relative_path)
    headers = {
        "Accept": "application/fhir+json",
        "Content-Type": content_type,
        "Prefer": "return=" + prefer,
    }
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    observed_status = None
    observed_headers = {}
    started = time.monotonic()
    try:
        # httpx timeouts apply per phase; asyncio.timeout bounds the whole exchange.
        async with asyncio.timeout(config.mcp_request_timeout):
            async with create_mcp_http_client(
                timeout=httpx.Timeout(config.mcp_request_timeout)
            ) as client:
                async with client.stream(
                    method, url, content=body, headers=headers, follow_redirects=False
                ) as response:
                    observed_status = response.status_code
                    observed_headers = {
                        key: response.headers[key]
                        for key in RESPONSE_HEADERS
                        if key in response.headers
                    }
                    chunks = bytearray()
                    async for chunk in response.aiter_bytes():
                        if (
                            len(chunks) + len(chunk)
                            > config.mcp_max_interaction_response_bytes
                        ):
                            raise FhirTransportError(
                                "response-too-large",
                                "Response exceeded the byte limit; reconcile server state before retrying.",
                                status=observed_status,
                                headers=observed_headers,
                            )
                        chunks.extend(chunk)
                    parsed, is_json = parse_json(bytes(chunks)) if chunks else (None, False)
                    return FhirHttpResponse(
                        observed_status, observed_headers, parsed, is_json, bool(chunks)
                    )
    except (httpx.ConnectError, httpx.ConnectTimeout):
        raise FhirTransportError(
            "network",
            "Could not connect to the FHIR server; request was not sent.",
            uncertain=False,
        ) from None
    except (TimeoutError, httpx.TimeoutException):
        raise FhirTransportError(
            "timeout",
            "Request timed out; reconcile server state before retrying.",
            status=observed_status,
            headers=observed_headers,
        ) from None
    except httpx.HTTPError:
        raise FhirTransportError(
            "network",
            "Connection failed; reconcile server state before retrying.",
            status=observed_status,
            headers=observed_headers,
        ) from None
    finally:
        logger.info(
            "FHIR tool=%s method=%s count=%s status=%s duration_ms=%d",
            tool,
            method,
            count,
            observed_status,
            (time.monotonic() - started) * 1000,
        )
