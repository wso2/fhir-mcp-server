"""Bounded, single-attempt transport for FHIR mutations. No redirect following."""

import asyncio
from dataclasses import dataclass
import json
import logging
import time
from urllib.parse import urlsplit
from uuid import uuid4

import aiohttp

from fhir_mcp_server.interactions import FhirInputError, FhirTransportError
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


async def send_fhir_request(
    config: ServerConfigs,
    access_token: str | None,
    method: str,
    relative_path: str,
    body: bytes,
    *,
    content_type: str = "application/fhir+json",
    if_match: str | None = None,
    prefer: str = "representation",
    interaction: str = "patch",
    count: int = 0,
) -> FhirHttpResponse:
    """Send one bounded mutation request without redirects or retries.

    Return the observed status, allowlisted headers and parsed JSON body. Failures after
    dispatch are uncertain because the server may have committed.
    """
    url = request_url(config.server_base_url, relative_path)
    headers = {
        "Accept": "application/fhir+json",
        "Content-Type": content_type,
        "Prefer": "return=" + prefer,
    }
    if access_token:
        headers["Authorization"] = "Bearer " + access_token
    if if_match is not None:
        headers["If-Match"] = if_match
    observed_status = None
    observed_headers = {}
    started = time.monotonic()
    correlation_id = uuid4().hex
    try:
        async with aiohttp.ClientSession(
            timeout=aiohttp.ClientTimeout(total=config.mcp_request_timeout)
        ) as session:
            async with session.request(
                method, url, data=body, headers=headers, allow_redirects=False
            ) as response:
                observed_status = response.status
                observed_headers = {
                    key: response.headers[key]
                    for key in RESPONSE_HEADERS
                    if key in response.headers
                }
                chunks = bytearray()
                async for chunk in response.content.iter_chunked(65536):
                    if (
                        len(chunks) + len(chunk)
                        > config.mcp_max_interaction_response_bytes
                    ):
                        raise FhirTransportError(
                            "response-too-large",
                            "Response exceeded the byte limit; reconcile server state before retrying.",
                            status=response.status,
                            headers=observed_headers,
                        )
                    chunks.extend(chunk)
                parsed = None
                is_json = False
                if chunks:
                    try:

                        def reject_constant(value):
                            """Reject nonfinite JSON constants instead of treating the response
                            as valid JSON.
                            """
                            raise ValueError("Nonfinite JSON constant")

                        parsed = json.loads(chunks, parse_constant=reject_constant)
                        is_json = True
                    except (ValueError, UnicodeError, RecursionError):
                        pass
                return FhirHttpResponse(
                    response.status, observed_headers, parsed, is_json, bool(chunks)
                )
    except aiohttp.ClientConnectorError:
        raise FhirTransportError(
            "network",
            "Could not connect to the FHIR server; request was not sent.",
            uncertain=False,
        ) from None
    except asyncio.TimeoutError:
        raise FhirTransportError(
            "timeout",
            "Request timed out; reconcile server state before retrying.",
            status=observed_status,
            headers=observed_headers,
        ) from None
    except aiohttp.ClientError:
        raise FhirTransportError(
            "network",
            "Connection failed; reconcile server state before retrying.",
            status=observed_status,
            headers=observed_headers,
        ) from None
    finally:
        logger.info(
            "FHIR tool=%s method=%s interaction=%s count=%s status=%s duration_ms=%d correlation_id=%s",
            "patch" if interaction == "patch" else "execute_bundle",
            method,
            interaction,
            count,
            observed_status,
            (time.monotonic() - started) * 1000,
            correlation_id,
        )
