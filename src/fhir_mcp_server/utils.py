# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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

import aiohttp
import logging
import re

from pydantic import ValidationError

from fhir_mcp_server.oauth import ServerConfigs

from typing import Any, Dict, List, Optional
from fhirpy import AsyncFHIRClient
from mcp.shared._httpx_utils import create_mcp_http_client

logger: logging.Logger = logging.getLogger(__name__)


async def create_async_fhir_client(
    config: ServerConfigs,
    access_token: str | None = None,
    extra_headers: dict | None = None,
) -> AsyncFHIRClient:
    """Create a FHIR AsyncClient with defaults."""

    client_kwargs: Dict = {
        "url": config.server_base_url,
        "aiohttp_config": {
            "timeout": aiohttp.ClientTimeout(total=config.mcp_request_timeout),
        },
        "extra_headers": extra_headers,
    }
    if access_token:
        client_kwargs["authorization"] = f"Bearer {access_token}"

    return AsyncFHIRClient(**client_kwargs)


async def extract_bundle_resources(bundle: Dict[str, Any]) -> Dict[str, Any]:
    if bundle and "entry" in bundle and isinstance(bundle["entry"], list):
        logger.debug(f"found {len(bundle['entry'])} entries for type '{type}'")
        return {
            "resourceType": "Bundle",
            "entry": [
                entry.get("resource")
                for entry in bundle["entry"]
                if "resource" in entry
            ]
        }
    return bundle


def trim_resource_capabilities(
    capabilities: List[Dict[str, Any]],
) -> List[Dict[str, Optional[str]]]:
    logger.debug(
        f"trim_resource_capabilities called with {len(capabilities)} capabilities."
    )
    trimmed = [
        {
            "name": capability.get("name"),
            "documentation": capability.get("documentation"),
        }
        for capability in capabilities
        if "name" in capability or "documentation" in capability
    ]
    logger.debug(
        f"trim_resource_capabilities returning {len(trimmed)} trimmed capabilities."
    )
    return trimmed


async def get_operation_outcome_exception() -> dict:
    return await get_operation_outcome(
        code="exception", diagnostics="An unexpected internal error has occurred."
    )


async def get_operation_outcome_required_error(element: str = "") -> dict:
    return await get_operation_outcome(
        code="required", diagnostics=f"A required element {element} is missing."
    )


async def validate_resource_type(resource_type: str) -> dict | None:
    try:
        if not re.fullmatch(r"[A-Za-z]{1,64}", resource_type):
            logger.error(
                f"Invalid resource type '{resource_type}': must be 1-64 alphabetic characters."
            )
            return await get_operation_outcome(
                code="invalid",
                diagnostics=f"Invalid resource type '{resource_type}'. The type must be 1-64 alphabetic characters (e.g., 'Patient', 'Observation').",
            )
    except ValidationError as ex:
        logger.error(
            f"Invalid resource type '{resource_type}' provided. Caused by, ", exc_info=ex
        )
        return await get_operation_outcome(
            code="invalid",
            diagnostics=f"Invalid resource type '{resource_type}'. The type must be 1-64 alphabetic characters (e.g., 'Patient', 'Observation').",
        )
    return None


async def validate_resource_id(resource_id: str) -> dict | None:
    """Validate a FHIR logical id before it is interpolated into a request path.

   Rejects path separators, dot-segments and percent-encoded traversal sequences
   that would otherwise let the id escape the configured FHIR base path.
   """
    if not resource_id:
        return None  # empty id is valid: update/delete allow conditional operations

    # '.' is a legal FHIR id character, so dot-only ids (e.g. "..") must be rejected separately.
    if not re.fullmatch(r"[A-Za-z0-9\-\.]{1,64}", resource_id) or re.fullmatch(
        r"\.+", resource_id
    ):
        logger.error(
            f"Invalid resource id '{resource_id}': must be 1-64 characters of letters, digits, '-' or '.', and not only dots."
        )
        return await get_operation_outcome(
            code="invalid",
            diagnostics=f"Invalid resource id '{resource_id}'. The id must be 1-64 characters of letters, digits, '-' or '.' (e.g., '123', 'patient-001').",
        )
    return None


async def validate_operation(operation: str) -> dict | None:
    """Validate a FHIR operation name before it is interpolated into a request path."""
    if not operation:
        return None  # operation is optional
    if not re.fullmatch(r"[$_]?[A-Za-z][A-Za-z0-9\-]{0,63}", operation):
        logger.error(
            f"Invalid operation '{operation}': must be an alphanumeric name, optionally prefixed with '$' or '_'."
        )
        return await get_operation_outcome(
            code="invalid",
            diagnostics=f"Invalid operation '{operation}'. The operation must be an alphanumeric name optionally prefixed with '$' or '_' (e.g., '$everything', '_history').",
        )
    return None

async def validate_inputs(
    resource_type: str, resource_id: str = "", operation: str = ""
) -> dict | None:
    """Validate the type/id/operation path parameters for an FHIR interaction.

    Runs the individual validators in order and returns the first failure, or
    None if all inputs are valid.
    """
    return (
        await validate_resource_type(resource_type)
        or await validate_resource_id(resource_id)
        or await validate_operation(operation)
    )


async def get_operation_outcome(
    code: str, diagnostics: str, severity: str = "error"
) -> dict:
    return {
        "resourceType": "OperationOutcome",
        "issue": [
            {
                "severity": severity,
                "code": code,
                "diagnostics": diagnostics,
            }
        ],
    }


async def get_capability_statement(metadata_url: str) -> Dict[str, Any]:
    """
    Discover CapabilityStatement from server's metadata endpoint.
    """
    try:
        logger.debug(f"Fetching CapabilityStatement from {metadata_url}")
        async with create_mcp_http_client() as client:
            response = await client.get(url=metadata_url, headers=get_default_headers())
            response.raise_for_status()
            metadata_json = response.json()
            logger.debug(f"OAuth metadata discovered: {metadata_json}")
            return metadata_json
    except Exception as ex:
        logger.exception(
            "Unable to invoke the FHIR metadata endpoint. Caused by, ", exc_info=ex
        )
        raise ValueError("Unable to fetch FHIR metadata")


def get_default_headers() -> Dict[str, str]:
    return {"Accept": "application/fhir+json", "Content-Type": "application/fhir+json"}


def build_user_profile(resource: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build user profile dictionary from FHIR resource.

    Args:
        resource: The FHIR resource dictionary of the user.

    Returns:
        Dict containing only mandatory user fields
    """

    # Define fields to extract from the resource
    fields_to_extract = [
        "id",
        "resourceType",
        "name",
        "gender",
        "birthDate",
        "telecom",
        "address",
    ]

    profile: Dict[str, Any] = {}
    # Add fields only if they exist and have values
    for field in fields_to_extract:
        value = resource.get(field)
        if value is not None:
            profile[field] = value

    return profile
