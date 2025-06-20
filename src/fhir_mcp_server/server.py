# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

# WSO2 LLC. licenses this file to you under the Apache License,
# Version 2.0 (the "License"); you may not use this file except
# in compliance with the License.
# You may obtain postgres_pgvector copy of the License at

# http://www.apache.org/licenses/LICENSE-2.0

# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied. See the License for the
# specific language governing permissions and limitations
# under the License.

import click
import logging
import sys

from fhir_mcp_server.utils import (
    create_async_fhir_client,
    get_bundle_entries,
    get_default_headers,
    get_operation_outcome_error,
    get_operation_outcome_exception,
    get_operation_outcome_required_error,
    get_capability_statement,
    trim_resource,
)
from fhir_mcp_server.oauth import (
    handle_failed_authentication,
    handle_successful_authentication,
    OAuthServerProvider,
    FHIRClientProvider,
    OAuthToken,
    ServerConfigs,
)
from fhirpy import AsyncFHIRClient
from fhirpy.lib import AsyncFHIRResource
from fhirpy.base.exceptions import OperationOutcome
from fhirpy.base.searchset import Raw
from typing import Dict, Any, Optional
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response, HTMLResponse
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp.server import FastMCP

logger: logging.Logger = logging.getLogger(__name__)


configs: ServerConfigs = ServerConfigs()

server_provider: OAuthServerProvider = OAuthServerProvider(configs=configs)

auth_settings: AuthSettings = AuthSettings(
    issuer_url=AnyHttpUrl(configs.effective_server_url),
    client_registration_options=ClientRegistrationOptions(
        enabled=True,
        valid_scopes=configs.oauth.scopes,
        default_scopes=configs.oauth.scopes,
    ),
)

mcp: FastMCP = FastMCP(
    name="FHIR MCP Server",
    instructions="This server implements the HL7 FHIR MCP for secure, standards-based access to FHIR resources",
    auth_server_provider=server_provider,
    host=configs.host,
    port=configs.port,
    auth=auth_settings,
    json_response=True,
    stateless_http=True,
)

client_provider: FHIRClientProvider = FHIRClientProvider(
    callback_url=AnyHttpUrl(configs.fhir.callback_url(configs.effective_server_url)),
    configs=configs.fhir,
)


@mcp.custom_route("/fhir/callback", methods=["GET"])
async def handle_fhir_server_callback(request: Request) -> HTMLResponse:
    """Handle FHIR OAuth redirect."""
    code: str | None = request.query_params.get("code")
    state: str | None = request.query_params.get("state")

    if not code or not state:
        return handle_failed_authentication("Missing code or state parameter")

    try:
        await client_provider.handle_fhir_oauth_callback(code, state)
        return handle_successful_authentication()
    except Exception as ex:
        logger.error(
            "Error occurred while handling FHIR oauth callback. Caused by, ",
            exc_info=ex,
        )
        return handle_failed_authentication("Something went wrong.")


@mcp.custom_route("/oauth/callback", methods=["GET"])
async def handle_auth_server_callback(request: Request) -> Response:
    """Handle MCP OAuth redirect."""
    code: str | None = request.query_params.get("code")
    state: str | None = request.query_params.get("state")

    if not code or not state:
        return handle_failed_authentication("Missing code or state parameter")

    try:
        redirect_uri: str = await server_provider.handle_mcp_oauth_callback(code, state)
        return RedirectResponse(status_code=302, url=redirect_uri)
    except Exception as ex:
        logger.error(
            "Error occurred while handling MCP oauth callback. Caused by, ", exc_info=ex
        )
        return handle_failed_authentication("Something went wrong.")


async def get_user_access_token() -> OAuthToken | None:
    """Get the access token for the authenticated user."""
    if configs.fhir.access_token:
        logger.debug("Using configured FHIR access token for user.")
        return OAuthToken(access_token=configs.fhir.access_token, token_type="Bearer")

    client_access_token: AccessToken | None = get_access_token()
    if not client_access_token:
        raise ValueError("Failed to obtain client access token.")

    return await client_provider.get_access_token(client_access_token.token)


async def get_async_fhir_client() -> AsyncFHIRClient:
    """Get an async FHIR client with user access token."""
    user_token: OAuthToken | None = await get_user_access_token()
    if not user_token:
        raise ValueError("User is not authenticated")

    logger.debug(
        f"Creating async FHIR client with access token: {user_token.access_token}"
    )
    return await create_async_fhir_client(
        config=configs.fhir,
        access_token=user_token.access_token,
        extra_headers=get_default_headers(),
    )


@mcp.tool()
async def get_capabilities(type: str) -> Dict[str, Any]:
    """
    Retrieves metadata about a specified FHIR resource type, including its supported search parameters and custom operations.

    This tool should be used at the start of any workflow where you need to discover what queries or operations are permitted
    against that resource (e.g., before calling search, read, or create). Do not use this tool to fetch actual resources.
    It only returns definitions and descriptions of capabilities, not resource instances. Because FHIR defines different search
    parameters and operations per resource type, this tool ensures your subsequent calls use valid inputs.

    Args:
        type (str): The FHIR resource type name (e.g., "Patient", "Observation", "Encounter").
                Must exactly match one of the core or profile-defined resource types supported by the server.

    Returns:
        Dict[str, Any]:
            A dictionary containing:
            - "type" (str): The requested resource type (if available) or empty.
            - "searchParam" (Dict[str, str]): A map of FHIR search-parameter names. Each key is the parameter name
                    (e.g., "family", "_id", "_lastUpdated"), and each value is the FHIR-provided description of that parameter's meaning and usage constraints.
            - "operation" (Dict[str, str]): A map of custom FHIR operation names to their descriptions.
                    Each key is the operation name (e.g., "$validate"), and each value explains the operation's purpose.
    """

    try:
        logger.debug(f"Invoked with resource_type='{type}'")
        data: Dict[str, Any] = await get_capability_statement(configs.fhir.metadata_url)
        for resource in data["rest"][0]["resource"]:
            if resource.get("type") == type:
                logger.info(f"Resource type '{type}' found in the CapabilityStatement.")
                return {
                    "type": resource.get("type"),
                    "searchParam": trim_resource(resource.get("searchParam", [])),
                    "operation": trim_resource(resource.get("operation", [])),
                }
        logger.info(f"Resource type '{type}' not found in the CapabilityStatement.")
        return await get_operation_outcome_error(
            code="not-supported",
            diagnostics=f"The interaction, operation, resource or profile {type} is not supported.",
        )
    except Exception as ex:
        logger.exception(
            f"Error while executing the FHIR metadata interaction for resource_type '{type}'. Caused by, ",
            exc_info=ex,
        )
    return await get_operation_outcome_exception()


@mcp.tool()
async def search(
    type: str, searchParam: Dict[str, str]
) -> list[AsyncFHIRResource] | Dict[str, Any]:
    """
    Executes a standard FHIR search interaction on a given resource type, returning a bundle or list of matching resources.

    Use this when you need to query for multiple resources based on one or more search-parameters.
    Do not use this tool for create, update, or delete operations, and be aware that large result sets may be paginated by the FHIR server.

    Args:
        type (str): The FHIR resource type name (e.g., "MedicationRequest", "Condition", "Procedure").
                Must exactly match one of the core or profile-defined resource types supported by the server.
        searchParam (Dict[str, str]): A mapping of FHIR search parameter names to their desired values (e.g., {"family":"Smith","birthdate":"1970-01-01"}).
                These parameters refine queries for operation-specific query qualifiers.
                Only parameters exposed by `get_capabilities` for that resource type are valid.

    Returns:
        Dict[str, Any]: A dictionary containing the full FHIR resource instance matching the search criteria.
    """

    try:
        logger.debug(f"Invoked with type='{type}' and searchParam={searchParam}")
        if not type:
            logger.error(
                "Unable to perform search operation: 'type' is a mandatory field."
            )
            return await get_operation_outcome_required_error("type")

        client: AsyncFHIRClient = await get_async_fhir_client()
        return await client.resources(type).search(Raw(**searchParam)).fetch()
    except ValueError as ex:
        logger.exception(
            f"User does not have permission to perform FHIR '{type}' resource search operation. Caused by, ",
            exc_info=ex,
        )
        return await get_operation_outcome_error(
            code="forbidden",
            diagnostics=f"The user does not have the rights to perform search operation.",
        )
    except OperationOutcome as ex:
        logger.exception(
            f"FHIR server returned an OperationOutcome error while searching the resource: '{type}', Caused by,",
            exc_info=ex,
        )
        return ex.resource["issue"] or await get_operation_outcome_exception()
    except Exception as ex:
        logger.exception(
            f"An unexpected error occurred during the FHIR search operation for resource: '{type}'. Caused by, ",
            exc_info=ex,
        )
    return await get_operation_outcome_exception()


@mcp.tool()
async def read(
    type: str,
    id: str,
    searchParam: Optional[Dict[str, str]] = None,
    operation: Optional[str] = "",
) -> Dict[str, Any]:
    """
    Performs a FHIR "read" interaction to retrieve a single resource instance by its type and resource ID,
    optionally refining the response with search parameters or custom operations.

    Use it when you know the exact resource ID and require that one resource; do not use it for bulk queries.
    If additional query-level parameters or operations are needed (e.g., _elements or $validate), include them in searchParam or operation.

    Args:
        type (str): The FHIR resource type name (e.g., "DiagnosticReport", "AllergyIntolerance", "Immunization").
                Must exactly match one of the core or profile-defined resource types supported by the server.
        id (str): The logical ID of a specific FHIR resource instance.
        searchParam (Dict[str, str]): A mapping of FHIR search parameter names to their desired values (e.g., {"device-name":"glucometer"}).
                These parameters refine queries for operation-specific query qualifiers.
                Only parameters exposed by `get_capabilities` for that resource type are valid.
        operation (Optional[str]): The name of a custom FHIR operation or extended query defined for the resource (e.g., "$everything").
                Must match one of the operation names returned by `get_capabilities`.

    Returns:
        Dict[str, Any]: A dictionary containing the single FHIR resource instance of the requested type and id.
    """

    try:
        logger.debug(
            f"Invoked with type='{type}', id={id}, searchParam={searchParam}, and operation={operation}"
        )
        if not type:
            logger.error(
                "Unable to perform read operation: 'type' is a mandatory field."
            )
            return await get_operation_outcome_required_error("type")

        client: AsyncFHIRClient = await get_async_fhir_client()
        bundle: dict = await client.resource(resource_type=type, id=id).execute(
            operation=operation or "", method="GET", params=searchParam
        )

        return await get_bundle_entries(bundle=bundle)
    except ValueError as ex:
        logger.exception(
            f"User does not have permission to perform FHIR '{type}' resource read operation. Caused by, ",
            exc_info=ex,
        )
        return await get_operation_outcome_error(
            code="forbidden",
            diagnostics=f"The user does not have the rights to perform read operation.",
        )
    except OperationOutcome as ex:
        logger.exception(
            f"FHIR server returned an OperationOutcome error while reading the resource: '{type}', Caused by,",
            exc_info=ex,
        )
        return ex.resource["issue"] or await get_operation_outcome_exception()
    except Exception as ex:
        logger.exception(
            f"An unexpected error occurred during the FHIR read operation for resource: '{type}'. Caused by, ",
            exc_info=ex,
        )
    return await get_operation_outcome_exception()


@mcp.tool()
async def create(
    type: str,
    payload: Dict[str, Any],
    searchParam: Optional[Dict[str, str]] = None,
    operation: Optional[str] = "",
) -> Dict[str, Any]:
    """
    Executes a FHIR "create" interaction to persist a new resource of the specified type. It is required to supply the full resource payload in JSON form.

    Use this tool when you need to add new data (e.g., a new Patient or Observation). Do not call it to update existing resources; for updates, use patch.
    Note that servers may reject resources that violate profiles or mandatory bindings.

    Args:
        type (str): The FHIR resource type name (e.g., "Device", "CarePlan", "Goal").
                Must exactly match one of the core or profile-defined resource types supported by the server.
        payload (Dict[str, str]): A JSON object representing the full FHIR resource body to be created.
                It must include all required elements of the resource's profile.
        searchParam (Dict[str, str]): A mapping of FHIR search parameter names to their desired values (e.g., {"address-city":"Boston"}).
                These parameters refine queries for operation-specific query qualifiers.
                Only parameters exposed by `get_capabilities` for that resource type are valid.
        operation (Optional[str]): The name of a custom FHIR operation or extended query defined for the resource (e.g., "$evaluate").
                Must match one of the operation names returned by `get_capabilities`.

    Returns:
        Dict[str, Any]: A dictionary containing the newly created FHIR resource, including server-assigned fields (id, meta.versionId, meta.lastUpdated,
                and any server-added extensions). Reflects exactly what was persisted.
    """

    try:
        logger.debug(
            f"Invoked with type='{type}', payload={payload}, searchParam={searchParam}, and operation={operation}"
        )
        if not type:
            logger.error(
                "Unable to perform create operation: 'type' is a mandatory field."
            )
            return await get_operation_outcome_required_error("type")

        client: AsyncFHIRClient = await get_async_fhir_client()
        bundle: dict = await client.resource(resource_type=type).execute(
            operation=operation or "", data=payload, params=searchParam
        )

        return await get_bundle_entries(bundle=bundle)
    except ValueError as ex:
        logger.exception(
            f"User does not have permission to perform FHIR '{type}' resource create operation. Caused by, ",
            exc_info=ex,
        )
        return await get_operation_outcome_error(
            code="forbidden",
            diagnostics=f"The user does not have the rights to perform create operation.",
        )
    except OperationOutcome as ex:
        logger.exception(
            f"FHIR server returned an OperationOutcome error while creating the resource: '{type}', Caused by,",
            exc_info=ex,
        )
        return ex.resource["issue"] or await get_operation_outcome_exception()
    except Exception as ex:
        logger.exception(
            f"An unexpected error occurred during the FHIR create operation for resource: '{type}'. Caused by, ",
            exc_info=ex,
        )
    return await get_operation_outcome_exception()


@mcp.tool()
async def update(
    type: str,
    id: str,
    payload: Dict[str, Any],
    searchParam: Optional[Dict[str, str]] = None,
    operation: Optional[str] = "",
) -> Dict[str, Any]:
    """
    Performs a FHIR "update" interaction by replacing an existing resource instance's content with the provided payload.

    Use it when you need to overwrite a resource's data in its entirety, such as correcting or completing a record, and you already know the resource's logical id.
    Optionally, you can include searchParam for conditional updates (e.g., only update if the resource matches certain criteria) or specify a
    custom operation (e.g., "$validate" to run validation before updating). The tool returns the updated resource or an OperationOutcome detailing any errors.

    Args:
        type (str): The FHIR resource type name (e.g., "Location", "Organization", "Coverage").
        id (str): The logical ID of a specific FHIR resource instance.
                Must exactly match one of the core or profile-defined resource types supported by the server.
        payload (Dict[str, Any]): The complete JSON representation of the FHIR resource, containing all required elements and any optional data.
                Servers replace the existing resource with this exact content, so the payload must include all mandatory fields defined by the resource's profile
                and any previous data you wish to preserve.
        searchParam (Dict[str, str]): A mapping of FHIR search parameter names to their desired values (e.g., {"patient":"Patient/54321","relationship":"father"}).
                These parameters refine queries for operation-specific query qualifiers.
                Only parameters exposed by `get_capabilities` for that resource type are valid.
        operation (Optional[str]): The name of a custom FHIR operation or extended query defined for the resource (e.g., "$lastn").
                Must match one of the operation names returned by `get_capabilities`.

    Returns:
        Dict[str, Any]: A dictionary containing the updated FHIR resource after applying the JSON Patch operations..
    """

    try:
        logger.debug(
            f"Invoked with type='{type}', id={id}, payload={payload}, searchParam={searchParam}, and operation={operation}"
        )
        if not type:
            logger.error(
                "Unable to perform update operation: 'type' is a mandatory field."
            )
            return await get_operation_outcome_required_error("type")

        client: AsyncFHIRClient = await get_async_fhir_client()
        bundle: dict = await client.resource(resource_type=type, id=id).execute(
            operation=operation or "",
            method="PUT",
            data={id: id, **payload},
            params=searchParam,
        )
        return await get_bundle_entries(bundle=bundle)
    except ValueError as ex:
        logger.exception(
            f"User does not have permission to perform FHIR '{type}' resource update operation. Caused by, ",
            exc_info=ex,
        )
        return await get_operation_outcome_error(
            code="forbidden",
            diagnostics=f"The user does not have the rights to perform update operation.",
        )
    except OperationOutcome as ex:
        logger.exception(
            f"FHIR server returned an OperationOutcome error while updating the resource: '{type}', Caused by,",
            exc_info=ex,
        )
        return ex.resource["issue"] or await get_operation_outcome_exception()
    except Exception as ex:
        logger.exception(
            f"An unexpected error occurred during the FHIR update operation for resource: '{type}'. Caused by, ",
            exc_info=ex,
        )
    return await get_operation_outcome_exception()


@mcp.tool()
async def delete(
    type: str,
    id: Optional[str] = "",
    searchParam: Optional[Dict[str, str]] = None,
    operation: Optional[str] = "",
) -> Dict[str, Any]:
    """
    Execute a FHIR "delete" interaction on a specific resource instance.

    Use this tool when you need to remove a single resource identified by its logical ID or optionally filtered by search parameters.
    The optional `id` parameter must match an existing resource instance when present. If you include `searchParam`,
    the server will perform a conditional delete, deleting the resource only if it matches the given criteria. If you supply `operation`,
    it will execute the named FHIR operation (e.g., `$expunge`) on the resource. Do not use this tool for bulk deletes across multiple
    This tool returns a FHIR `OperationOutcome` describing success or failure of the deletion.

    Args:
        type (str): The FHIR resource type name (e.g., "ServiceRequest", "Appointment", "HealthcareService").
        id (str): The logical ID of a specific FHIR resource instance.
                Must exactly match one of the core or profile-defined resource types supported by the server.
        payload (Dict[str, str]): A JSON object following the RFC 6902 patch syntax (an array of operations) of the FHIR resource to be patched
                (e.g., [{"op": "replace", "path": "/name/family", "value": "Doe"}]).
        searchParam (Dict[str, str]): A mapping of FHIR search parameter names to their desired values (e.g., {"category":"laboratory","issued:"2025-05-01"}).
                These parameters refine queries for operation-specific query qualifiers.
                Only parameters exposed by `get_capabilities` for that resource type are valid.
        operation (Optional[str]): The name of a custom FHIR operation or extended query defined for the resource (e.g., "$expand").
                Must match one of the operation names returned by `get_capabilities`.

    Returns:
        Dict[str, Any]: A dictionary containing the confirmation of deletion or details on why deletion failed.
    """

    try:
        logger.debug(
            f"Invoked with type='{type}', id={id}, searchParam={searchParam}, and operation={operation}"
        )
        if not type:
            logger.error(
                "Unable to perform delete operation: 'type' is a mandatory field."
            )
            return await get_operation_outcome_required_error("type")

        client: AsyncFHIRClient = await get_async_fhir_client()
        bundle: dict = await client.resource(resource_type=type, id=id).execute(
            operation=operation or "", method="DELETE", params=searchParam
        )
        return await get_bundle_entries(bundle=bundle)
    except ValueError as ex:
        logger.exception(
            f"User does not have permission to perform FHIR '{type}' resource delete operation. Caused by, ",
            exc_info=ex,
        )
        return await get_operation_outcome_error(
            code="forbidden",
            diagnostics=f"The user does not have the rights to perform delete operation.",
        )
    except OperationOutcome as ex:
        logger.exception(
            f"FHIR server returned an OperationOutcome error while deleting the resource: '{type}', Caused by,",
            exc_info=ex,
        )
        return ex.resource["issue"] or await get_operation_outcome_exception()
    except Exception as ex:
        logger.exception(
            f"An unexpected error occurred during the FHIR delete operation for resource: '{type}'. Caused by, ",
            exc_info=ex,
        )
    return await get_operation_outcome_exception()


@click.command()
@click.option(
    "--transport",
    type=click.Choice(["stdio", "sse", "streamable-http"]),
    default="streamable-http",
    show_default=True,
    help="Transport protocol to use",
)
@click.option(
    "--log-level",
    type=click.Choice(["DEBUG", "INFO", "WARN", "ERROR"], case_sensitive=False),
    default="INFO",
    show_default=True,
    help="Log level to use",
)
def main(transport, log_level) -> None:
    """Start the FHIR MCP server."""
    logger.setLevel(log_level.upper())
    try:
        logger.info(f"Starting FHIR MCP server with {transport} transport")
        mcp.run(transport=transport)
    except Exception as ex:
        logger.error(
            f"Unable to run the FHIR MCP server. Caused by, %s", ex, exc_info=True
        )
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - %(message)s",
    )
    main()
