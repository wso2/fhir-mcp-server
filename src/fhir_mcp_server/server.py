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

from fhir_mcp_server.utils import (
    create_async_fhir_client,
    get_bundle_entries,
    get_default_headers,
    get_operation_outcome,
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
from fhirpy.base.exceptions import OperationOutcome, ResourceNotFound
from fhirpy.base.searchset import Raw
from typing import Dict, Any, List, Optional
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

client_provider: FHIRClientProvider = FHIRClientProvider(
    callback_url=AnyHttpUrl(configs.fhir.callback_url(configs.effective_server_url)),
    configs=configs.fhir,
)


@click.pass_context
async def get_user_access_token(click_ctx: click.Context) -> OAuthToken | None:
    """
    Retrieve the access token for the authenticated user.
    Returns an OAuthToken if available, otherwise raises an error.
    """
    if configs.fhir.access_token:
        logger.debug("Using configured FHIR access token for user.")
        return OAuthToken(access_token=configs.fhir.access_token, token_type="Bearer")

    disable_mcp_auth: bool = (
        click_ctx.obj.get("disable_mcp_auth") if click_ctx.obj else False
    )
    client_access_token: str = ""
    if not disable_mcp_auth:
        client_token: AccessToken | None = get_access_token()
        if not client_token:
            logger.error("Failed to obtain client access token.")
            raise ValueError("Failed to obtain client access token.")
        client_access_token = client_token.token

    logger.debug("Obtained client access token from context.")
    return await client_provider.get_access_token(client_access_token)


@click.pass_context
async def get_async_fhir_client(click_ctx: click.Context) -> AsyncFHIRClient:
    """
    Get an async FHIR client with the user's access token.
    Returns an AsyncFHIRClient instance.
    """
    client_kwargs: Dict = {
        "config": configs.fhir,
        "extra_headers": get_default_headers(),
    }

    disable_fhir_auth: bool = (
        click_ctx.obj.get("disable_fhir_auth") if click_ctx.obj else False
    )
    if not disable_fhir_auth:
        user_token: OAuthToken | None = await get_user_access_token()
        if not user_token:
            logger.error("User is not authenticated.")
            raise ValueError("User is not authenticated.")
        client_kwargs["access_token"] = user_token.access_token
    else:
        logger.debug("FHIR authentication is disabled.")
    return await create_async_fhir_client(**client_kwargs)


def configure_mcp_server(disable_mcp_auth: bool) -> FastMCP:
    """
    Configure and instantiate the FastMCP server instance.
    If disable_mcp_auth is True, the server will be started without authorization.
    Returns a FastMCP instance.
    """
    fastmcp_kwargs: Dict = {
        "name": "FHIR MCP Server",
        "instructions": "This server implements the HL7 FHIR MCP for secure, standards-based access to FHIR resources",
        "host": configs.host,
        "port": configs.port,
        "json_response": True,
        "stateless_http": True,
    }
    if not disable_mcp_auth:
        logger.debug("Enabling authorization for FHIR MCP server.")
        auth_settings: AuthSettings = AuthSettings(
            issuer_url=AnyHttpUrl(configs.effective_server_url),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=configs.oauth.scopes,
                default_scopes=configs.oauth.scopes,
            ),
        )
        fastmcp_kwargs["auth_server_provider"] = server_provider
        fastmcp_kwargs["auth"] = auth_settings
    else:
        logger.warning("MCP authentication is disabled.")
    return FastMCP(**fastmcp_kwargs)


def register_mcp_routes(
    mcp: FastMCP,
    server_provider: OAuthServerProvider,
    client_provider: FHIRClientProvider,
) -> None:
    """
    Register custom routes for the FastMCP server instance.
    """
    logger.debug("Registering custom MCP routes.")

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
            redirect_uri: str = await server_provider.handle_mcp_oauth_callback(
                code, state
            )
            return RedirectResponse(status_code=302, url=redirect_uri)
        except Exception as ex:
            logger.error(
                "Error occurred while handling MCP oauth callback. Caused by, ",
                exc_info=ex,
            )
            return handle_failed_authentication("Something went wrong.")


def register_mcp_tools(mcp: FastMCP) -> None:
    """
    Register tool functions for the FastMCP server instance.
    """
    logger.debug("Registering MCP tools.")

    @mcp.tool()
    async def get_capabilities(type: str) -> Dict[str, Any]:
        """
        Retrieves metadata about a specified FHIR resource type, including its supported search parameters and custom operations.

        This tool must always be invoked before performing any resource operation (such as search, read, create, update, or delete)
        to discover the valid searchParams and operations permitted for that resource type. Do not use this tool to fetch actual resources.
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
            data: Dict[str, Any] = await get_capability_statement(
                configs.fhir.metadata_url
            )
            for resource in data["rest"][0]["resource"]:
                if resource.get("type") == type:
                    logger.info(
                        f"Resource type '{type}' found in the CapabilityStatement."
                    )
                    return {
                        "type": resource.get("type"),
                        "searchParam": trim_resource(resource.get("searchParam", [])),
                        "operation": trim_resource(resource.get("operation", [])),
                    }
            logger.info(f"Resource type '{type}' not found in the CapabilityStatement.")
            return await get_operation_outcome(
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
        type: str, searchParam: Dict[str, str | List[str]]
    ) -> list[Dict[str, Any]] | Dict[str, Any]:
        """
        Executes a standard FHIR "search" interaction on a given resource type, returning a bundle or list of matching resources.

        Use this when you need to query for multiple resources based on one or more search-parameters.
        Do not use this tool for create, update, or delete operations, and be aware that large result sets may be paginated by the FHIR server.

        Args:
            type (str): The FHIR resource type name (e.g., "MedicationRequest", "Condition", "Procedure").
                    Must exactly match one of the core or profile-defined resource types supported by the server.
            searchParam (Dict[str, str|List[str]]): A mapping of FHIR search parameter names to their values.
                    For parameters that appear once in the query (e.g., `/Patient?family=Smith`), use a string value: `{"family": "Smith"}`.
                    For parameters that can appear multiple times (e.g., `/Patient?date=lt2000-01-01&date=gt1970-01-01`),
                    use a list of strings: `{"date": ["lt2000-01-01", "gt1970-01-01"]}`.
                    Only include parameters supported for the resource type, as listed by `get_capabilities`.

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
            async_resources: list[AsyncFHIRResource] = (
                await client.resources(type).search(Raw(**searchParam)).fetch()
            )
            resources: list[Dict[str, Any]] = []
            for async_resource in async_resources:
                resources.append(async_resource.serialize())
            return resources
        except ValueError as ex:
            logger.exception(
                f"User does not have permission to perform FHIR '{type}' resource search operation. Caused by, ",
                exc_info=ex,
            )
            return await get_operation_outcome(
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
        searchParam: Optional[Dict[str, str | List[str]]] = None,
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
            searchParam (Dict[str, str|List[str]]): A mapping of FHIR search parameter names to their desired values
                    (e.g., {"device-name": "glucometer", "identifier": ["12345"]}).
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
        except ResourceNotFound as ex:
            logger.error(
                f"Resource of type '{type}' with id '{id}' not found. Caused by, ",
                exc_info=ex,
            )
            return await get_operation_outcome(
                code="not-found",
                diagnostics=f"The resource of type '{type}' with id '{id}' was not found.",
            )
        except ValueError as ex:
            logger.exception(
                f"User does not have permission to perform FHIR '{type}' resource read operation. Caused by, ",
                exc_info=ex,
            )
            return await get_operation_outcome(
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
        searchParam: Optional[Dict[str, str | List[str]]] = None,
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
            searchParam (Dict[str, str|List[str]]): A mapping of FHIR search parameter names to their desired values
                    (e.g., {"address-city": "Boston", "address-state": ["NY"]}).
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
            return await get_operation_outcome(
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
        searchParam: Optional[Dict[str, str | List[str]]] = None,
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
            searchParam (Dict[str, str|List[str]]): A mapping of FHIR search parameter names to their desired values
                    (e.g., {"patient":"Patient/54321","relationship":["father"]}).
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
            return await get_operation_outcome(
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
        searchParam: Optional[Dict[str, str | List[str]]] = None,
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
            searchParam (Dict[str, str|List[str]]): A mapping of FHIR search parameter names to their desired values
                    (e.g., {"category": "laboratory", "status": ["active"]}).
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
            bundle = await client.resource(resource_type=type, id=id).execute(
                operation=operation or "", method="DELETE", params=searchParam
            )
            if isinstance(bundle, Dict):
                return await get_bundle_entries(bundle=bundle)
            return await get_operation_outcome(
                severity="information",
                code="SUCCESSFUL_DELETE",
                diagnostics="Successfully deleted resource(s).",
            )
        except ValueError as ex:
            logger.exception(
                f"User does not have permission to perform FHIR '{type}' resource delete operation. Caused by, ",
                exc_info=ex,
            )
            return await get_operation_outcome(
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
@click.option(
    "--disable-mcp-auth",
    is_flag=True,
    default=False,
    show_default=True,
    help="Disable authorization between MCP client and MCP server. [default: False]",
)
@click.option(
    "--disable-fhir-auth",
    is_flag=True,
    default=False,
    show_default=True,
    help="Disable authorization between MCP server and FHIR server. [default: False]",
)
@click.pass_context
def main(
    click_ctx: click.Context, transport, log_level, disable_mcp_auth, disable_fhir_auth
) -> int:
    """
    FHIR MCP Server - helping you expose any FHIR Server or API as a MCP Server.
    """
    # Store CLI options in context for downstream access
    click_ctx.ensure_object(dict)
    click_ctx.obj["disable_fhir_auth"] = disable_fhir_auth
    click_ctx.obj["disable_mcp_auth"] = disable_mcp_auth

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - %(message)s",
    )
    try:
        mcp: FastMCP = configure_mcp_server(disable_mcp_auth)
        register_mcp_tools(mcp=mcp)
        register_mcp_routes(
            mcp=mcp, server_provider=server_provider, client_provider=client_provider
        )
        logger.info(f"Starting FHIR MCP server with {transport} transport")
        mcp.run(transport=transport)
    except Exception as ex:
        logger.error(
            f"Unable to run the FHIR MCP server. Caused by, %s", ex, exc_info=True
        )
        return 1
    return 0
