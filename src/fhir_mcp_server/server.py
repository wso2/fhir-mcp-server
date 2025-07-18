# Copyright (c) 2025, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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
    trim_resource_capabilities,
)
from fhir_mcp_server.oauth import (
    handle_failed_authentication,
    OAuthServerProvider,
    OAuthToken,
    ServerConfigs,
)
from fhirpy import AsyncFHIRClient
from fhirpy.lib import AsyncFHIRResource
from fhirpy.base.exceptions import OperationOutcome, ResourceNotFound
from fhirpy.base.searchset import Raw
from typing import Dict, Any, List
from typing_extensions import Annotated
from pydantic import AnyHttpUrl, Field
from starlette.requests import Request
from starlette.responses import RedirectResponse, Response
from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings, ClientRegistrationOptions
from mcp.server.fastmcp.server import FastMCP

logger: logging.Logger = logging.getLogger(__name__)

configs: ServerConfigs = ServerConfigs()

server_provider: OAuthServerProvider = OAuthServerProvider(configs=configs)


@click.pass_context
async def get_user_access_token(click_ctx: click.Context) -> OAuthToken | None:
    """
    Retrieve the access token for the authenticated user.
    Returns an OAuthToken if available, otherwise raises an error.
    """
    if configs.server_access_token:
        logger.debug("Using configured FHIR access token for user.")
        return OAuthToken(access_token=configs.server_access_token, token_type="Bearer")
    
    user_token: AccessToken | None = get_access_token()
    if not user_token:
        logger.error("Failed to obtain client access token.")
        raise ValueError("Failed to obtain client access token.")

    logger.debug("Obtained client access token from context.")

    # Return the FHIR access token
    return user_token


@click.pass_context
async def get_async_fhir_client(click_ctx: click.Context) -> AsyncFHIRClient:
    """
    Get an async FHIR client with the user's access token.
    Returns an AsyncFHIRClient instance.
    """
    client_kwargs: Dict = {
        "config": configs,
        "extra_headers": get_default_headers(),
    }

    disable_auth: bool = (
        click_ctx.obj.get("disable_auth") if click_ctx.obj else False
    )
    if not disable_auth:
        user_token: AccessToken | None = await get_user_access_token()
        if not user_token:
            logger.error("User is not authenticated.")
            raise ValueError("User is not authenticated.")
        client_kwargs["access_token"] = user_token.token
    else:
        logger.debug("FHIR authentication is disabled.")
    return await create_async_fhir_client(**client_kwargs)


def configure_mcp_server(disable_auth: bool) -> FastMCP:
    """
    Configure and instantiate the FastMCP server instance.
    If disable_auth is True, the server will be started without authorization.
    Returns a FastMCP instance.
    """
    fastmcp_kwargs: Dict = {
        "name": "FHIR MCP Server",
        "instructions": "This server implements the HL7 FHIR MCP for secure, standards-based access to FHIR resources",
        "host": configs.mcp_host,
        "port": configs.mcp_port,
        "json_response": True,
        "stateless_http": True,
    }
    if not disable_auth:
        logger.debug("Enabling authorization for FHIR MCP server.")
        auth_settings: AuthSettings = AuthSettings(
            issuer_url=AnyHttpUrl(configs.effective_server_url),
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=configs.scopes,
                default_scopes=configs.scopes,
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
) -> None:
    """
    Register custom routes for the FastMCP server instance.
    """
    logger.debug("Registering custom MCP routes.")

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

    @mcp.tool(
        description=(
            "Retrieves metadata about a specified FHIR resource type, including its supported search parameters and custom operations. "
            "This tool MUST always be invoked before performing any resource operation (such as search, read, create, update, or delete) "
            "to discover the valid searchParams and operations permitted for that resource type. "
            "Do not use this tool to fetch actual resources."
        )
    )
    async def get_capabilities(
        type: Annotated[
            str,
            Field(
                description=(
                    "The FHIR resource type name. Must exactly match one of the core or "
                    "profile-defined resource types as per the FHIR specification."
                ),
                examples=["Patient", "Observation", "Encounter"],
            ),
        ],
    ) -> Annotated[
        Dict[str, Any],
        Field(
            description=(
                "A dictionary containing: "
                "'type': The requested resource type (if supported by the system) or empty. "
                "'searchParam': A mapping of FHIR search parameter names to their descriptions. Each key is a parameter name "
                "(e.g., family, _id, _lastUpdated), and each value is a string describing the parameter's meaning and usage constraints. "
                "'operation': A mapping of custom FHIR operation names to their descriptions. Each key is an operation name "
                "(e.g., $validate), and each value is a string explaining the operation's purpose and usage. "
                "'interaction': A list of supported interactions for the resource type (e.g., read, search-type, create). "
                "'searchInclude': A list of supported _include parameters for the resource type, indicating which related resources can be included. "
                "'searchRevInclude': A list of supported _revinclude parameters for the resource type, indicating which reverse-included resources can be included."
            )
        ),
    ]:
        try:
            logger.debug(f"Invoked with resource_type='{type}'")
            data: Dict[str, Any] = await get_capability_statement(
                configs.metadata_url
            )
            for resource in data["rest"][0]["resource"]:
                if resource.get("type") == type:
                    logger.info(
                        f"Resource type '{type}' found in the CapabilityStatement."
                    )
                    return {
                        "type": resource.get("type"),
                        "searchParam": trim_resource_capabilities(
                            resource.get("searchParam", [])
                        ),
                        "operation": trim_resource_capabilities(
                            resource.get("operation", [])
                        ),
                        "interaction": resource.get("interaction", []),
                        "searchInclude": resource.get("searchInclude", []),
                        "searchRevInclude": resource.get("searchRevInclude", []),
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

    @mcp.tool(
        description=(
            "Executes a standard FHIR `search` interaction on a given resource type, returning a bundle or list of matching resources. "
            "Use this when you need to query for multiple resources based on one or more search-parameters. "
            "Do not use this tool for create, update, or delete operations, and be aware that large result sets may be paginated by the FHIR server."
        )
    )
    async def search(
        type: Annotated[
            str,
            Field(
                description="The FHIR resource type name. Must exactly match one of the resource types supported by the server",
                examples=["MedicationRequest", "Condition", "Procedure"],
            ),
        ],
        searchParam: Annotated[
            Dict[str, str | List[str]],
            Field(
                description=(
                    "A mapping of FHIR search parameter names to their values. "
                    "Only include parameters supported for the resource type, as listed by `get_capabilities`."
                ),
                examples=[
                    '{"family": "Smith"}',
                    '{"date": ["ge1970-01-01", "lt2000-01-01"]}',
                ],
            ),
        ],
    ) -> Annotated[
        list[Dict[str, Any]] | Dict[str, Any],
        Field(
            description="A dictionary containing the full FHIR resource instance matching the search criteria."
        ),
    ]:
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

    @mcp.tool(
        description=(
            "Performs a FHIR `read` interaction to retrieve a single resource instance by its type and resource ID, "
            "optionally refining the response with search parameters or custom operations. "
            "Use it when you know the exact resource ID and require that one resource; do not use it for bulk queries. "
            "If additional query-level parameters or operations are needed (e.g., _elements or $validate), include them in searchParam or operation."
        )
    )
    async def read(
        type: Annotated[
            str,
            Field(
                description="The FHIR resource type name. Must exactly match one of the resource types supported by the server.",
                examples=["DiagnosticReport", "AllergyIntolerance", "Immunization"],
            ),
        ],
        id: Annotated[
            str,
            Field(description="The logical ID of a specific FHIR resource instance."),
        ],
        searchParam: Annotated[
            Dict[str, str | List[str]],
            Field(
                description=(
                    "A mapping of FHIR search parameter names to their desired values. "
                    "These parameters refine queries for operation-specific query qualifiers. "
                    "Only parameters exposed by `get_capabilities` for that resource type are valid."
                ),
                examples=['{"device-name": "glucometer", "identifier": ["12345"]}'],
            ),
        ] = {},
        operation: Annotated[
            str,
            Field(
                description=(
                    "The name of a custom FHIR operation or extended query defined for the resource "
                    "must match one of the operation names returned by `get_capabilities`."
                ),
                examples=["$everything"],
            ),
        ] = "",
    ) -> Annotated[
        Dict[str, Any],
        Field(
            description="A dictionary containing the single FHIR resource instance of the requested type and id."
        ),
    ]:
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

    @mcp.tool(
        description=(
            "Executes a FHIR `create` interaction to persist a new resource of the specified type. "
            "It is required to supply the full resource payload in JSON form. "
            "Use this tool when you need to add new data (e.g., a new Patient or Observation). "
            "Note that servers may reject resources that violate profiles or mandatory bindings."
        )
    )
    async def create(
        type: Annotated[
            str,
            Field(
                description="The FHIR resource type name. Must exactly match one of the resource types supported by the server.",
                examples=["Device", "CarePlan", "Goal"],
            ),
        ],
        payload: Annotated[
            Dict[str, Any],
            Field(
                description=(
                    "A JSON object representing the full FHIR resource body to be created. "
                    "It must include all required elements of the resource's profile."
                )
            ),
        ],
        searchParam: Annotated[
            Dict[str, str | List[str]],
            Field(
                description=(
                    "A mapping of FHIR search parameter names to their desired values. "
                    "These parameters refine queries for operation-specific query qualifiers. "
                    "Only parameters exposed by `get_capabilities` for that resource type are valid."
                ),
                examples=['{"address-city": "Boston", "address-state": ["NY"]}'],
            ),
        ] = {},
        operation: Annotated[
            str,
            Field(
                description=(
                    "The name of a custom FHIR operation or extended query defined for the resource"
                    "Must match one of the operation names returned by `get_capabilities`."
                ),
                examples=["$evaluate"],
            ),
        ] = "",
    ) -> Annotated[
        Dict[str, Any],
        Field(
            description=(
                "A dictionary containing the newly created FHIR resource, including server-assigned fields "
                "(id, meta.versionId, meta.lastUpdated, and any server-added extensions). Reflects exactly what was persisted."
            )
        ),
    ]:
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

    @mcp.tool(
        description=(
            "Performs a FHIR `update` interaction by replacing an existing resource instance's content with the provided payload. "
            "Use it when you need to overwrite a resource's data in its entirety, such as correcting or completing a record, "
            "and you already know the resource's logical id. "
            "Optionally, you can include searchParam for conditional updates (e.g., only update if the resource matches certain criteria) "
            "or specify a custom operation (e.g., `$validate` to run validation before updating) "
            "The tool returns the updated resource or an OperationOutcome detailing any errors."
        )
    )
    async def update(
        type: Annotated[
            str,
            Field(
                description="The FHIR resource type name. Must exactly match one of the resource types supported by the server.",
                examples=["Location", "Organization", "Coverage"],
            ),
        ],
        id: Annotated[
            str,
            Field(description="The logical ID of a specific FHIR resource instance."),
        ],
        payload: Annotated[
            Dict[str, Any],
            Field(
                description=(
                    "The complete JSON representation of the FHIR resource, containing all required elements and any optional data. "
                    "Servers replace the existing resource with this exact content, so the payload must include all mandatory fields "
                    "defined by the resource's profile and any previous data you wish to preserve."
                )
            ),
        ],
        searchParam: Annotated[
            Dict[str, str | List[str]],
            Field(
                description=(
                    "A mapping of FHIR search parameter names to their desired values. "
                    "These parameters refine queries for operation-specific query qualifiers. "
                    "Only parameters exposed by `get_capabilities` for that resource type are valid. "
                ),
                examples=['{"patient":"Patient/54321","relationship":["father"]}'],
            ),
        ] = {},
        operation: Annotated[
            str,
            Field(
                description=(
                    "The name of a custom FHIR operation or extended query defined for the resource"
                    "Must match one of the operation names returned by `get_capabilities`."
                ),
                examples=["$lastn"],
            ),
        ] = "",
    ) -> Annotated[
        Dict[str, Any],
        Field(description="A dictionary containing the updated FHIR resource"),
    ]:
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
                data={**payload, "id": id},
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

    @mcp.tool(
        description=(
            "Execute a FHIR `delete` interaction on a specific resource instance. "
            "Use this tool when you need to remove a single resource identified by its logical ID or optionally filtered by search parameters. "
            "The optional `id` parameter must match an existing resource instance when present. "
            "If you include `searchParam`, the server will perform a conditional delete, deleting the resource only if it matches the given criteria. "
            "If you supply `operation`, it will execute the named FHIR operation (e.g., `$expunge`) on the resource. "
            "This tool returns a FHIR `OperationOutcome` describing success or failure of the deletion."
        )
    )
    async def delete(
        type: Annotated[
            str,
            Field(
                description="The FHIR resource type name. Must exactly match one of the resource types supported by the server.",
                examples=["ServiceRequest", "Appointment", "HealthcareService"],
            ),
        ],
        id: Annotated[
            str,
            Field(description="The logical ID of a specific FHIR resource instance."),
        ] = "",
        searchParam: Annotated[
            Dict[str, str | List[str]],
            Field(
                description=(
                    "A mapping of FHIR search parameter names to their desired values. "
                    "These parameters refine queries for operation-specific query qualifiers. "
                    "Only parameters exposed by `get_capabilities` for that resource type are valid. "
                ),
                examples=['{"category": "laboratory", "status": ["active"]}'],
            ),
        ] = {},
        operation: Annotated[
            str,
            Field(
                description=(
                    "The name of a custom FHIR operation or extended query defined for the resource"
                    "Must match one of the operation names returned by `get_capabilities`."
                ),
                examples=["$expand"],
            ),
        ] = "",
    ) -> Annotated[
        Dict[str, Any],
        Field(
            description="A dictionary containing the confirmation of deletion or details on why deletion failed."
        ),
    ]:
        try:
            logger.debug(
                f"Invoked with type='{type}', id={id}, searchParam={searchParam}, and operation={operation}"
            )
            if not type:
                logger.error(
                    "Unable to perform delete operation: 'type' is a mandatory field."
                )
                return await get_operation_outcome_required_error("type")
            if not id and not searchParam:
                logger.error(
                    "Unable to perform delete operation: 'id' or 'searchParam' is required."
                )
                return await get_operation_outcome_required_error("id")

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
    "--disable-auth",
    is_flag=True,
    default=False,
    show_default=True,
    help="Disable authorization between MCP client and MCP server. [default: False]",
)
@click.pass_context
def main(
    click_ctx: click.Context, transport, log_level, disable_auth
) -> int:
    """
    FHIR MCP Server - helping you expose any FHIR Server or API as a MCP Server.
    """
    # Store CLI options in context for downstream access
    click_ctx.ensure_object(dict)
    click_ctx.obj["disable_auth"] = disable_auth

    logging.basicConfig(
        level=getattr(logging, log_level.upper()),
        format="[%(asctime)s] %(levelname)s {%(name)s.%(funcName)s:%(lineno)d} - %(message)s",
    )
    try:
        mcp: FastMCP = configure_mcp_server(disable_auth)
        register_mcp_tools(mcp=mcp)
        register_mcp_routes(
            mcp=mcp, server_provider=server_provider
        )
        logger.info(f"Starting FHIR MCP server with {transport} transport")
        mcp.run(transport=transport)
    except Exception as ex:
        logger.error(
            f"Unable to run the FHIR MCP server. Caused by, %s", ex, exc_info=True
        )
        return 1
    return 0
