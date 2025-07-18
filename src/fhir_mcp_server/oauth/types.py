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

from pydantic import AnyHttpUrl, BaseModel
from pydantic_settings import BaseSettings, SettingsConfigDict


class ServerConfigs(BaseSettings):
    """Contains environment configurations of the MCP server."""

    model_config = SettingsConfigDict(
        env_prefix="FHIR_",
        env_file=".env",
        env_file_encoding="utf-8",
        env_nested_delimiter="__",
        extra="ignore",
    )

    # MCP Server settings
    mcp_host: str = "localhost"
    mcp_port: int = 8000
    mcp_server_url: str | None = None
    # FHIR settings
    server_client_id: str = ""
    server_client_secret: str = ""
    server_scopes: str = ""
    server_base_url: str = ""
    server_request_timeout: int = 30  # in secs
    server_access_token: str | None = None

    def callback_url(
        self, server_url: str, suffix: str = "/oauth/callback"
    ) -> AnyHttpUrl:
        return AnyHttpUrl(f"{server_url.rstrip('/')}{suffix}")

    @property
    def discovery_url(self) -> str:
        return f"{self.server_base_url.rstrip('/')}/.well-known/smart-configuration"

    @property
    def metadata_url(self) -> str:
        return f"{self.server_base_url.rstrip('/')}/metadata?_format=json"

    @property
    def scopes(self) -> list[str]:
        # If the raw value is a string, split on empty spaces
        if isinstance(self.server_scopes, str):
            return [scope.strip() for scope in self.server_scopes.split(" ") if scope.strip()]
        return [self.server_scopes]

    @property
    def effective_server_url(self) -> str:
        return self.mcp_server_url or f"http://{self.mcp_host}:{self.mcp_port}"

    def __init__(self, **data):
        """Initialize settings with values from environment variables"""
        super().__init__(**data)


class OAuthMetadata(BaseModel):
    """
    OAuth 2.0 Authorization Server Metadata.
    """

    issuer: AnyHttpUrl
    authorization_endpoint: AnyHttpUrl
    token_endpoint: AnyHttpUrl
    registration_endpoint: AnyHttpUrl | None = None
    scopes_supported: list[str] | None = None
    response_types_supported: list[str]
    response_modes_supported: list[str] | None = None
    grant_types_supported: list[str] | None = None
    token_endpoint_auth_methods_supported: list[str] | None = None
    token_endpoint_auth_signing_alg_values_supported: list[str] | None = None
    service_documentation: AnyHttpUrl | None = None
    ui_locales_supported: list[str] | None = None
    op_policy_uri: AnyHttpUrl | None = None
    op_tos_uri: AnyHttpUrl | None = None
    revocation_endpoint: AnyHttpUrl | None = None
    revocation_endpoint_auth_methods_supported: list[str] | None = None
    revocation_endpoint_auth_signing_alg_values_supported: None = None
    introspection_endpoint: AnyHttpUrl | None = None
    introspection_endpoint_auth_methods_supported: list[str] | None = None
    introspection_endpoint_auth_signing_alg_values_supported: None = None
    code_challenge_methods_supported: list[str] | None = None


class OAuthToken(BaseModel):
    """
    OAuth 2.0 token with metadata.
    """

    access_token: str
    token_type: str
    expires_in: int | None = None
    scope: str | None = None
    refresh_token: str | None = None
    expires_at: float | None = None

    @property
    def scopes(self) -> list[str]:
        return self.scope.split(" ") if self.scope else []


class AuthorizationCode(BaseModel):
    code: str
    scopes: list[str]
    expires_at: float
    client_id: str
    code_verifier: str
    code_challenge: str
    redirect_uri: AnyHttpUrl
    redirect_uri_provided_explicitly: bool
