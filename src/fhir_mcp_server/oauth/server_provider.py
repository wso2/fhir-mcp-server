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

import logging
import secrets
import time

from typing import Dict
from pydantic import AnyHttpUrl
from starlette.exceptions import HTTPException
from urllib.parse import urlencode
from mcp.server.auth.provider import (
    AccessToken,
    OAuthAuthorizationServerProvider,
    RefreshToken,
    AuthorizationParams,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from fhir_mcp_server.oauth.types import (
    AuthorizationCode,
    OAuthMetadata,
    OAuthToken as OAuth2Token,
)
from fhir_mcp_server.oauth.types import OAuthMetadata, ServerConfigs
from fhir_mcp_server.oauth.common import (
    discover_oauth_metadata,
    get_endpoint,
    generate_code_challenge,
    generate_code_verifier,
    perform_token_flow,
)

logger = logging.getLogger(__name__)


class OAuthServerProvider(OAuthAuthorizationServerProvider):

    def __init__(self, configs: ServerConfigs):
        self.configs = configs

        self.clients: Dict[str, OAuthClientInformationFull] = {}
        self.auth_code_mapping: Dict[str, AuthorizationCode] = {}
        self.token_mapping: Dict[str, AccessToken | RefreshToken] = {}
        self.state_mapping: Dict[str, Dict[str, str]] = {}

        self._metadata: OAuthMetadata | None = None

    async def initialize(self) -> None:
        """Initialize the OAuth server."""
        self._metadata = await self._discover_oauth_metadata()

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get OAuth client information."""
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull):
        """Register a new OAuth client."""
        self.clients[client_info.client_id] = client_info

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Generate an authorization URL for OAuth flow."""
        if not self._metadata:
            self._metadata = await self._discover_oauth_metadata()

        authorization_endpoint: str = await self._get_authorization_endpoint()

        # Generate PKCE challenge
        code_verifier: str = self._generate_code_verifier()
        code_challenge: str = self._generate_code_challenge(code_verifier)

        state: str = params.state or secrets.token_hex(16)

        # Store the state mapping
        self.state_mapping[state] = {
            "redirect_uri": str(params.redirect_uri),
            "code_verifier": code_verifier,
            "code_challenge": params.code_challenge,
            "redirect_uri_provided_explicitly": str(
                params.redirect_uri_provided_explicitly
            ),
            "client_id": client.client_id,
            **({"scope": " ".join(params.scopes)} if params.scopes else {}),
        }

        auth_params: Dict[str, str] = {
            "response_type": "code",
            "scope": self.configs.server_scopes,
            "client_id": self.configs.server_client_id,
            "redirect_uri": str(
                self.configs.callback_url(self.configs.effective_server_url)
            ),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        auth_url: str = f"{authorization_endpoint}?{urlencode(auth_params)}"
        logger.debug(f"Redirecting the request to authorization URL: {auth_url}")
        return auth_url

    async def handle_mcp_oauth_callback(self, code: str, state: str) -> str:
        """Handle OAuth redirect."""
        state_data: Dict[str, str] | None = self.state_mapping.get(state)
        if not state_data:
            raise HTTPException(400, "Invalid state parameter")

        redirect_uri: str = state_data["redirect_uri"]
        code_challenge: str = state_data["code_challenge"]
        redirect_uri_provided_explicitly: bool = (
            state_data["redirect_uri_provided_explicitly"] == "True"
        )
        client_id: str = state_data["client_id"]
        code_verifier: str = state_data["code_verifier"]
        scope: str | None = state_data.get("scope")

        # Create MCP authorization code
        mcp_auth_code: str = f"fhir_mcp_{secrets.token_hex(16)}"
        self.auth_code_mapping[mcp_auth_code] = AuthorizationCode(
            code=code,
            client_id=client_id,
            redirect_uri=AnyHttpUrl(redirect_uri),
            redirect_uri_provided_explicitly=redirect_uri_provided_explicitly,
            expires_at=int(time.time() + 600),  # 10 min
            scopes=scope.strip().split(" ") if scope else [],
            code_verifier=code_verifier,
            code_challenge=code_challenge,
        )

        del self.state_mapping[state]
        return construct_redirect_uri(redirect_uri, code=mcp_auth_code, state=state)

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load an validate authorization code."""
        auth_code: AuthorizationCode | None = self.auth_code_mapping.get(
            authorization_code
        )
        if not auth_code:
            return None
        if auth_code.client_id != client.client_id:
            return None
        if auth_code.expires_at < time.time():
            return None

        del self.auth_code_mapping[authorization_code]
        return auth_code

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """Exchange authorization code for tokens."""
        if client.client_id != authorization_code.client_id:
            raise ValueError("Client authentication failed")

        access_token_payload: Dict = {
            "grant_type": "authorization_code",
            "code": authorization_code.code,
            "code_verifier": authorization_code.code_verifier,
            "client_id": self.configs.server_client_id,
            "client_secret": self.configs.server_client_secret,
            "redirect_uri": self.configs.callback_url(self.configs.effective_server_url),
        }

        token: OAuth2Token = await perform_token_flow(
            url=await self._get_token_endpoint(),
            data=access_token_payload,
            headers={"Accept": "application/json"},
        )

        # Generate MCP tokens
        mcp_access_token: str = f"fhir_mcp_{secrets.token_hex(32)}"
        mcp_refresh_token: str = f"fhir_mcp_{secrets.token_hex(32)}"

        self.token_mapping[mcp_access_token] = AccessToken(
            token=token.access_token,
            client_id=self.configs.server_client_id,
            scopes=token.scopes,
            expires_at=int(token.expires_at or 3600),
        )

        if token.refresh_token:
            self.token_mapping[mcp_refresh_token] = RefreshToken(
                token=token.refresh_token,
                client_id=self.configs.server_client_id,
                scopes=token.scopes,
                expires_at=int(token.expires_at or 3600),
            )

        return OAuthToken(
            access_token=mcp_access_token,
            refresh_token=mcp_refresh_token,
            token_type="bearer",
            expires_in=token.expires_in,
            scope=" ".join(authorization_code.scopes),
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate an access token."""
        access_token: AccessToken | RefreshToken | None = self.token_mapping.get(token)
        if not access_token:
            return None
        if access_token.expires_at and access_token.expires_at < time.time():
            return None
        if isinstance(access_token, AccessToken):
            return access_token
        return None

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """Load and validate refresh token."""
        token = self.token_mapping.get(refresh_token)

        if not token:
            return None
        if token.client_id != client.client_id:
            return None
        if token.expires_at and token.expires_at < time.time():
            return None
        if isinstance(token, RefreshToken):
            return token
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token"""
        if refresh_token.client_id != client.client_id:
            raise ValueError("Client authentication failed")

        refresh_token_payload: Dict = {
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "client_id": self.configs.server_client_id,
            "client_secret": self.configs.server_client_secret,
            "scopes": " ".join(scopes),
        }
        new_token: OAuth2Token = await perform_token_flow(
            url=await self._get_token_endpoint(),
            data=refresh_token_payload,
            headers={"Accept": "application/json"},
        )

        # Generate new MCP tokens
        mcp_access_token: str = f"fhir_mcp_{secrets.token_hex(32)}"
        mcp_refresh_token: str = f"fhir_mcp_{secrets.token_hex(32)}"

        self.token_mapping[mcp_access_token] = AccessToken(
            token=new_token.access_token,
            scopes=new_token.scopes,
            expires_at=int(new_token.expires_at or 3600),
            client_id=client.client_id,
        )

        if new_token.refresh_token:
            self.token_mapping[mcp_refresh_token] = RefreshToken(
                token=new_token.refresh_token,
                scopes=new_token.scopes,
                expires_at=int(new_token.expires_at or 3600),
                client_id=client.client_id,
            )

        return OAuthToken(
            access_token=mcp_access_token,
            refresh_token=mcp_refresh_token,
            token_type="bearer",
            expires_in=int(new_token.expires_in or 3600),
            scope=new_token.scope,
        )

    async def revoke_token(
        self, token: str, token_type_hint: str | None = None
    ) -> None:
        """Revoke a token."""
        if token in self.token_mapping:
            del self.token_mapping[token]

    async def _discover_oauth_metadata(self) -> OAuthMetadata | None:

        return await discover_oauth_metadata(
            metadata_url=self.configs.discovery_url,
            headers={"Accept": "application/json"},
        )

    async def _get_authorization_endpoint(self) -> str:
        return get_endpoint(self._metadata, "authorization_endpoint")

    async def _get_token_endpoint(self) -> str:
        return get_endpoint(self._metadata, "token_endpoint")

    def _generate_code_verifier(self) -> str:
        """Generate a cryptographically random code verifier for PKCE."""
        return generate_code_verifier(128)

    def _generate_code_challenge(self, code_verifier: str) -> str:
        """Generate a code challenge from a code verifier using SHA256."""
        return generate_code_challenge(code_verifier)
