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

import asyncio
import anyio
import httpx
import logging
import secrets
import webbrowser

from collections.abc import Awaitable, Callable
from typing import Dict
from urllib.parse import urlencode
from http.client import HTTPException
from pydantic import AnyHttpUrl
from fhir_mcp_server.oauth.types import FHIROAuthConfigs, OAuthMetadata, OAuthToken
from fhir_mcp_server.oauth.common import (
    discover_oauth_metadata,
    is_token_expired,
    get_endpoint,
    generate_code_verifier,
    generate_code_challenge,
    perform_token_flow,
)

logger = logging.getLogger(__name__)


async def webbrowser_redirect_handler(authorization_url: str):
    print(f"Opening user's browser with URL: {authorization_url}")
    webbrowser.open_new_tab(authorization_url)


class FHIRClientProvider(httpx.Auth):
    """
    Authentication for httpx using anyio.
    Handles OAuth flow and token storage.
    """

    def __init__(
        self,
        callback_url: AnyHttpUrl,
        configs: FHIROAuthConfigs,
        redirect_handler: Callable[
            [str], Awaitable[None]
        ] = webbrowser_redirect_handler,
    ):
        """
        Initialize OAuth2 authentication.

        Args:
            callback_url: Callback URL of the FHIR client
            configs: FHIR server configurations
            redirect_handler: Function to handle authorization URL like opening browser
        """
        self.callback_url = callback_url
        self.redirect_handler = redirect_handler
        self.configs = configs

        self.state_mapping: dict[str, dict[str, str]] = {}
        self.token_mapping: Dict[str, OAuthToken | None] = {}
        # Thread safety lock
        self._token_lock = anyio.Lock()
        self._metadata: OAuthMetadata | None = None

    def _generate_code_verifier(self) -> str:
        """Generate a cryptographically random code verifier for PKCE."""
        return generate_code_verifier(128)

    def _generate_code_challenge(self, code_verifier: str) -> str:
        """Generate a code challenge from a code verifier using SHA256."""
        return generate_code_challenge(code_verifier)

    async def _discover_oauth_metadata(
        self, discovery_url: str
    ) -> OAuthMetadata | None:
        """
        Discover OAuth metadata from server's well-known endpoint.
        """

        return await discover_oauth_metadata(metadata_url=discovery_url)

    def _is_valid_token(self, token_id: str) -> bool:
        """Check if current token is valid."""
        current_token: OAuthToken | None = self.token_mapping.get(token_id)
        return not is_token_expired(current_token)

    async def _validate_token_scopes(self, token_response: OAuthToken) -> None:
        """
        Validate returned scopes against requested scopes.

        Per OAuth 2.1 Section 3.2.3: server may grant subset, not superset.
        """
        if not token_response.scope:
            # No scope returned = validation passes
            return

        # Check explicitly requested scopes only
        requested_scopes: set[str] = set()

        if self.configs.scope:
            # Validate against explicit scope request
            requested_scopes = set(self.configs.scopes)

            # Check for unauthorized scopes
            returned_scopes = set(token_response.scope.split(" "))
            unauthorized_scopes = returned_scopes - requested_scopes

            if unauthorized_scopes:
                logger.debug(
                    f"Server granted unauthorized scopes: {unauthorized_scopes}. "
                    f"Requested: {requested_scopes}, Returned: {returned_scopes}"
                )
                raise ValueError("scope validation failed!")
        else:
            # No explicit scopes requested - accept server defaults
            logger.debug(
                f"No explicit scopes requested, accepting server-granted "
                f"scopes: {token_response.scope}"
            )

    async def ensure_token(self, token_id: str) -> None:
        """Ensure valid access token, refreshing or re-authenticating as needed."""
        async with self._token_lock:
            # Return early if token is valid
            if self._is_valid_token(token_id):
                return

            # Try refreshing existing token
            if await self._refresh_access_token(token_id):
                return

            # Fall back to full OAuth flow
            await self._perform_oauth_flow(token_id)

    async def _perform_oauth_flow(self, token_id: str) -> None:
        """Execute OAuth2 authorization code flow with PKCE."""
        logger.debug("Starting authentication flow.")

        # Discover OAuth metadata
        if not self._metadata:
            self._metadata = await self._discover_oauth_metadata(
                self.configs.discovery_url
            )

        # Generate PKCE challenge
        code_verifier: str = self._generate_code_verifier()
        code_challenge: str = self._generate_code_challenge(code_verifier)

        authorization_endpoint: str = self._get_authorization_endpoint()

        # Build authorization URL
        state: str = secrets.token_urlsafe(32)
        auth_params: Dict[str, str] = {
            "response_type": "code",
            "client_id": self.configs.client_id,
            "redirect_uri": str(self.callback_url),
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }

        # Include explicit scopes only
        if self.configs.scope:
            auth_params["scope"] = self.configs.scope

        auth_url: str = f"{authorization_endpoint}?{urlencode(auth_params)}"

        self.state_mapping[state] = {
            **auth_params,
            "token_id": token_id,
            "code_verifier": code_verifier,
        }

        # Redirect user for authorization
        await self.redirect_handler(auth_url)

    async def handle_fhir_oauth_callback(self, code: str, state: str) -> None:

        state_mapping: Dict[str, str] | None = self.state_mapping.get(state)
        if not state_mapping:
            raise HTTPException(400, "Invalid state parameter")

        code_verifier: str = state_mapping["code_verifier"]
        token_id: str = state_mapping["token_id"]

        # Exchange authorization code for tokens
        await self._exchange_code_for_token(token_id, code, code_verifier)

    async def _exchange_code_for_token(
        self,
        token_id: str,
        auth_code: str,
        code_verifier: str,
    ) -> None:
        """Exchange authorization code for access token."""

        access_token_payload: dict = {
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": str(self.callback_url),
            "client_id": self.configs.client_id,
            "client_secret": self.configs.client_secret,
            "code_verifier": code_verifier,
        }

        try:
            token: OAuthToken = await perform_token_flow(
                url=self._get_token_endpoint(),
                data=access_token_payload,
                timeout=self.configs.timeout,
            )

            self.token_mapping[token_id] = token
        except Exception as ex:
            logger.exception("Access token request failed. Caused by, ", exc_info=ex)
            raise ValueError("Access token request failed")

    def _get_authorization_endpoint(self) -> str:
        """Get authorization endpoint."""
        return get_endpoint(self._metadata, "authorization_endpoint")

    def _get_token_endpoint(self) -> str:
        """Get token endpoint."""
        return get_endpoint(self._metadata, "token_endpoint")

    async def _refresh_access_token(self, token_id: str) -> None:
        """Refresh access token using refresh token."""

        current_token: OAuthToken | None = self.token_mapping.get(token_id)

        if not current_token:
            logger.debug("Unable to perform token refresh. No access token found!")
            return None

        refresh_token_payload: dict = {
            "grant_type": "refresh_token",
            "refresh_token": current_token.refresh_token,
            "client_id": self.configs.client_id,
            "client_secret": self.configs.client_secret,
        }

        try:
            new_token: OAuthToken = await perform_token_flow(
                url=self._get_token_endpoint(),
                data=refresh_token_payload,
                timeout=self.configs.timeout,
            )

            self.token_mapping[token_id] = new_token
        except Exception as ex:
            logger.exception("Token refresh failed. Caused by, ", exc_info=ex)
            raise ValueError("Token refresh failed")

    async def get_access_token(self, token_id: str) -> OAuthToken | None:
        """Get access token for the given token ID."""
        await self.ensure_token(token_id)
        access_token: OAuthToken | None = self.token_mapping.get(token_id)

        if not access_token:
            # Wait for user_access_token to become available, with a timeout
            for _ in range(self.configs.timeout):
                access_token: OAuthToken | None = self.token_mapping.get(token_id)
                if access_token:
                    break
                await asyncio.sleep(1)
            if not access_token:
                logger.error("Failed to obtain user access token.")
                raise ValueError("Failed to obtain user access token.")
        return access_token
