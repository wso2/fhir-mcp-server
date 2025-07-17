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

from pydantic import AnyHttpUrl
import pytest
import time
from unittest.mock import Mock, patch

from mcp.shared.auth import OAuthClientInformationFull
from fhir_mcp_server.oauth.server_provider import OAuthServerProvider
from fhir_mcp_server.oauth.types import OAuthMetadata, ServerConfigs


class TestOAuthServerProvider:
    """Test the OAuthServerProvider class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_configs = ServerConfigs(
            mcp_host="localhost", 
            mcp_port=8000, 
            mcp_server_url="http://localhost:8000",
            server_client_id="test_client_id",
            server_client_secret="test_client_secret",
            server_base_url="https://auth.example.com",
            server_scopes="read write"
        )

    @pytest.mark.asyncio
    async def test_init_server_provider(self):
        """Test OAuthServerProvider initialization."""
        provider = OAuthServerProvider(self.mock_configs)

        assert provider.configs == self.mock_configs
        # The oauth_configs property doesn't exist, configs should be accessed directly
        assert provider.configs == self.mock_configs

    @pytest.mark.asyncio
    async def test_initialize_server(self):
        """Test server initialization."""
        provider = OAuthServerProvider(self.mock_configs)

        # Mock the discover_oauth_metadata function
        with patch(
            "fhir_mcp_server.oauth.server_provider.discover_oauth_metadata"
        ) as mock_discover:
            mock_metadata = {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                "token_endpoint": "https://auth.example.com/oauth/token",
                "revocation_endpoint": "https://auth.example.com/oauth/revoke",
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid", "profile", "email"],
            }
            mock_discover.return_value = mock_metadata

            await provider.initialize()

            assert provider._metadata == mock_metadata
            mock_discover.assert_called_once_with(
                metadata_url=self.mock_configs.discovery_url,
                headers={"Accept": "application/json"},
            )

    @pytest.mark.asyncio
    async def test_initialize_server_error(self):
        """Test server initialization with error handling."""
        provider = OAuthServerProvider(self.mock_configs)

        # Mock the discover_oauth_metadata function to raise an exception
        with patch(
            "fhir_mcp_server.oauth.server_provider.discover_oauth_metadata"
        ) as mock_discover:
            mock_discover.side_effect = Exception("OAuth metadata discovery failed")

            with pytest.raises(Exception, match="OAuth metadata discovery failed"):
                await provider.initialize()

    @pytest.mark.asyncio
    async def test_client_registration_and_retrieval(self):
        """Test client registration and retrieval."""
        provider = OAuthServerProvider(self.mock_configs)

        # Create client info
        client_info = Mock()
        client_info.client_id = "test_client_id"

        # Register client
        await provider.register_client(client_info)

        # Retrieve client
        retrieved_client: OAuthClientInformationFull | None = await provider.get_client(
            "test_client_id"
        )
        assert retrieved_client is not None
        assert retrieved_client == client_info
        assert retrieved_client.client_id == "test_client_id"

        # Test non-existent client
        non_existent = await provider.get_client("non_existent")
        assert non_existent is None

    @pytest.mark.asyncio
    async def test_authorize_method(self):
        """Test authorize method."""
        provider = OAuthServerProvider(self.mock_configs)

        # Set the required metadata directly
        provider._metadata = OAuthMetadata(
            issuer=AnyHttpUrl("https://auth.example.com/"),
            token_endpoint=AnyHttpUrl("https://auth.example.com/oauth/token"),
            authorization_endpoint=AnyHttpUrl(
                "https://auth.example.com/oauth/authorize"
            ),
            code_challenge_methods_supported=["S256"],
            response_types_supported=["code"],
        )

        # Mock the client and authorization params
        client = Mock()
        client.client_id = "test_client_id"

        params = Mock()
        params.redirect_uri = "http://localhost:8000/oauth/callback"
        params.redirect_uri_provided_explicitly = True
        params.scopes = ["read", "write"]
        params.state = "test_state"
        params.code_challenge = "test_challenge"

        # Mock the PKCE generation functions
        with (
            patch(
                "fhir_mcp_server.oauth.server_provider.generate_code_verifier"
            ) as mock_verifier,
            patch(
                "fhir_mcp_server.oauth.server_provider.generate_code_challenge"
            ) as mock_challenge,
        ):

            mock_verifier.return_value = "test_code_verifier"
            mock_challenge.return_value = "test_code_challenge"

            auth_url = await provider.authorize(client, params)

            assert "https://auth.example.com/oauth/authorize" in auth_url
            assert "client_id=test_client_id" in auth_url
            assert "redirect_uri=" in auth_url
            assert "code_challenge=test_code_challenge" in auth_url
            assert "code_challenge_method=S256" in auth_url

    @pytest.mark.asyncio
    async def test_token_management(self):
        """Test token storage and retrieval."""
        provider = OAuthServerProvider(self.mock_configs)

        # Test that initially no token exists
        result = await provider.load_access_token("non_existent_token")
        assert result is None

        # Create a mock access token and store it directly
        from mcp.server.auth.provider import AccessToken

        test_token = AccessToken(
            token="real_token",
            client_id="test_client",
            scopes=["read", "write"],
            expires_at=int(time.time() + 3600),
        )

        provider.token_mapping["test_mcp_token"] = test_token

        # Test retrieval
        retrieved: AccessToken | None = await provider.load_access_token(
            "test_mcp_token"
        )
        assert retrieved is not None
        assert retrieved == test_token
        assert retrieved.token == "real_token"
        assert retrieved.client_id == "test_client"

    @pytest.mark.asyncio
    async def test_token_revocation(self):
        """Test token revocation."""
        provider = OAuthServerProvider(self.mock_configs)

        # Add a token first
        from mcp.server.auth.provider import AccessToken

        test_token = AccessToken(
            token="real_token",
            client_id="test_client",
            scopes=["read"],
            expires_at=int(time.time() + 3600),
        )

        provider.token_mapping["test_token"] = test_token

        # Verify token exists
        retrieved = await provider.load_access_token("test_token")
        assert retrieved is not None

        # Revoke token
        await provider.revoke_token("test_token")

        # Verify token is gone
        result = await provider.load_access_token("test_token")
        assert result is None

    def test_state_generation(self):
        """Test internal state generation methods."""
        provider = OAuthServerProvider(self.mock_configs)

        # Mock the PKCE generation functions
        with (
            patch(
                "fhir_mcp_server.oauth.server_provider.generate_code_verifier"
            ) as mock_verifier,
            patch(
                "fhir_mcp_server.oauth.server_provider.generate_code_challenge"
            ) as mock_challenge,
        ):

            mock_verifier.return_value = "test_code_verifier"
            mock_challenge.return_value = "test_code_challenge"

            verifier = provider._generate_code_verifier()
            challenge = provider._generate_code_challenge(verifier)

            assert verifier == "test_code_verifier"
            assert challenge == "test_code_challenge"

            mock_verifier.assert_called_once()
            mock_challenge.assert_called_once_with("test_code_verifier")
