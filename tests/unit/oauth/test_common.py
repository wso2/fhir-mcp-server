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

import pytest
import time
import json
from unittest.mock import AsyncMock, Mock, patch
from starlette.responses import HTMLResponse

from fhir_mcp_server.oauth.common import (
    discover_oauth_metadata,
    is_token_expired,
    get_endpoint,
    handle_successful_authentication,
    handle_failed_authentication,
    generate_code_verifier,
    generate_code_challenge,
    perform_token_flow,
)
from fhir_mcp_server.oauth.types import OAuthMetadata, OAuthToken


class TestDiscoverOAuthMetadata:
    """Test the discover_oauth_metadata function."""

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_success(self):
        """Test successful OAuth metadata discovery."""
        metadata_url = "https://example.com/.well-known/oauth"
        metadata_response = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code"],
        }

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = metadata_response
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await discover_oauth_metadata(metadata_url)

            assert isinstance(result, OAuthMetadata)
            assert str(result.issuer).rstrip("/") == "https://example.com"
            assert str(result.authorization_endpoint) == "https://example.com/auth"
            assert str(result.token_endpoint) == "https://example.com/token"

            mock_client.get.assert_called_once_with(
                url=metadata_url, headers={"Accept": "application/fhir+json"}
            )

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_custom_headers(self):
        """Test OAuth metadata discovery with custom headers."""
        metadata_url = "https://example.com/.well-known/oauth"
        custom_headers = {"Accept": "application/json", "User-Agent": "test"}
        metadata_response = {
            "issuer": "https://example.com",
            "authorization_endpoint": "https://example.com/auth",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code"],
        }

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = metadata_response
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await discover_oauth_metadata(metadata_url, custom_headers)

            assert isinstance(result, OAuthMetadata)
            mock_client.get.assert_called_once_with(
                url=metadata_url, headers=custom_headers
            )

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_404(self):
        """Test OAuth metadata discovery with 404 response."""
        metadata_url = "https://example.com/.well-known/oauth"

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 404
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await discover_oauth_metadata(metadata_url)

            assert result is None

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_http_error(self):
        """Test OAuth metadata discovery with HTTP error."""
        metadata_url = "https://example.com/.well-known/oauth"

        with (
            patch(
                "fhir_mcp_server.oauth.common.create_mcp_http_client"
            ) as mock_client_context,
            patch("fhir_mcp_server.oauth.common.logger.exception"),
        ):
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 500
            mock_response.raise_for_status.side_effect = Exception("HTTP 500")
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await discover_oauth_metadata(metadata_url)

            assert result is None

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_invalid_json(self):
        """Test OAuth metadata discovery with invalid JSON."""
        metadata_url = "https://example.com/.well-known/oauth"

        with (
            patch(
                "fhir_mcp_server.oauth.common.create_mcp_http_client"
            ) as mock_client_context,
            patch("fhir_mcp_server.oauth.common.logger.exception"),
        ):
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await discover_oauth_metadata(metadata_url)

            assert result is None


class TestIsTokenExpired:
    """Test the is_token_expired function."""

    def test_is_token_expired_no_token(self):
        """Test token expiration with no token."""
        assert is_token_expired(None) is True

    def test_is_token_expired_no_expires_at(self):
        """Test token expiration with no expires_at attribute."""
        token = Mock()
        token.expires_at = None

        assert is_token_expired(token) is True

    def test_is_token_expired_valid_token(self):
        """Test token expiration with valid token."""
        token = Mock()
        token.expires_at = time.time() + 3600  # Expires in 1 hour

        assert is_token_expired(token) is False

    def test_is_token_expired_expired_token(self):
        """Test token expiration with expired token."""
        token = Mock()
        token.expires_at = time.time() - 3600  # Expired 1 hour ago

        assert is_token_expired(token) is True

    def test_is_token_expired_missing_attribute(self):
        """Test token expiration with missing expires_at attribute."""
        token = Mock(spec=[])  # Empty spec, no attributes

        assert is_token_expired(token) is True


class TestGetEndpoint:
    """Test the get_endpoint function."""

    def test_get_endpoint_success(self):
        """Test successful endpoint retrieval."""
        metadata = Mock()
        metadata.authorization_endpoint = "https://example.com/auth"

        result = get_endpoint(metadata, "authorization_endpoint")

        assert result == "https://example.com/auth"

    def test_get_endpoint_missing(self):
        """Test endpoint retrieval with missing endpoint."""
        metadata = Mock()
        metadata.authorization_endpoint = None

        with pytest.raises(
            Exception, match="authorization_endpoint not found in metadata"
        ):
            get_endpoint(metadata, "authorization_endpoint")

    def test_get_endpoint_attribute_not_exists(self):
        """Test endpoint retrieval with non-existent attribute."""
        metadata = Mock(spec=[])  # Empty spec, no attributes

        with pytest.raises(
            Exception, match="nonexistent_endpoint not found in metadata"
        ):
            get_endpoint(metadata, "nonexistent_endpoint")


class TestHandleAuthentication:
    """Test the authentication handling functions."""

    def test_handle_successful_authentication(self):
        """Test successful authentication response."""
        response: HTMLResponse = handle_successful_authentication()

        assert response.status_code == 200
        assert "Authentication Successful!" in bytes(response.body).decode()
        assert "text/html" in response.media_type

    def test_handle_failed_authentication_default(self):
        """Test failed authentication response with default message."""
        response = handle_failed_authentication()

        assert response.status_code == 200
        assert "Authentication Failed!" in bytes(response.body).decode()
        assert "text/html" in response.media_type

    def test_handle_failed_authentication_custom_error(self):
        """Test failed authentication response with custom error."""
        error_desc = "Invalid credentials provided"
        response = handle_failed_authentication(error_desc)

        assert response.status_code == 200
        body = bytes(response.body).decode()
        assert "Authentication Failed!" in body
        assert error_desc in body


class TestGenerateCodeVerifier:
    """Test the generate_code_verifier function."""

    def test_generate_code_verifier_default_length(self):
        """Test code verifier generation with default length."""
        verifier = generate_code_verifier()

        assert len(verifier) == 128
        # Check that all characters are from the allowed set
        allowed_chars = set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        )
        assert all(c in allowed_chars for c in verifier)

    def test_generate_code_verifier_custom_length(self):
        """Test code verifier generation with custom length."""
        length = 64
        verifier = generate_code_verifier(length)

        assert len(verifier) == length

    def test_generate_code_verifier_minimum_length(self):
        """Test code verifier generation with minimum length."""
        length = 43
        verifier = generate_code_verifier(length)

        assert len(verifier) == length

    def test_generate_code_verifier_maximum_length(self):
        """Test code verifier generation with maximum length."""
        length = 128
        verifier = generate_code_verifier(length)

        assert len(verifier) == length

    def test_generate_code_verifier_invalid_length_too_short(self):
        """Test code verifier generation with invalid length (too short)."""
        with pytest.raises(
            ValueError, match="Code verifier length must be between 43 and 128"
        ):
            generate_code_verifier(42)

    def test_generate_code_verifier_invalid_length_too_long(self):
        """Test code verifier generation with invalid length (too long)."""
        with pytest.raises(
            ValueError, match="Code verifier length must be between 43 and 128"
        ):
            generate_code_verifier(129)

    def test_generate_code_verifier_uniqueness(self):
        """Test that generated code verifiers are unique."""
        verifier1 = generate_code_verifier()
        verifier2 = generate_code_verifier()

        assert verifier1 != verifier2


class TestGenerateCodeChallenge:
    """Test the generate_code_challenge function."""

    def test_generate_code_challenge(self):
        """Test code challenge generation."""
        code_verifier = "test_verifier_12345"
        challenge = generate_code_challenge(code_verifier)

        # Should be base64url encoded SHA256 hash without padding
        assert (
            len(challenge) == 43
        )  # SHA256 is 32 bytes, base64 is 43 chars without padding
        # Should not contain padding characters
        assert not challenge.endswith("=")

    def test_generate_code_challenge_consistency(self):
        """Test that the same verifier always produces the same challenge."""
        code_verifier = "consistent_verifier"
        challenge1 = generate_code_challenge(code_verifier)
        challenge2 = generate_code_challenge(code_verifier)

        assert challenge1 == challenge2

    def test_generate_code_challenge_different_verifiers(self):
        """Test that different verifiers produce different challenges."""
        verifier1 = "verifier_one"
        verifier2 = "verifier_two"

        challenge1 = generate_code_challenge(verifier1)
        challenge2 = generate_code_challenge(verifier2)

        assert challenge1 != challenge2


class TestPerformTokenFlow:
    """Test the perform_token_flow function."""

    @pytest.mark.asyncio
    async def test_perform_token_flow_success(self):
        """Test successful token flow."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "test_code"}
        token_response = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
        }

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = token_response
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await perform_token_flow(url, data)

            assert isinstance(result, OAuthToken)
            assert result.access_token == "test_access_token"
            assert result.token_type == "Bearer"
            assert result.expires_in == 3600
            assert result.expires_at is not None

            mock_client.post.assert_called_once_with(
                url=url,
                data=data,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Accept": "application/json",
                },
                timeout=30.0,
            )

    @pytest.mark.asyncio
    async def test_perform_token_flow_custom_params(self):
        """Test token flow with custom headers and timeout."""
        url = "https://example.com/token"
        data = {"grant_type": "refresh_token", "refresh_token": "test_refresh"}
        custom_headers = {
            "Content-Type": "application/json",
            "Authorization": "Basic xyz",
        }
        timeout = 60.0
        token_response = {"access_token": "new_access_token", "token_type": "Bearer"}

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = token_response
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await perform_token_flow(url, data, custom_headers, timeout)

            assert isinstance(result, OAuthToken)
            assert result.access_token == "new_access_token"
            # Should set default expiry when not provided
            assert result.expires_at is not None

            mock_client.post.assert_called_once_with(
                url=url, data=data, headers=custom_headers, timeout=timeout
            )

    @pytest.mark.asyncio
    async def test_perform_token_flow_http_error(self):
        """Test token flow with HTTP error."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "invalid_code"}

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 400
            mock_response.text = "Invalid authorization code"
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            with pytest.raises(ValueError, match="Token endpoint call failed"):
                await perform_token_flow(url, data)

    @pytest.mark.asyncio
    async def test_perform_token_flow_network_error(self):
        """Test token flow with network error."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "test_code"}

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_client.post.side_effect = Exception("Network error")
            mock_client_context.return_value.__aenter__.return_value = mock_client

            with pytest.raises(ValueError, match="Token endpoint call failed"):
                await perform_token_flow(url, data)

    @pytest.mark.asyncio
    async def test_perform_token_flow_invalid_response(self):
        """Test token flow with invalid JSON response."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "test_code"}

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            with pytest.raises(ValueError, match="Token endpoint call failed"):
                await perform_token_flow(url, data)

    @pytest.mark.asyncio
    async def test_perform_token_flow_expires_at_calculation(self):
        """Test token flow expires_at calculation."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "test_code"}

        # Test case 1: With expires_in
        token_response_with_expires_in = {
            "access_token": "test_token",
            "token_type": "Bearer",
            "expires_in": 1800,
        }

        with (
            patch(
                "fhir_mcp_server.oauth.common.create_mcp_http_client"
            ) as mock_client_context,
            patch("fhir_mcp_server.oauth.common.time.time", return_value=1000000),
        ):

            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = token_response_with_expires_in
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await perform_token_flow(url, data)

            assert result.expires_at == 1001800  # 1000000 + 1800

    @pytest.mark.asyncio
    async def test_perform_token_flow_default_expiry(self):
        """Test token flow default expiry when no expires_in provided."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "test_code"}

        # Test case: Without expires_in
        token_response_no_expires = {
            "access_token": "test_token",
            "token_type": "Bearer",
        }

        with (
            patch(
                "fhir_mcp_server.oauth.common.create_mcp_http_client"
            ) as mock_client_context,
            patch("fhir_mcp_server.oauth.common.time.time", return_value=2000000),
        ):

            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = token_response_no_expires
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await perform_token_flow(url, data)

            assert result.expires_at == 2003600  # 2000000 + 3600 (default)


class TestDiscoverOAuthMetadataEdgeCases:
    """Test edge cases for discover_oauth_metadata function."""

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_empty_response(self):
        """Test OAuth metadata discovery with empty response."""
        metadata_url = "https://example.com/.well-known/oauth"

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {}
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            with pytest.raises(Exception):  # Should fail validation
                await discover_oauth_metadata(metadata_url)

    @pytest.mark.asyncio
    async def test_discover_oauth_metadata_malformed_urls(self):
        """Test OAuth metadata discovery with malformed URLs in response."""
        metadata_url = "https://example.com/.well-known/oauth"
        metadata_response = {
            "issuer": "not-a-valid-url",
            "authorization_endpoint": "also-not-valid",
            "token_endpoint": "https://example.com/token",
            "response_types_supported": ["code"],
        }

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = metadata_response
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            with pytest.raises(Exception):  # Should fail validation
                await discover_oauth_metadata(metadata_url)


class TestTokenFlowEdgeCases:
    """Test edge cases for token flow operations."""

    @pytest.mark.asyncio
    async def test_perform_token_flow_with_refresh_token_response(self):
        """Test token flow with refresh token in response."""
        url = "https://example.com/token"
        data = {"grant_type": "authorization_code", "code": "test_code"}
        token_response = {
            "access_token": "test_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "test_refresh_token",
            "scope": "read write"
        }

        with patch(
            "fhir_mcp_server.oauth.common.create_mcp_http_client"
        ) as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = token_response
            mock_client.post.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client

            result = await perform_token_flow(url, data)

            assert isinstance(result, OAuthToken)
            assert result.access_token == "test_access_token"
            assert result.token_type == "Bearer"
            assert result.expires_in == 3600
            assert result.refresh_token == "test_refresh_token"
            assert result.scope == "read write"
            assert result.expires_at is not None
