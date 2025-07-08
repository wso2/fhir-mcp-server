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
import asyncio
from unittest.mock import AsyncMock, Mock, patch
from http.client import HTTPException

from fhir_mcp_server.oauth.client_provider import FHIRClientProvider, webbrowser_redirect_handler
from fhir_mcp_server.oauth.types import FHIROAuthConfigs, OAuthMetadata, OAuthToken

# Patch webbrowser.open_new_tab for all tests in this module to prevent browser opening
from unittest.mock import Mock, AsyncMock, patch

class TestWebBrowserRedirectHandler:
    """Test the webbrowser redirect handler function."""

    @pytest.mark.asyncio
    @patch('fhir_mcp_server.oauth.client_provider.webbrowser.open_new_tab')
    @patch('builtins.print')
    async def test_webbrowser_redirect_handler(self, mock_print, mock_open):
        """Test webbrowser redirect handler opens browser."""
        authorization_url = "https://example.com/auth?code=123"
        await webbrowser_redirect_handler(authorization_url)
        mock_print.assert_called_once_with(f"Opening user's browser with URL: {authorization_url}")
        mock_open.assert_called_once_with(authorization_url)


class TestFHIRClientProvider:
    """Test the FHIRClientProvider class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.callback_url = "https://example.com/callback"
        self.configs = FHIROAuthConfigs(
            client_id="test_client",
            client_secret="test_secret",
            scope="read write",
            base_url="https://fhir.example.com"
        )
        self.redirect_handler = AsyncMock()
        self.provider = FHIRClientProvider(
            callback_url=AnyHttpUrl(self.callback_url),
            configs=self.configs,
            redirect_handler=self.redirect_handler
        )

    def test_init_basic(self):
        """Test basic initialization."""
        assert str(self.provider.callback_url) == self.callback_url
        assert self.provider.configs == self.configs
        assert self.provider.redirect_handler == self.redirect_handler
        assert self.provider.state_mapping == {}
        assert self.provider.token_mapping == {}
        assert self.provider._metadata is None

    @patch('fhir_mcp_server.oauth.client_provider.webbrowser.open_new_tab')
    def test_init_default_redirect_handler(self, mock_open):
        """Test initialization with default redirect handler."""
        provider = FHIRClientProvider(
            callback_url=AnyHttpUrl(self.callback_url),
            configs=self.configs
        )
        assert provider.redirect_handler == webbrowser_redirect_handler

    @patch('fhir_mcp_server.oauth.client_provider.generate_code_verifier')
    def test_generate_code_verifier(self, mock_generate):
        """Test code verifier generation."""
        mock_generate.return_value = "test_verifier"
        
        result = self.provider._generate_code_verifier()
        
        assert result == "test_verifier"
        mock_generate.assert_called_once_with(128)

    @patch('fhir_mcp_server.oauth.client_provider.generate_code_challenge')
    def test_generate_code_challenge(self, mock_generate):
        """Test code challenge generation."""
        mock_generate.return_value = "test_challenge"
        code_verifier = "test_verifier"
        
        result = self.provider._generate_code_challenge(code_verifier)
        
        assert result == "test_challenge"
        mock_generate.assert_called_once_with(code_verifier)

    @pytest.mark.asyncio
    @patch('fhir_mcp_server.oauth.client_provider.discover_oauth_metadata')
    async def test_discover_oauth_metadata(self, mock_discover):
        """Test OAuth metadata discovery."""
        mock_metadata = OAuthMetadata(
            issuer=AnyHttpUrl("https://example.com"),
            authorization_endpoint=AnyHttpUrl("https://example.com/auth"),
            token_endpoint=AnyHttpUrl("https://example.com/token"),
            response_types_supported=["code"]
        )
        mock_discover.return_value = mock_metadata
        discovery_url = "https://example.com/.well-known/oauth"
        
        result = await self.provider._discover_oauth_metadata(discovery_url)
        
        assert result == mock_metadata
        mock_discover.assert_called_once_with(metadata_url=discovery_url)

    @patch('fhir_mcp_server.oauth.client_provider.is_token_expired')
    def test_is_valid_token_valid(self, mock_is_expired):
        """Test valid token check."""
        mock_is_expired.return_value = False
        token_id = "test_token_id"
        mock_token = OAuthToken(access_token="test_token", token_type="Bearer")
        self.provider.token_mapping[token_id] = mock_token
        
        result = self.provider._is_valid_token(token_id)
        
        assert result is True
        mock_is_expired.assert_called_once_with(mock_token)

    @patch('fhir_mcp_server.oauth.client_provider.is_token_expired')
    def test_is_valid_token_expired(self, mock_is_expired):
        """Test expired token check."""
        mock_is_expired.return_value = True
        token_id = "test_token_id"
        mock_token = OAuthToken(access_token="test_token", token_type="Bearer")
        self.provider.token_mapping[token_id] = mock_token
        
        result = self.provider._is_valid_token(token_id)
        
        assert result is False

    def test_is_valid_token_not_found(self):
        """Test token check when token not found."""
        token_id = "nonexistent_token"
        
        result = self.provider._is_valid_token(token_id)
        
        assert result is False

    @pytest.mark.asyncio
    async def test_validate_token_scopes_no_scope(self):
        """Test scope validation when no scope returned."""
        token_response = OAuthToken(access_token="test_token", token_type="Bearer")
        
        # Should not raise any exception
        await self.provider._validate_token_scopes(token_response)

    @pytest.mark.asyncio
    async def test_validate_token_scopes_no_config_scope(self):
        """Test scope validation when no scope configured."""
        self.provider.configs.scope = ""
        token_response = OAuthToken(
            access_token="test_token", 
            token_type="Bearer",
            scope="read write"
        )
        
        # Should not raise any exception
        await self.provider._validate_token_scopes(token_response)

    @pytest.mark.asyncio
    async def test_validate_token_scopes_valid(self):
        """Test scope validation with valid scopes."""
        token_response = OAuthToken(
            access_token="test_token", 
            token_type="Bearer",
            scope="read write"
        )
        
        # Should not raise any exception
        await self.provider._validate_token_scopes(token_response)

    @pytest.mark.asyncio
    async def test_validate_token_scopes_subset(self):
        """Test scope validation with subset of requested scopes."""
        token_response = OAuthToken(
            access_token="test_token", 
            token_type="Bearer",
            scope="read"  # Only subset of "read write"
        )
        
        # Should not raise any exception (subset is allowed)
        await self.provider._validate_token_scopes(token_response)

    @pytest.mark.asyncio
    async def test_validate_token_scopes_invalid(self):
        """Test scope validation with unauthorized scopes."""
        token_response = OAuthToken(
            access_token="test_token", 
            token_type="Bearer",
            scope="read write admin"  # Extra 'admin' scope not requested
        )
        
        with pytest.raises(ValueError, match="scope validation failed"):
            await self.provider._validate_token_scopes(token_response)

    @pytest.mark.asyncio
    async def test_ensure_token_already_valid(self):
        """Test ensure_token when token is already valid."""
        token_id = "test_token_id"
        
        with patch.object(self.provider, '_is_valid_token', return_value=True):
            await self.provider.ensure_token(token_id)
            
            # Should return early without further calls

    @pytest.mark.asyncio
    async def test_ensure_token_refresh_successful(self):
        """Test ensure_token when refresh is successful."""
        token_id = "test_token_id"
        
        with patch.object(self.provider, '_is_valid_token', return_value=False), \
             patch.object(self.provider, '_refresh_access_token', return_value=True):
            
            await self.provider.ensure_token(token_id)

    @pytest.mark.asyncio
    async def test_ensure_token_oauth_flow(self):
        """Test ensure_token falls back to OAuth flow."""
        token_id = "test_token_id"
        
        with patch.object(self.provider, '_is_valid_token', return_value=False), \
             patch.object(self.provider, '_refresh_access_token', return_value=False), \
             patch.object(self.provider, '_perform_oauth_flow') as mock_oauth:
            
            await self.provider.ensure_token(token_id)
            
            mock_oauth.assert_called_once_with(token_id)

    @pytest.mark.asyncio
    async def test_perform_oauth_flow(self):
        """Test OAuth flow execution."""
        token_id = "test_token_id"
        mock_metadata = OAuthMetadata(
            issuer=AnyHttpUrl("https://example.com"),
            authorization_endpoint=AnyHttpUrl("https://example.com/auth"),
            token_endpoint=AnyHttpUrl("https://example.com/token"),
            response_types_supported=["code"]
        )
        
        with patch.object(self.provider, '_discover_oauth_metadata', return_value=mock_metadata), \
             patch.object(self.provider, '_generate_code_verifier', return_value="test_verifier"), \
             patch.object(self.provider, '_generate_code_challenge', return_value="test_challenge"), \
             patch.object(self.provider, '_get_authorization_endpoint', return_value="https://example.com/auth"), \
             patch('fhir_mcp_server.oauth.client_provider.secrets.token_urlsafe', return_value="test_state"):
            
            await self.provider._perform_oauth_flow(token_id)
            
            # Verify redirect handler was called
            self.redirect_handler.assert_called_once()
            call_args = self.redirect_handler.call_args[0][0]
            assert "https://example.com/auth" in call_args
            assert "client_id=test_client" in call_args
            assert "scope=read+write" in call_args
            
            # Verify state mapping was set
            assert "test_state" in self.provider.state_mapping
            state_data = self.provider.state_mapping["test_state"]
            assert state_data["token_id"] == token_id
            assert state_data["code_verifier"] == "test_verifier"

    @pytest.mark.asyncio
    async def test_handle_fhir_oauth_callback_valid(self):
        """Test handling valid OAuth callback."""
        code = "test_auth_code"
        state = "test_state"
        token_id = "test_token_id"
        
        # Set up state mapping
        self.provider.state_mapping[state] = {
            "code_verifier": "test_verifier",
            "token_id": token_id
        }
        
        with patch.object(self.provider, '_exchange_code_for_token') as mock_exchange:
            await self.provider.handle_fhir_oauth_callback(code, state)
            
            mock_exchange.assert_called_once_with(token_id, code, "test_verifier")

    @pytest.mark.asyncio
    async def test_handle_fhir_oauth_callback_invalid_state(self):
        """Test handling OAuth callback with invalid state."""
        code = "test_auth_code"
        state = "invalid_state"
        
        with pytest.raises(HTTPException) as exc_info:
            await self.provider.handle_fhir_oauth_callback(code, state)
        
        assert exc_info.value.args == (400, "Invalid state parameter")

    @pytest.mark.asyncio
    @patch('fhir_mcp_server.oauth.client_provider.perform_token_flow')
    async def test_exchange_code_for_token_success(self, mock_perform_token):
        """Test successful code exchange for token."""
        token_id = "test_token_id"
        auth_code = "test_auth_code"
        code_verifier = "test_verifier"
        
        mock_token = OAuthToken(access_token="test_access_token", token_type="Bearer")
        mock_perform_token.return_value = mock_token
        
        with patch.object(self.provider, '_get_token_endpoint', return_value="https://example.com/token"):
            await self.provider._exchange_code_for_token(token_id, auth_code, code_verifier)
            
            # Verify token was stored
            assert self.provider.token_mapping[token_id] == mock_token
            
            # Verify token flow was called with correct parameters
            call_args = mock_perform_token.call_args
            assert call_args[1]["url"] == "https://example.com/token"
            data = call_args[1]["data"]
            assert data["grant_type"] == "authorization_code"
            assert data["code"] == auth_code
            assert data["code_verifier"] == code_verifier

    @pytest.mark.asyncio
    @patch('fhir_mcp_server.oauth.client_provider.perform_token_flow')
    async def test_exchange_code_for_token_failure(self, mock_perform_token):
        """Test failed code exchange for token."""
        token_id = "test_token_id"
        auth_code = "test_auth_code"
        code_verifier = "test_verifier"
        
        mock_perform_token.side_effect = Exception("Token request failed")
        
        with patch.object(self.provider, '_get_token_endpoint', return_value="https://example.com/token"), \
             pytest.raises(ValueError, match="Access token request failed"):
            
            await self.provider._exchange_code_for_token(token_id, auth_code, code_verifier)

    @patch('fhir_mcp_server.oauth.client_provider.get_endpoint')
    def test_get_authorization_endpoint(self, mock_get_endpoint):
        """Test getting authorization endpoint."""
        mock_get_endpoint.return_value = "https://example.com/auth"
        self.provider._metadata = Mock()
        
        result = self.provider._get_authorization_endpoint()
        
        assert result == "https://example.com/auth"
        mock_get_endpoint.assert_called_once_with(self.provider._metadata, "authorization_endpoint")

    @patch('fhir_mcp_server.oauth.client_provider.get_endpoint')
    def test_get_token_endpoint(self, mock_get_endpoint):
        """Test getting token endpoint."""
        mock_get_endpoint.return_value = "https://example.com/token"
        self.provider._metadata = Mock()
        
        result = self.provider._get_token_endpoint()
        
        assert result == "https://example.com/token"
        mock_get_endpoint.assert_called_once_with(self.provider._metadata, "token_endpoint")

    @pytest.mark.asyncio
    @patch('fhir_mcp_server.oauth.client_provider.perform_token_flow')
    async def test_refresh_access_token_success(self, mock_perform_token):
        """Test successful token refresh."""
        token_id = "test_token_id"
        current_token = OAuthToken(
            access_token="old_token",
            token_type="Bearer",
            refresh_token="refresh_token"
        )
        new_token = OAuthToken(access_token="new_token", token_type="Bearer")
        
        self.provider.token_mapping[token_id] = current_token
        mock_perform_token.return_value = new_token
        
        with patch.object(self.provider, '_get_token_endpoint', return_value="https://example.com/token"):
            await self.provider._refresh_access_token(token_id)
            
            # Verify new token was stored
            assert self.provider.token_mapping[token_id] == new_token
            
            # Verify refresh request was made
            call_args = mock_perform_token.call_args
            data = call_args[1]["data"]
            assert data["grant_type"] == "refresh_token"
            assert data["refresh_token"] == "refresh_token"

    @pytest.mark.asyncio
    async def test_refresh_access_token_no_token(self):
        """Test token refresh when no token exists."""
        token_id = "nonexistent_token"
        
        result = await self.provider._refresh_access_token(token_id)
        
        assert result is None

    @pytest.mark.asyncio
    @patch('fhir_mcp_server.oauth.client_provider.perform_token_flow')
    async def test_refresh_access_token_failure(self, mock_perform_token):
        """Test failed token refresh."""
        token_id = "test_token_id"
        current_token = OAuthToken(
            access_token="old_token",
            token_type="Bearer",
            refresh_token="refresh_token"
        )
        
        self.provider.token_mapping[token_id] = current_token
        mock_perform_token.side_effect = Exception("Refresh failed")
        
        with patch.object(self.provider, '_get_token_endpoint', return_value="https://example.com/token"), \
             pytest.raises(ValueError, match="Token refresh failed"):
            
            await self.provider._refresh_access_token(token_id)

    @pytest.mark.asyncio
    async def test_get_access_token_success(self):
        """Test successful access token retrieval."""
        token_id = "test_token_id"
        mock_token = OAuthToken(access_token="test_token", token_type="Bearer")
        
        with patch.object(self.provider, 'ensure_token'):
            self.provider.token_mapping[token_id] = mock_token
            
            result = await self.provider.get_access_token(token_id)
            
            assert result == mock_token

    @pytest.mark.asyncio
    async def test_get_access_token_with_wait(self):
        """Test access token retrieval with wait for token."""
        token_id = "test_token_id"
        mock_token = OAuthToken(access_token="test_token", token_type="Bearer")
        
        async def delayed_token_set():
            await asyncio.sleep(0.1)
            self.provider.token_mapping[token_id] = mock_token
        
        with patch.object(self.provider, 'ensure_token'), \
             patch('fhir_mcp_server.oauth.client_provider.asyncio.sleep', return_value=None):
            
            # Start setting the token after a delay
            asyncio.create_task(delayed_token_set())
            
            # Simulate the wait loop by manually setting the token
            self.provider.token_mapping[token_id] = mock_token
            
            result = await self.provider.get_access_token(token_id)
            
            assert result == mock_token

    @pytest.mark.asyncio
    async def test_get_access_token_timeout(self):
        """Test access token retrieval timeout."""
        token_id = "test_token_id"
        self.provider.configs.timeout = 1  # Short timeout for test
        
        with patch.object(self.provider, 'ensure_token'), \
             patch('fhir_mcp_server.oauth.client_provider.asyncio.sleep', return_value=None), \
             pytest.raises(ValueError, match="Failed to obtain user access token"):
            
            await self.provider.get_access_token(token_id)
