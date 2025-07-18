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

import os
import pytest
from unittest.mock import patch, Mock

from fhir_mcp_server.oauth.types import ServerConfigs
from fhir_mcp_server.oauth.server_provider import OAuthServerProvider


class TestIntegration:
    """Integration tests for the FHIR MCP server components."""

    def test_server_configs_integration(self):
        """Test that server configurations work with providers."""
        
        # Clear environment variables and disable .env file loading
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(
                mcp_host="0.0.0.0",
                mcp_port=9000,
                _env_file=None
            )
            
            # Set the server config after initialization
            config.server_base_url = "https://custom.fhir.org"
            config.server_request_timeout = 60
            
            # Test that nested configuration works
            assert config.mcp_host == "0.0.0.0"
            assert config.mcp_port == 9000
            assert config.effective_server_url == "http://0.0.0.0:9000"
            
            # Test that providers can be initialized with the config
            server_provider = OAuthServerProvider(configs=config)
            assert server_provider.configs == config
            
            # Test server config integration
            assert config.server_base_url == "https://custom.fhir.org"
            assert config.server_request_timeout == 60

    def test_fhir_oauth_config_integration(self):
        """Test FHIR OAuth config integration with server config."""
        
        # Clear environment variables and disable .env file loading
        with patch.dict(os.environ, {}, clear=True):
            server_config = ServerConfigs(_env_file=None)
            
            # Modify server config using the new structure
            server_config.server_client_id = "test_client"
            server_config.server_client_secret = "test_secret" 
            server_config.server_scopes = "read write"
            
            # Test that the config values are properly set
            assert server_config.server_client_id == "test_client"
            assert server_config.server_client_secret == "test_secret"
            assert server_config.scopes == ["read", "write"]
            
            # Test callback URL generation
            callback_url = server_config.callback_url(server_config.effective_server_url)
            assert str(callback_url) == "http://localhost:8000/oauth/callback"

    @pytest.mark.asyncio
    async def test_oauth_server_provider_integration(self):
        """Test OAuth server provider integration."""
        
        # Clear environment variables and disable .env file loading
        with patch.dict(os.environ, {}, clear=True):
            # Set up server config
            server_config = ServerConfigs(mcp_host="localhost", mcp_port=8080, _env_file=None)
            server_config.server_client_id = "integration_test_client"
            server_config.server_client_secret = "integration_test_secret"
            
            # Set up server provider
            server_provider = OAuthServerProvider(configs=server_config)
            
            # Mock external dependencies
            with patch.object(server_provider, '_discover_oauth_metadata') as mock_discover:
                mock_metadata = Mock()
                mock_metadata.authorization_endpoint = "https://example.com/auth"
                mock_metadata.token_endpoint = "https://example.com/token"
                mock_discover.return_value = mock_metadata
                
                # Initialize server provider
                await server_provider.initialize()
                
                # Verify metadata was discovered
                assert server_provider._metadata == mock_metadata
                assert await server_provider._get_authorization_endpoint() == "https://example.com/auth"
                assert await server_provider._get_token_endpoint() == "https://example.com/token"

    def test_config_url_generation_integration(self):
        """Test URL generation integration across different configs."""
        # Create ServerConfigs with mocked FHIR configuration
        with patch.dict('os.environ', {}, clear=True):  # Clear env vars to avoid external config
            server_config = ServerConfigs(
                mcp_host="api.example.com",
                mcp_port=443,
                mcp_server_url="https://api.example.com"
            )
            
            # Mock the server config with test values to avoid external URLs
            mock_base_url = "https://mock.fhir.local/R4"
            server_config.server_base_url = mock_base_url
            
            # Test OAuth callback URL
            oauth_callback = server_config.callback_url(server_config.effective_server_url)
            assert str(oauth_callback) == "https://api.example.com/oauth/callback"
            
            # Test FHIR discovery URL with mocked config
            assert server_config.discovery_url == f"{mock_base_url}/.well-known/smart-configuration"
            
            # Test FHIR metadata URL with mocked config
            assert server_config.metadata_url == f"{mock_base_url}/metadata?_format=json"

    def test_provider_initialization_integration(self):
        """Test that server provider can be initialized with config."""
        
        # Clear environment variables and disable .env file loading
        with patch.dict(os.environ, {}, clear=True):
            config = ServerConfigs(_env_file=None)
            
            # Initialize server provider
            server_provider = OAuthServerProvider(configs=config)
            assert server_provider is not None
            
            # Verify it uses the configuration
            assert server_provider.configs == config
            assert server_provider.configs is not None
