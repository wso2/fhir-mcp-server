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
from unittest.mock import patch, Mock

from fhir_mcp_server.oauth.types import ServerConfigs
from fhir_mcp_server.oauth.client_provider import FHIRClientProvider
from fhir_mcp_server.oauth.server_provider import OAuthServerProvider


class TestIntegration:
    """Integration tests for the FHIR MCP server components."""

    def test_server_configs_integration(self):
        """Test that server configurations work with providers."""
        config = ServerConfigs(
            host="0.0.0.0",
            port=9000,
            fhir__base_url="https://custom.fhir.org",
            fhir__timeout=60
        )
        
        # Test that nested configuration works
        assert config.host == "0.0.0.0"
        assert config.port == 9000
        assert config.effective_server_url == "http://0.0.0.0:9000"
        
        # Test that providers can be initialized with the config
        server_provider = OAuthServerProvider(configs=config)
        assert server_provider.configs == config
        
        client_provider = FHIRClientProvider(
            callback_url=AnyHttpUrl("https://example.com/callback"),
            configs=config.fhir
        )
        assert client_provider.configs == config.fhir

    def test_fhir_client_provider_with_server_config(self):
        """Test FHIR client provider integration with server config."""
        server_config = ServerConfigs()
        
        # Modify FHIR config
        server_config.fhir.client_id = "test_client"
        server_config.fhir.client_secret = "test_secret" 
        server_config.fhir.scope = "read write"
        
        client_provider = FHIRClientProvider(
            callback_url=server_config.fhir.callback_url(server_config.effective_server_url),
            configs=server_config.fhir
        )
        
        assert client_provider.configs.client_id == "test_client"
        assert client_provider.configs.client_secret == "test_secret"
        assert client_provider.configs.scopes == ["read", "write"]
        assert str(client_provider.callback_url) == "http://localhost:8000/fhir/callback"

    @pytest.mark.asyncio
    async def test_oauth_flow_integration(self):
        """Test integration between client and server providers for OAuth flow."""
        # Set up server config
        server_config = ServerConfigs(host="localhost", port=8080)
        server_config.fhir.client_id = "integration_test_client"
        server_config.fhir.client_secret = "integration_test_secret"
        
        # Set up providers
        server_provider = OAuthServerProvider(configs=server_config)
        client_provider = FHIRClientProvider(
            callback_url=server_config.fhir.callback_url(server_config.effective_server_url),
            configs=server_config.fhir
        )
        
        # Mock external dependencies
        with patch.object(client_provider, '_discover_oauth_metadata') as mock_discover:
            mock_metadata = Mock()
            mock_metadata.authorization_endpoint = "https://example.com/auth"
            mock_metadata.token_endpoint = "https://example.com/token"
            mock_discover.return_value = mock_metadata
            
            with patch.object(client_provider, '_generate_code_verifier', return_value="test_verifier"), \
                 patch.object(client_provider, '_generate_code_challenge', return_value="test_challenge"), \
                 patch('fhir_mcp_server.oauth.client_provider.secrets.token_urlsafe', return_value="test_state"):
                
                # Start OAuth flow
                await client_provider._perform_oauth_flow("test_token_id")
                
                # Verify state was stored
                assert "test_state" in client_provider.state_mapping
                state_data = client_provider.state_mapping["test_state"]
                assert state_data["token_id"] == "test_token_id"
                assert state_data["client_id"] == "integration_test_client"

    def test_config_url_generation_integration(self):
        """Test URL generation integration across different configs."""
        # Create ServerConfigs with mocked FHIR configuration
        with patch.dict('os.environ', {}, clear=True):  # Clear env vars to avoid external config
            server_config = ServerConfigs(
                host="api.example.com",
                port=443,
                server_url="https://api.example.com"
            )
            
            # Mock the FHIR config with test values to avoid external URLs
            mock_base_url = "https://mock.fhir.local/R4"
            server_config.fhir.base_url = mock_base_url
            
            # Test OAuth callback URL
            oauth_callback = server_config.oauth.callback_url(server_config.effective_server_url)
            assert str(oauth_callback) == "https://api.example.com/oauth/callback"
            
            # Test FHIR callback URL  
            fhir_callback = server_config.fhir.callback_url(server_config.effective_server_url)
            assert str(fhir_callback) == "https://api.example.com/fhir/callback"
            
            # Test FHIR discovery URL with mocked config
            assert server_config.fhir.discovery_url == f"{mock_base_url}/.well-known/smart-configuration"
            
            # Test FHIR metadata URL with mocked config
            assert server_config.fhir.metadata_url == f"{mock_base_url}/metadata?_format=json"

    def test_provider_initialization_integration(self):
        """Test that all providers can be initialized together."""
        config = ServerConfigs()
        
        # Initialize server provider
        server_provider = OAuthServerProvider(configs=config)
        assert server_provider is not None
        
        # Initialize client provider
        client_provider = FHIRClientProvider(
            callback_url=config.fhir.callback_url(config.effective_server_url),
            configs=config.fhir
        )
        assert client_provider is not None
        
        # Verify they use the same configuration
        assert client_provider.configs == config.fhir
        assert server_provider.configs == config
