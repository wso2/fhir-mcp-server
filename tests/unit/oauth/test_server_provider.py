import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock
from typing import Dict, Any

from fhir_mcp_server.oauth.server_provider import OAuthServerProvider
from fhir_mcp_server.oauth.types import ServerConfigs, MCPOAuthConfigs


class TestOAuthServerProvider:
    """Test the OAuthServerProvider class."""

    def setup_method(self):
        """Set up test fixtures."""
        self.mock_configs = ServerConfigs(
            host="localhost",
            port=8000,
            server_url="http://localhost:8000"
        )
        self.mock_configs.oauth = MCPOAuthConfigs(
            client_id="test_client_id",
            client_secret="test_client_secret",
            metadata_url="https://auth.example.com/.well-known/oauth-authorization-server"
        )

    @pytest.mark.asyncio
    async def test_init_server_provider(self):
        """Test OAuthServerProvider initialization."""
        provider = OAuthServerProvider(self.mock_configs)
        
        assert provider.configs == self.mock_configs
        assert provider.oauth_configs == self.mock_configs.oauth

    @pytest.mark.asyncio
    async def test_get_client_metadata(self):
        """Test get_client_metadata method."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the discover_oauth_metadata function
        with patch('fhir_mcp_server.oauth.server_provider.discover_oauth_metadata') as mock_discover:
            mock_metadata = {
                "issuer": "https://auth.example.com",
                "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                "token_endpoint": "https://auth.example.com/oauth/token",
                "revocation_endpoint": "https://auth.example.com/oauth/revoke",
                "grant_types_supported": ["authorization_code", "refresh_token"],
                "response_types_supported": ["code"],
                "code_challenge_methods_supported": ["S256"],
                "scopes_supported": ["openid", "profile", "email"]
            }
            mock_discover.return_value = mock_metadata
            
            result = await provider.get_client_metadata()
            
            assert result["issuer"] == "https://auth.example.com"
            assert result["authorization_endpoint"] == "https://auth.example.com/oauth/authorize"
            assert result["token_endpoint"] == "https://auth.example.com/oauth/token"
            mock_discover.assert_called_once_with(self.mock_configs.oauth.metadata_url)

    @pytest.mark.asyncio
    async def test_get_client_metadata_error(self):
        """Test get_client_metadata with error handling."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the discover_oauth_metadata function to raise an exception
        with patch('fhir_mcp_server.oauth.server_provider.discover_oauth_metadata') as mock_discover:
            mock_discover.side_effect = Exception("OAuth metadata discovery failed")
            
            with pytest.raises(Exception, match="OAuth metadata discovery failed"):
                await provider.get_client_metadata()

    @pytest.mark.asyncio
    async def test_get_authorization_url(self):
        """Test get_authorization_url method."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the discover_oauth_metadata function
        with patch('fhir_mcp_server.oauth.server_provider.discover_oauth_metadata') as mock_discover:
            mock_metadata = {
                "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                "code_challenge_methods_supported": ["S256"]
            }
            mock_discover.return_value = mock_metadata
            
            # Mock the PKCE generation functions
            with patch('fhir_mcp_server.oauth.server_provider.generate_code_verifier') as mock_verifier, \
                 patch('fhir_mcp_server.oauth.server_provider.generate_code_challenge') as mock_challenge:
                
                mock_verifier.return_value = "test_code_verifier"
                mock_challenge.return_value = "test_code_challenge"
                
                client_info = {
                    "client_id": "test_client_id",
                    "redirect_uri": "http://localhost:8000/oauth/callback"
                }
                
                auth_url, state = await provider.get_authorization_url(client_info)
                
                assert "https://auth.example.com/oauth/authorize" in auth_url
                assert "client_id=test_client_id" in auth_url
                assert "redirect_uri=http%3A//localhost%3A8000/oauth/callback" in auth_url
                assert "code_challenge=test_code_challenge" in auth_url
                assert "code_challenge_method=S256" in auth_url
                assert isinstance(state, str)
                assert len(state) > 0

    @pytest.mark.asyncio
    async def test_exchange_authorization_code(self):
        """Test exchange_authorization_code method."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the perform_token_flow function
        with patch('fhir_mcp_server.oauth.server_provider.perform_token_flow') as mock_token_flow:
            mock_token_response = {
                "access_token": "test_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "test_refresh_token",
                "scope": "openid profile email"
            }
            mock_token_flow.return_value = mock_token_response
            
            client_info = {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "redirect_uri": "http://localhost:8000/oauth/callback"
            }
            
            result = await provider.exchange_authorization_code(
                client_info, 
                "test_auth_code", 
                "test_state_data"
            )
            
            assert result["access_token"] == "test_access_token"
            assert result["token_type"] == "Bearer"
            assert result["expires_in"] == 3600
            assert result["refresh_token"] == "test_refresh_token"

    @pytest.mark.asyncio
    async def test_exchange_authorization_code_error(self):
        """Test exchange_authorization_code with error handling."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the perform_token_flow function to raise an exception
        with patch('fhir_mcp_server.oauth.server_provider.perform_token_flow') as mock_token_flow:
            mock_token_flow.side_effect = Exception("Token exchange failed")
            
            client_info = {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret",
                "redirect_uri": "http://localhost:8000/oauth/callback"
            }
            
            with pytest.raises(Exception, match="Token exchange failed"):
                await provider.exchange_authorization_code(
                    client_info, 
                    "test_auth_code", 
                    "test_state_data"
                )

    @pytest.mark.asyncio
    async def test_refresh_access_token(self):
        """Test refresh_access_token method."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the perform_token_flow function
        with patch('fhir_mcp_server.oauth.server_provider.perform_token_flow') as mock_token_flow:
            mock_token_response = {
                "access_token": "new_access_token",
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "new_refresh_token",
                "scope": "openid profile email"
            }
            mock_token_flow.return_value = mock_token_response
            
            client_info = {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret"
            }
            
            result = await provider.refresh_access_token(
                client_info, 
                "old_refresh_token"
            )
            
            assert result["access_token"] == "new_access_token"
            assert result["token_type"] == "Bearer"
            assert result["expires_in"] == 3600
            assert result["refresh_token"] == "new_refresh_token"

    @pytest.mark.asyncio
    async def test_refresh_access_token_error(self):
        """Test refresh_access_token with error handling."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the perform_token_flow function to raise an exception
        with patch('fhir_mcp_server.oauth.server_provider.perform_token_flow') as mock_token_flow:
            mock_token_flow.side_effect = Exception("Token refresh failed")
            
            client_info = {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret"
            }
            
            with pytest.raises(Exception, match="Token refresh failed"):
                await provider.refresh_access_token(
                    client_info, 
                    "old_refresh_token"
                )

    @pytest.mark.asyncio
    async def test_revoke_access_token(self):
        """Test revoke_access_token method."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the revoke implementation
        with patch('fhir_mcp_server.oauth.server_provider.discover_oauth_metadata') as mock_discover, \
             patch('fhir_mcp_server.oauth.server_provider.get_endpoint') as mock_get_endpoint:
            
            mock_metadata = {
                "revocation_endpoint": "https://auth.example.com/oauth/revoke"
            }
            mock_discover.return_value = mock_metadata
            mock_get_endpoint.return_value = "https://auth.example.com/oauth/revoke"
            
            # Mock the HTTP request
            with patch('aiohttp.ClientSession.post') as mock_post:
                mock_response = Mock()
                mock_response.status = 200
                mock_response.raise_for_status = Mock()
                mock_post.return_value.__aenter__.return_value = mock_response
                
                client_info = {
                    "client_id": "test_client_id",
                    "client_secret": "test_client_secret"
                }
                
                result = await provider.revoke_access_token(
                    client_info, 
                    "test_access_token"
                )
                
                # The method should complete without raising an exception
                assert result is None or result == True

    @pytest.mark.asyncio
    async def test_revoke_access_token_error(self):
        """Test revoke_access_token with error handling."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the revoke implementation to raise an exception
        with patch('fhir_mcp_server.oauth.server_provider.discover_oauth_metadata') as mock_discover:
            mock_discover.side_effect = Exception("Revoke endpoint discovery failed")
            
            client_info = {
                "client_id": "test_client_id",
                "client_secret": "test_client_secret"
            }
            
            with pytest.raises(Exception, match="Revoke endpoint discovery failed"):
                await provider.revoke_access_token(
                    client_info, 
                    "test_access_token"
                )

    def test_state_management(self):
        """Test state management methods."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Test state generation
        state1 = provider._generate_state()
        state2 = provider._generate_state()
        
        assert isinstance(state1, str)
        assert isinstance(state2, str)
        assert len(state1) > 0
        assert len(state2) > 0
        assert state1 != state2  # Should be unique

    def test_pkce_methods(self):
        """Test PKCE code generation methods."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Mock the PKCE generation functions
        with patch('fhir_mcp_server.oauth.server_provider.generate_code_verifier') as mock_verifier, \
             patch('fhir_mcp_server.oauth.server_provider.generate_code_challenge') as mock_challenge:
            
            mock_verifier.return_value = "test_code_verifier"
            mock_challenge.return_value = "test_code_challenge"
            
            verifier = provider._generate_code_verifier()
            challenge = provider._generate_code_challenge(verifier)
            
            assert verifier == "test_code_verifier"
            assert challenge == "test_code_challenge"
            
            mock_verifier.assert_called_once()
            mock_challenge.assert_called_once_with("test_code_verifier")

    @pytest.mark.asyncio
    async def test_client_validation(self):
        """Test client information validation."""
        provider = OAuthServerProvider(self.mock_configs)
        
        # Valid client info
        valid_client = {
            "client_id": "test_client_id",
            "client_secret": "test_client_secret",
            "redirect_uri": "http://localhost:8000/oauth/callback"
        }
        
        # Test that validation passes for valid client
        # This is mostly checking that the method doesn't raise exceptions
        try:
            # Calling a method that would validate client info
            with patch('fhir_mcp_server.oauth.server_provider.discover_oauth_metadata') as mock_discover:
                mock_discover.return_value = {
                    "authorization_endpoint": "https://auth.example.com/oauth/authorize",
                    "code_challenge_methods_supported": ["S256"]
                }
                
                with patch('fhir_mcp_server.oauth.server_provider.generate_code_verifier') as mock_verifier, \
                     patch('fhir_mcp_server.oauth.server_provider.generate_code_challenge') as mock_challenge:
                    
                    mock_verifier.return_value = "test_code_verifier"
                    mock_challenge.return_value = "test_code_challenge"
                    
                    auth_url, state = await provider.get_authorization_url(valid_client)
                    assert auth_url is not None
                    assert state is not None
                    
        except Exception as e:
            pytest.fail(f"Valid client info should not raise exception: {e}")