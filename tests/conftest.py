import pytest
from unittest.mock import Mock, patch

@pytest.fixture(autouse=True, scope="session")
def patch_webbrowser_open():
    with patch('fhir_mcp_server.oauth.client_provider.webbrowser.open_new_tab', new=Mock()), \
         patch('webbrowser.open_new_tab', new=Mock()):
        yield
