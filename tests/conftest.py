import pytest
from unittest.mock import Mock, patch

@pytest.fixture(autouse=True, scope="session")
def patch_webbrowser_open():
    with patch('webbrowser.open_new_tab', new=Mock()):
        yield
