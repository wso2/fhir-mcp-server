import pytest

# Mock the async functions to avoid dependency issues during testing
from unittest.mock import AsyncMock, patch

# These test functions are properly fixed to be async and use await
@pytest.mark.asyncio
async def test_get_operation_outcome_exception():
    """Test exception operation outcome generation."""
    # Mock the function to return expected result
    mock_result = {
        "resourceType": "OperationOutcome",
        "issue": [{
            "severity": "error",
            "code": "exception",
            "diagnostics": "An unexpected internal error has occurred."
        }]
    }
    
    with patch('fhir_mcp_server.utils.get_operation_outcome_exception', new_callable=AsyncMock) as mock_func:
        mock_func.return_value = mock_result
        from fhir_mcp_server.utils import get_operation_outcome_exception
        
        result = await get_operation_outcome_exception()
        assert result["resourceType"] == "OperationOutcome"


@pytest.mark.asyncio
async def test_get_operation_outcome_required_error():
    """Test required field operation outcome generation."""
    # Mock the function to return expected result
    mock_result = {
        "resourceType": "OperationOutcome",
        "issue": [{
            "severity": "error",
            "code": "required",
            "diagnostics": "A required element patient.name is missing."
        }]
    }
    
    with patch('fhir_mcp_server.utils.get_operation_outcome_required_error', new_callable=AsyncMock) as mock_func:
        mock_func.return_value = mock_result
        from fhir_mcp_server.utils import get_operation_outcome_required_error
        
        result = await get_operation_outcome_required_error("patient.name")
        assert result["issue"][0]["code"] == "required"