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
import json
from unittest.mock import AsyncMock, Mock, patch
from typing import Dict, Any

from fhir_mcp_server.utils import (
    create_async_fhir_client,
    get_bundle_entries,
    trim_resource_capabilities,
    get_operation_outcome_exception,
    get_operation_outcome_required_error,
    get_operation_outcome,
    get_capability_statement,
    get_default_headers,
    filter_resource_fields,
    format_response,
)
from fhir_mcp_server.oauth.types import ServerConfigs
import fhir_mcp_server.utils as utils_module


class TestCreateAsyncFhirClient:
    """Test the create_async_fhir_client function."""

    @pytest.mark.asyncio
    async def test_create_client_basic_config(self):
        """Test creating FHIR client with basic configuration."""
        config = ServerConfigs(server_base_url="https://example.fhir.org/R4")
        
        with patch('fhir_mcp_server.utils.AsyncFHIRClient') as mock_client:
            # Create the client
            await create_async_fhir_client(config)
            
            # Verify AsyncFHIRClient was called with correct parameters
            mock_client.assert_called_once()
            call_args = mock_client.call_args[1]
            
            assert call_args["url"] == "https://example.fhir.org/R4"
            assert "aiohttp_config" in call_args
            assert "timeout" in call_args["aiohttp_config"]
            assert call_args["extra_headers"] is None
            assert "authorization" not in call_args

    @pytest.mark.asyncio
    async def test_create_client_with_access_token(self):
        """Test creating FHIR client with access token."""
        config = ServerConfigs(server_base_url="https://example.fhir.org/R4")
        access_token = "test_token_123"
        
        with patch('fhir_mcp_server.utils.AsyncFHIRClient') as mock_client:
            await create_async_fhir_client(config, access_token=access_token)
            
            call_args = mock_client.call_args[1]
            assert call_args["authorization"] == "Bearer test_token_123"

    @pytest.mark.asyncio
    async def test_create_client_with_extra_headers(self):
        """Test creating FHIR client with extra headers."""
        config = ServerConfigs(server_base_url="https://example.fhir.org/R4")
        extra_headers = {"X-Custom": "value", "User-Agent": "test"}
        
        with patch('fhir_mcp_server.utils.AsyncFHIRClient') as mock_client:
            await create_async_fhir_client(config, extra_headers=extra_headers)
            
            call_args = mock_client.call_args[1]
            assert call_args["extra_headers"] == extra_headers

    @pytest.mark.asyncio
    async def test_create_client_with_custom_timeout(self):
        """Test creating FHIR client with custom timeout."""
        config = ServerConfigs(server_base_url="https://example.fhir.org/R4", mcp_request_timeout=60)
        
        with patch('fhir_mcp_server.utils.AsyncFHIRClient') as mock_client, \
             patch('fhir_mcp_server.utils.aiohttp.ClientTimeout') as mock_timeout:
            
            await create_async_fhir_client(config)
            
            # Verify timeout was set correctly
            mock_timeout.assert_called_once_with(total=60)


class TestGetBundleEntries:
    """Test the get_bundle_entries function."""

    @pytest.mark.asyncio
    async def test_get_bundle_entries_with_valid_entries(self):
        """Test extracting entries from a valid bundle."""
        bundle = {
            "resourceType": "Bundle",
            "entry": [
                {"resource": {"resourceType": "Patient", "id": "1"}},
                {"resource": {"resourceType": "Patient", "id": "2"}},
                {"fullUrl": "http://example.com/Patient/3"}  # No resource
            ]
        }
        
        result = await get_bundle_entries(bundle)
        
        assert "entry" in result
        assert len(result["entry"]) == 2
        assert result["entry"][0] == {"resourceType": "Patient", "id": "1"}
        assert result["entry"][1] == {"resourceType": "Patient", "id": "2"}

    @pytest.mark.asyncio
    async def test_get_bundle_entries_empty_bundle(self):
        """Test handling bundle with no entries."""
        bundle = {"resourceType": "Bundle"}
        
        result = await get_bundle_entries(bundle)
        
        assert result == bundle

    @pytest.mark.asyncio
    async def test_get_bundle_entries_empty_entry_list(self):
        """Test handling bundle with empty entry list."""
        bundle = {"resourceType": "Bundle", "entry": []}
        
        result = await get_bundle_entries(bundle)
        
        assert "entry" in result
        assert result["entry"] == []

    @pytest.mark.asyncio
    async def test_get_bundle_entries_non_list_entry(self):
        """Test handling bundle with non-list entry."""
        bundle = {"resourceType": "Bundle", "entry": "not-a-list"}
        
        result = await get_bundle_entries(bundle)
        
        assert result == bundle


class TestTrimResource:
    """Test the trim_resource function."""

    def test_trim_resource_basic(self):
        """Test trimming operations with name and documentation."""
        operations = [
            {"name": "read", "documentation": "Read operation"},
            {"name": "search", "documentation": "Search operation"},
            {"name": "create"}  # No documentation
        ]
        
        result = trim_resource_capabilities(operations)
        
        assert len(result) == 3
        assert result[0] == {"name": "read", "documentation": "Read operation"}
        assert result[1] == {"name": "search", "documentation": "Search operation"}
        assert result[2] == {"name": "create", "documentation": None}

    def test_trim_resource_empty_list(self):
        """Test trimming empty operations list."""
        result = trim_resource_capabilities([])
        assert result == []

    def test_trim_resource_with_extra_fields(self):
        """Test trimming operations with extra fields."""
        operations = [
            {
                "name": "read", 
                "documentation": "Read operation",
                "code": "read",
                "system": "http://hl7.org/fhir/restful-interaction"
            }
        ]
        
        result = trim_resource_capabilities(operations)
        
        assert len(result) == 1
        assert result[0] == {"name": "read", "documentation": "Read operation"}

    def test_trim_resource_missing_required_fields(self):
        """Test trimming operations missing name and documentation."""
        operations = [
            {"code": "read"},  # No name or documentation
            {"name": "search"},  # Has name
            {"documentation": "Create operation"}  # Has documentation
        ]
        
        result = trim_resource_capabilities(operations)
        
        assert len(result) == 2
        assert result[0] == {"name": "search", "documentation": None}
        assert result[1] == {"name": None, "documentation": "Create operation"}


class TestOperationOutcomeGenerators:
    """Test operation outcome generation functions."""

    @pytest.mark.asyncio
    async def test_get_operation_outcome_error(self):
        """Test basic operation outcome error generation."""
        result = await get_operation_outcome("not-found", "Resource not found")
        
        expected = {
            "resourceType": "OperationOutcome",
            "issue": [{
                "severity": "error",
                "code": "not-found",
                "diagnostics": "Resource not found"
            }]
        }
        
        assert result == expected

    @pytest.mark.asyncio
    async def test_get_operation_outcome_exception(self):
        """Test exception operation outcome generation."""
        result = await get_operation_outcome_exception()
        
        assert result["resourceType"] == "OperationOutcome"
        assert len(result["issue"]) == 1
        assert result["issue"][0]["code"] == "exception"
        assert "internal error" in result["issue"][0]["diagnostics"]

    @pytest.mark.asyncio
    async def test_get_operation_outcome_required_error(self):
        """Test required field operation outcome generation."""
        result = await get_operation_outcome_required_error("patient.name")
        
        assert result["resourceType"] == "OperationOutcome"
        assert len(result["issue"]) == 1
        assert result["issue"][0]["code"] == "required"
        assert "patient.name" in result["issue"][0]["diagnostics"]

    @pytest.mark.asyncio
    async def test_get_operation_outcome_required_error_no_element(self):
        """Test required field operation outcome without element name."""
        result = await get_operation_outcome_required_error()
        
        assert result["resourceType"] == "OperationOutcome"
        assert result["issue"][0]["code"] == "required"
        assert "is missing" in result["issue"][0]["diagnostics"]


class TestGetCapabilityStatement:
    """Test the get_capability_statement function."""

    @pytest.mark.asyncio
    async def test_get_capability_statement_success(self):
        """Test successful capability statement retrieval."""
        metadata_url = "https://example.fhir.org/R4/metadata"
        expected_metadata = {
            "resourceType": "CapabilityStatement",
            "status": "active",
            "fhirVersion": "4.0.1"
        }
        
        with patch('fhir_mcp_server.utils.create_mcp_http_client') as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.return_value = expected_metadata
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client
            
            result = await get_capability_statement(metadata_url)
            
            assert result == expected_metadata
            mock_client.get.assert_called_once_with(
                url=metadata_url, 
                headers=get_default_headers()
            )
            mock_response.raise_for_status.assert_called_once()

    @pytest.mark.asyncio
    async def test_get_capability_statement_http_error(self):
        """Test capability statement retrieval with HTTP error."""
        metadata_url = "https://example.fhir.org/R4/metadata"
        
        with patch('fhir_mcp_server.utils.create_mcp_http_client') as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.raise_for_status.side_effect = Exception("HTTP 404")
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client
            
            with pytest.raises(ValueError, match="Unable to fetch FHIR metadata"):
                await get_capability_statement(metadata_url)

    @pytest.mark.asyncio
    async def test_get_capability_statement_json_error(self):
        """Test capability statement retrieval with JSON decode error."""
        metadata_url = "https://example.fhir.org/R4/metadata"
        
        with patch('fhir_mcp_server.utils.create_mcp_http_client') as mock_client_context:
            mock_client = AsyncMock()
            mock_response = Mock()
            mock_response.json.side_effect = json.JSONDecodeError("Invalid JSON", "", 0)
            mock_client.get.return_value = mock_response
            mock_client_context.return_value.__aenter__.return_value = mock_client
            
            with pytest.raises(ValueError, match="Unable to fetch FHIR metadata"):
                await get_capability_statement(metadata_url)


class TestGetDefaultHeaders:
    """Test the get_default_headers function."""

    def test_get_default_headers(self):
        """Test default headers generation."""
        headers = get_default_headers()
        
        expected_headers = {
            "Accept": "application/fhir+json",
            "Content-Type": "application/fhir+json"
        }
        
        assert headers == expected_headers

    def test_get_default_headers_immutable(self):
        """Test that default headers are not shared between calls."""
        headers1 = get_default_headers()
        headers2 = get_default_headers()
        
        # Modify one set of headers
        headers1["X-Custom"] = "value"
        
        # Ensure the other set is not affected
        assert "X-Custom" not in headers2
        assert headers2 == {
            "Accept": "application/fhir+json",
            "Content-Type": "application/fhir+json"
        }


class TestFilterByFhirpath:
    """Test the filter_by_fhirpath function."""

    PATIENT = {
        "resourceType": "Patient",
        "id": "p1",
        "name": [{"family": "Smith"}],
        "gender": "male",
        "birthDate": "1990-01-01",
    }

    OBSERVATION = {
        "resourceType": "Observation",
        "id": "o1",
        "status": "final",
        "valueQuantity": {"value": 7.2, "unit": "mmol/L"},
    }

    def test_non_dict_returns_unchanged(self):
        """Test that non-dict input is returned unchanged."""
        assert filter_resource_fields("raw string", ["Patient.name"]) == "raw string"

    def test_single_resource_matched_expression(self):
        """Test filtering a single resource with a matching FHIRPath expression."""
        result = filter_resource_fields(self.PATIENT, ["Patient.name"])
        assert result["resourceType"] == "Patient"
        assert result["id"] == "p1"
        assert "name" in result

    def test_expression_for_different_resource_type_skipped(self):
        """Test that expressions prefixed for a different resource type are not evaluated."""
        result = filter_resource_fields(self.PATIENT, ["Observation.valueQuantity"])
        assert "Observation.valueQuantity" not in result
        assert "_unmatched" not in result

    def test_unprefixed_expression_applied_to_any_resource(self):
        """Test that unprefixed expressions are applied regardless of resource type."""
        result = filter_resource_fields(self.PATIENT, ["gender"])
        assert "gender" in result

    def test_unmatched_expression_recorded(self):
        """Test that expressions that yield no results are recorded in _unmatched."""
        result = filter_resource_fields(self.PATIENT, ["Patient.deceased"])
        assert "deceased" not in result
        assert "_unmatched" in result
        assert "Patient.deceased" in result["_unmatched"]

    def test_empty_string_expression_skipped(self):
        """Test that empty string expressions are skipped without raising errors."""
        result = filter_resource_fields(self.PATIENT, [""])
        assert "_errors" not in result

    def test_bundle_entries_filtered(self):
        """Test that FHIRPath expressions are applied to each entry in a Bundle."""
        bundle = {
            "resourceType": "Bundle",
            "id": "b1",
            "entry": [
                {"resource": self.PATIENT},
                {"resource": self.OBSERVATION},
            ],
        }
        result = filter_resource_fields(bundle, ["Patient.name"])
        assert len(result["entry"]) == 2
        patient_entry = result["entry"][0]
        assert "name" in patient_entry
        obs_entry = result["entry"][1]
        assert "name" not in obs_entry

    def test_bundle_entry_wrapper_preserves_search(self):
        """Test that search metadata is preserved when filtering a raw bundle entry wrapper."""
        entry = {
            "fullUrl": "http://example.com/Patient/p1",
            "resource": self.PATIENT,
            "search": {"mode": "match"},
        }
        result = filter_resource_fields(entry, ["Patient.name"])
        assert result["search"] == {"mode": "match"}
        assert "name" in result

    def test_bundle_entry_wrapper_drops_full_url(self):
        """fullUrl is intentionally dropped when filtering a raw bundle entry wrapper."""
        entry = {
            "fullUrl": "http://example.com/Patient/p1",
            "resource": self.PATIENT,
        }
        result = filter_resource_fields(entry, ["Patient.name"])
        assert "fullUrl" not in result

    def test_depth_limit_returns_data_unchanged(self):
        """Test that recursion beyond the depth limit returns data unchanged."""
        result = filter_resource_fields(self.PATIENT, ["Patient.name"], _depth=11)
        assert result is self.PATIENT

    def test_invalid_expression_recorded_in_errors(self):
        """Test that syntactically invalid FHIRPath expressions are recorded in _errors."""
        result = filter_resource_fields(self.PATIENT, ["!!!invalid"])
        assert "_errors" in result
        assert "!!!invalid" in result["_errors"]

    def test_bundle_mixed_resource_types_filtered_correctly(self):
        """Test that each Bundle entry is only filtered by expressions matching its resource type."""
        bundle = {
            "resourceType": "Bundle",
            "entry": [
                {"resource": self.PATIENT},
                {"resource": self.OBSERVATION},
            ],
        }
        result = filter_resource_fields(bundle, ["Patient.name", "Observation.valueQuantity"])
        patient_entry = result["entry"][0]
        obs_entry = result["entry"][1]
        assert "name" in patient_entry
        assert "valueQuantity" not in patient_entry
        assert "valueQuantity" in obs_entry
        assert "name" not in obs_entry

    def test_bundle_unprefixed_expression_does_not_pollute_wrapper(self):
        """Unprefixed expressions should filter entry resources but not add _unmatched to the Bundle wrapper."""
        bundle = {
            "resourceType": "Bundle",
            "type": "searchset",
            "total": 2,
            "entry": [
                {"resource": {"resourceType": "Patient", "id": "1", "name": [{"family": "Smith"}]}},
                {"resource": {"resourceType": "Patient", "id": "2", "name": [{"family": "Jones"}]}},
            ],
        }
        result = filter_resource_fields(bundle, ["name"])
        assert "_unmatched" not in result, f"Bundle wrapper should not have _unmatched: {result.get('_unmatched')}"


class TestFilterMetadataStripping:
    """Test of filter_resource_fields: no expressions, json_output=False strips meta/text."""

    def setup_method(self):
        self._original_json_output = utils_module.configs.json_output
        utils_module.configs.json_output = False

    def teardown_method(self):
        utils_module.configs.json_output = self._original_json_output

    PATIENT_WITH_META = {
        "resourceType": "Patient",
        "id": "p1",
        "gender": "male",
        "meta": {"versionId": "1", "lastUpdated": "2024-01-01"},
        "text": {"status": "generated", "div": "<div>...</div>"},
        "name": [{"family": "Smith"}],
    }

    def test_meta_stripped_from_resource(self):
        result = filter_resource_fields(self.PATIENT_WITH_META, [])
        assert "meta" not in result
        assert "gender" in result

    def test_text_stripped_from_resource(self):
        result = filter_resource_fields(self.PATIENT_WITH_META, [])
        assert "text" not in result
        assert "name" in result

    def test_other_fields_preserved(self):
        result = filter_resource_fields(self.PATIENT_WITH_META, [])
        assert result["id"] == "p1"
        assert result["gender"] == "male"

    def test_nested_data_type_left_untouched(self):
        # A CodeableConcept has no resourceType — should be returned as-is
        coding = {"system": "http://snomed.info/sct", "code": "73211009", "meta": "should-stay"}
        result = filter_resource_fields(coding, [])
        assert result is coding

    def test_primitive_returned_unchanged(self):
        assert filter_resource_fields("raw-string", []) == "raw-string"
        assert filter_resource_fields(42, []) == 42

    def test_meta_stripped_from_bundle_entries(self):
        bundle = {
            "resourceType": "Bundle",
            "meta": {"tag": [{"code": "SUBSETTED"}]},
            "entry": [
                {"resource": {**self.PATIENT_WITH_META}},
            ],
        }
        result = filter_resource_fields(bundle, [])
        assert "meta" not in result, "meta should be stripped from Bundle"
        resource = result["entry"][0]["resource"]
        assert "meta" not in resource, "meta should be stripped from entry resource"
        assert "text" not in resource, "text should be stripped from entry resource"
        assert resource["id"] == "p1"

    def test_bundle_entry_without_resource_left_untouched(self):
        bundle = {
            "resourceType": "Bundle",
            "entry": [{"fullUrl": "http://example.com/Patient/p1"}],
        }
        result = filter_resource_fields(bundle, [])
        assert result["entry"][0] == {"fullUrl": "http://example.com/Patient/p1"}


class TestFormatResponse:
    """Test the format_response function."""

    PATIENT = {"resourceType": "Patient", "id": "p1"}

    def test_json_output_no_fields_returns_data_unchanged(self):
        utils_module.configs.json_output = True
        try:
            assert format_response(self.PATIENT) is self.PATIENT
        finally:
            utils_module.configs.json_output = False

    def test_json_output_with_fields_filters_data(self):
        patient = {**self.PATIENT, "meta": {"versionId": "1"}, "gender": "male"}
        utils_module.configs.json_output = True
        try:
            result = format_response(patient, ["Patient.gender"])
            assert "gender" in result
            assert "meta" not in result
        finally:
            utils_module.configs.json_output = False

    def test_toon_output_returns_string(self):
        """Test that json_output=False returns a non-empty string."""
        utils_module.configs.json_output = False
        result = format_response(self.PATIENT)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_toon_output_is_not_json(self):
        """Test that toon output is not valid JSON."""
        import json
        utils_module.configs.json_output = False
        result = format_response(self.PATIENT)
        with pytest.raises(Exception):
            json.loads(result)
