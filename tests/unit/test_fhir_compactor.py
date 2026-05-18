# Copyright (c) 2026, WSO2 LLC. (https://www.wso2.com/) All Rights Reserved.

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
from datetime import date, datetime
from fhir_mcp_server.compactor.dispatch import compact_resource
from fhir_mcp_server.compactor.types import (
    Address,
    Annotation,
    Attachment,
    CodeableConcept,
    Coding,
    ContactPoint,
    Extension,
    HumanName,
    Identifier,
    Money,
    Period,
    Quantity,
    Range,
    Ratio,
    Reference,
    Timing,
)


class TestCompactCodeableConcept:
    """Test compact_resource with CodeableConcept payloads."""

    def test_uses_text_when_present(self):
        """Test that text field takes precedence over coding."""
        v = {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "8302-2",
                    "display": "Body Height",
                }
            ],
            "text": "Body Height",
        }
        assert compact_resource(v) == "Body Height"

    def test_text_only_no_coding(self):
        """Test that text-only CodeableConcept compacts to the text value."""
        assert (
            compact_resource({"text": "uncoded free text result"})
            == "uncoded free text result"
        )

    def test_uses_display_and_code_when_no_text(self):
        """Test that display and code are combined when text is absent."""
        v = {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "8302-2",
                    "display": "Body Height",
                }
            ]
        }
        assert compact_resource(v) == "Body Height (8302-2)"

    def test_display_only_no_code(self):
        """Test that display alone is used when code is absent."""
        v = {"coding": [{"display": "Body Height"}]}
        assert compact_resource(v) == "Body Height"

    def test_uses_system_and_code_when_no_display(self):
        """Test that system and code are combined when display is absent."""
        v = {"coding": [{"system": "http://loinc.org", "code": "8302-2"}]}
        assert compact_resource(v) == "http://loinc.org|8302-2"

    def test_code_only_no_system_no_display(self):
        """Test that bare code is returned when system and display are absent."""
        v = {"coding": [{"code": "8302-2"}]}
        assert compact_resource(v) == "8302-2"

    def test_empty_coding_returns_raw(self):
        """Test that unresolvable coding returns the raw dict."""
        v = {"coding": [{"userSelected": True}]}
        assert compact_resource(v) == v

    def test_multiple_codings_uses_first(self):
        """Test that only the first coding entry is used."""
        v = {
            "coding": [
                {
                    "system": "http://loinc.org",
                    "code": "8302-2",
                    "display": "Body Height",
                },
                {"system": "https://acme.lab/codes", "code": "HT", "display": "Height"},
            ]
        }
        assert compact_resource(v) == "Body Height (8302-2)"


class TestCompactCoding:
    """Test compact_resource with Coding payloads."""

    def test_uses_display_and_code(self):
        """Test that display and code are combined."""
        v = {"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"}
        assert compact_resource(v) == "Body Height (8302-2)"

    def test_display_only(self):
        """Test that display alone is returned when code is absent."""
        v = {"display": "Body Height"}
        assert compact_resource(v) == "Body Height"

    def test_uses_system_and_code_when_no_display(self):
        """Test that system and code are combined when display is absent."""
        v = {"system": "http://loinc.org", "code": "8302-2"}
        assert compact_resource(v) == "http://loinc.org|8302-2"

    def test_code_only(self):
        """Test that bare code is returned when system and display are absent."""
        v = {"code": "8302-2"}
        assert compact_resource(v) == "8302-2"


class TestCompactQuantity:
    """Test compact_resource with Quantity payloads."""

    def test_value_and_unit(self):
        """Test that value and unit are joined with a space."""
        assert compact_resource({"value": 7.2, "unit": "mmol/L"}) == "7.2 mmol/L"

    def test_with_comparator(self):
        """Test that comparator is prepended to the value."""
        assert (
            compact_resource({"value": 5.0, "comparator": ">=", "unit": "mg/dL"})
            == ">=5 mg/dL"
        )

    def test_integer_value_no_trailing_zeros(self):
        """Test that integer values are rendered without decimal places."""
        assert compact_resource({"value": 150, "unit": "cm"}) == "150 cm"

    def test_value_only_no_unit(self):
        """Test that value alone is returned when unit is absent."""
        assert (
            compact_resource({"value": 42, "system": "http://unitsofmeasure.org"})
            == "42"
        )

    def test_unit_only_no_value(self):
        """Test that unit alone is returned when value is absent."""
        assert compact_resource({"unit": "cm"}) == "cm"


class TestCompactQuantitySubtypes:
    """Test compact_resource with Quantity subtype payloads (Age, Count, Distance, etc.)."""

    def test_age(self):
        """Test Age subtype compaction."""
        assert compact_resource({"value": 30, "unit": "yr"}) == "30 yr"

    def test_count(self):
        """Test Count subtype compaction."""
        assert compact_resource({"value": 3, "unit": "{count}"}) == "3 {count}"

    def test_distance(self):
        """Test Distance subtype compaction."""
        assert compact_resource({"value": 5, "unit": "km"}) == "5 km"

    def test_duration(self):
        """Test Duration subtype compaction."""
        assert compact_resource({"value": 30, "unit": "min"}) == "30 min"

    def test_money_quantity(self):
        """Test MoneyQuantity subtype compaction."""
        assert (
            compact_resource(
                {"value": 100, "unit": "USD", "system": "urn:iso:std:iso:4217"}
            )
            == "100 USD"
        )

    def test_simple_quantity(self):
        """Test SimpleQuantity subtype compaction."""
        assert compact_resource({"value": 5, "unit": "mg"}) == "5 mg"


class TestCompactRange:
    """Test compact_resource with Range payloads."""

    def test_low_and_high(self):
        """Test that low and high bounds are joined with an en-dash."""
        v = {
            "low": {"value": 3.5, "unit": "mmol/L"},
            "high": {"value": 5.5, "unit": "mmol/L"},
        }
        assert compact_resource(v) == "3.5 mmol/L – 5.5 mmol/L"

    def test_only_low(self):
        """Test that only the low bound is returned when high is absent."""
        v = {"low": {"value": 3.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "3.5 mmol/L"

    def test_only_high(self):
        """Test that only the high bound is returned when low is absent."""
        v = {"high": {"value": 5.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "5.5 mmol/L"

    def test_equal_bounds_allowed(self):
        """Test that equal low and high bounds are accepted."""
        r = Range.model_validate({"low": {"value": 5.0}, "high": {"value": 5.0}})
        assert r.low.value == r.high.value


class TestPeriodValidation:
    """Test Period model validation with various date/datetime inputs."""

    def test_date_objects_accepted(self):
        """Test that Python date objects are accepted as period boundaries."""
        p = Period.model_validate({"start": date(2024, 1, 1), "end": date(2024, 6, 1)})
        assert p.start == date(2024, 1, 1)

    def test_equal_start_end_allowed(self):
        """Test that equal start and end dates are accepted."""
        p = Period.model_validate({"start": "2024-01-01", "end": "2024-01-01"})
        assert p.start == p.end

    def test_period_datetime_validation(self):
        """Test that Python datetime objects are accepted as period boundaries."""
        p = Period.model_validate(
            {"start": datetime(2024, 1, 1, 10), "end": datetime(2024, 1, 1, 12)}
        )
        assert p.start == datetime(2024, 1, 1, 10)


class TestCompactRatio:
    """Test compact_resource with Ratio payloads."""

    def test_numerator_and_denominator(self):
        """Test that numerator and denominator are joined with a slash."""
        v = {
            "numerator": {"value": 1, "unit": "mg"},
            "denominator": {"value": 10, "unit": "mL"},
        }
        assert compact_resource(v) == "1 mg/10 mL"

    def test_missing_denominator_returns_raw(self):
        """Test that a missing denominator returns the raw dict."""
        v = {"numerator": {"value": 1, "unit": "mg"}}
        assert compact_resource(v) == v

    def test_missing_numerator_returns_raw(self):
        """Test that a missing numerator returns the raw dict."""
        v = {"denominator": {"value": 10, "unit": "mL"}}
        assert compact_resource(v) == v


class TestCompactPeriod:
    """Test compact_resource with Period payloads."""

    def test_start_and_end(self):
        """Test that start and end are joined with an en-dash."""
        assert (
            compact_resource({"start": "2024-01-01", "end": "2024-06-30"})
            == "2024-01-01 – 2024-06-30"
        )

    def test_only_start(self):
        """Test that a start-only period is prefixed with 'from'."""
        assert compact_resource({"start": "2024-01-01"}) == "from 2024-01-01"

    def test_only_end(self):
        """Test that an end-only period is prefixed with 'until'."""
        assert compact_resource({"end": "2024-06-30"}) == "until 2024-06-30"


class TestCompactHumanName:
    """Test compact_resource with HumanName payloads."""

    def test_full_name_with_prefix(self):
        """Test that prefix, given, and family are joined in order."""
        v = {"use": "official", "family": "Smith", "given": ["John"], "prefix": ["Dr."]}
        assert compact_resource(v) == "Dr. John Smith"

    def test_nickname_appends_use(self):
        """Test that non-official use values are appended in parentheses."""
        v = {"use": "nickname", "given": ["Johnny"]}
        assert compact_resource(v) == "Johnny (nickname)"

    def test_uses_text_when_present(self):
        """Test that the text field takes precedence over structured name parts."""
        v = {"text": "John Smith", "family": "Smith", "given": ["John"]}
        assert compact_resource(v) == "John Smith"

    def test_suffix_appended(self):
        """Test that suffix is appended after the family name."""
        v = {"family": "Smith", "given": ["John"], "suffix": ["Jr."]}
        assert compact_resource(v) == "John Smith Jr."

    def test_official_use_suppressed(self):
        """Test that 'official' use is not appended to the name."""
        v = {"use": "official", "family": "Smith", "given": ["John"]}
        assert compact_resource(v) == "John Smith"

    def test_maiden_use_shown(self):
        """Test that 'maiden' use is appended in parentheses."""
        v = {"use": "maiden", "family": "Jones", "given": ["Jane"]}
        assert compact_resource(v) == "Jane Jones (maiden)"

    def test_usual_use_shown(self):
        """Test that 'usual' use is appended in parentheses."""
        v = {"use": "usual", "family": "Smith", "given": ["Johnny"]}
        assert compact_resource(v) == "Johnny Smith (usual)"

    def test_multiple_names_compacted_as_list(self):
        """Test that a list of HumanName entries is compacted to a list of strings."""
        v = [
            {
                "use": "official",
                "prefix": ["Ms."],
                "family": "Smith",
                "given": ["Jane"],
            },
            {"use": "maiden", "family": "Jones", "given": ["Jane"]},
            {"use": "nickname", "given": ["Jenny"]},
        ]
        assert compact_resource(v) == [
            "Ms. Jane Smith",
            "Jane Jones (maiden)",
            "Jenny (nickname)",
        ]


class TestCompactAddress:
    """Test compact_resource with Address payloads."""

    def test_full_address(self):
        """Test that all address fields are formatted correctly."""
        v = {
            "line": ["123 Main St"],
            "city": "Boston",
            "state": "MA",
            "postalCode": "02101",
            "country": "US",
        }
        assert compact_resource(v) == "123 Main St, Boston MA 02101, US"

    def test_uses_text_when_present(self):
        """Test that the text field takes precedence over structured address parts."""
        # text + city ensures HumanName validation fails (no city field) and Address is reached
        v = {"text": "123 Main St, Boston MA 02101", "city": "Boston"}
        assert compact_resource(v) == "123 Main St, Boston MA 02101"

    def test_district_included_in_location(self):
        """Test that district is included between city and state."""
        v = {
            "city": "Boston",
            "district": "Suffolk",
            "state": "MA",
            "postalCode": "02101",
        }
        assert compact_resource(v) == "Boston Suffolk MA 02101"

    def test_use_and_type_appended(self):
        """Test that use and type are appended in parentheses."""
        v = {"use": "home", "type": "postal", "line": ["123 Main St"], "city": "Boston"}
        assert compact_resource(v) == "123 Main St, Boston (home, postal)"

    def test_use_only(self):
        """Test that use alone is appended in parentheses when type is absent."""
        v = {"use": "work", "city": "Boston"}
        assert compact_resource(v) == "Boston (work)"


class TestCompactContactPoint:
    """Test compact_resource with ContactPoint payloads."""

    def test_phone_with_use(self):
        """Test that system, value, and use are formatted correctly."""
        assert (
            compact_resource({"system": "phone", "value": "555-1234", "use": "home"})
            == "phone: 555-1234 (home)"
        )

    def test_email_without_use(self):
        """Test that system and value are formatted without use when absent."""
        assert (
            compact_resource({"system": "email", "value": "john@example.com"})
            == "email: john@example.com"
        )

    def test_rank_appended(self):
        """Test that rank is appended with a # prefix."""
        v = {"system": "phone", "value": "555-1234", "use": "home", "rank": 1}
        assert compact_resource(v) == "phone: 555-1234 (home) #1"


class TestCompactIdentifier:
    """Test compact_resource with Identifier payloads."""

    def test_system_value_and_use(self):
        """Test that system, value, and use are formatted correctly."""
        v = {"system": "http://hospital.org/mrn", "value": "MRN123", "use": "official"}
        assert compact_resource(v) == "http://hospital.org/mrn|MRN123 [official]"

    def test_not_confused_with_contact_point(self):
        """Test that a URI system is not mistaken for a ContactPoint."""
        v = {"system": "http://hospital.org/mrn", "value": "MRN123"}
        result = compact_resource(v)
        assert "http://hospital.org/mrn" in result

    def test_type_prepended_as_label(self):
        """Test that the type text is prepended as a label."""
        v = {
            "type": {"text": "MRN"},
            "system": "http://hospital.org/mrn",
            "value": "MRN123",
        }
        assert compact_resource(v) == "MRN: http://hospital.org/mrn|MRN123"

    def test_value_only(self):
        """Test that value alone is returned when system is absent."""
        assert compact_resource({"value": "MRN123"}) == "MRN123"

    def test_system_only_returns_entire_json(self):
        """Test that a system-only identifier returns the raw dict."""
        assert (
            compact_resource({"system": "http://hospital.org/mrn"})
            == {"system": "http://hospital.org/mrn"}
        )


class TestCompactAttachment:
    """Test compact_resource with Attachment payloads."""

    def test_title_and_content_type(self):
        """Test that title and contentType are combined."""
        v = {"title": "Discharge Summary", "contentType": "application/pdf"}
        assert compact_resource(v) == "Discharge Summary (application/pdf)"

    def test_title_without_content_type(self):
        """Test that title alone is returned when contentType is absent."""
        v = {"title": "Discharge Summary"}
        assert compact_resource(v) == "Discharge Summary"

    def test_falls_back_to_url(self):
        """Test that URL is used when title is absent."""
        v = {"url": "http://example.com/image.png", "contentType": "image/png"}
        assert compact_resource(v) == "http://example.com/image.png"

    def test_content_type_only(self):
        """Test that contentType alone is returned when title and URL are absent."""
        v = {"contentType": "application/pdf"}
        assert compact_resource(v) == "application/pdf"

    def test_inline_text_data_decoded(self):
        """Test that base64-encoded text data is decoded and returned as a string."""
        import base64

        v = {
            "contentType": "text/plain",
            "data": base64.b64encode(b"hello world").decode(),
        }
        assert compact_resource(v) == "hello world"

    def test_inline_binary_data_as_data_uri(self):
        """Test that base64-encoded binary data is returned as a data URI."""
        import base64

        raw = b"\x89PNG\r\n"
        v = {"contentType": "image/png", "data": base64.b64encode(raw).decode()}
        assert (
            compact_resource(v)
            == f"data:image/png;base64,{base64.b64encode(raw).decode()}"
        )

    def test_hash_bytes_passthrough(self):
        """Test that raw bytes are accepted and stored as-is for hash."""
        raw_hash = b"\xde\xad\xbe\xef"
        a = Attachment.model_validate(
            {"contentType": "application/pdf", "hash": raw_hash}
        )
        assert a.hash == raw_hash

    def test_data_bytes_passthrough(self):
        """Test that raw bytes are accepted and stored as-is for data."""
        raw = b"raw bytes"
        a = Attachment.model_validate({"contentType": "application/pdf", "data": raw})
        assert a.data == raw

    def test_attachment_hash_data_non_string(self):
        """Test that dict values for hash and data are rejected."""
        with pytest.raises(Exception):
            Attachment.model_validate(
                {"contentType": "text/plain", "hash": {"dict": 1}, "data": {"dict": 2}}
            )


class TestCompactAnnotation:
    """Test compact_resource with Annotation payloads."""

    def test_text_only(self):
        """Test that text alone is returned as-is."""
        v = {"text": "Patient was fasting"}
        assert compact_resource(v) == "Patient was fasting"

    def test_text_with_time(self):
        """Test that time is appended in parentheses."""
        v = {"text": "Patient was fasting", "time": "2024-01-01T09:00:00Z"}
        assert compact_resource(v) == "Patient was fasting (2024-01-01T09:00:00Z)"

    def test_text_with_author_string(self):
        """Test that authorString is appended in parentheses."""
        v = {"text": "Patient was fasting", "authorString": "Dr. Smith"}
        assert compact_resource(v) == "Patient was fasting (Dr. Smith)"

    def test_text_with_author_and_time(self):
        """Test that author and time are both appended, comma-separated."""
        v = {
            "text": "Patient was fasting",
            "authorString": "Dr. Smith",
            "time": "2024-01-01",
        }
        assert compact_resource(v) == "Patient was fasting (Dr. Smith, 2024-01-01)"

    def test_author_reference(self):
        """Test that authorReference is resolved to its reference string."""
        v = {
            "text": "I don't think this is true",
            "authorReference": {"reference": "Patient/example"},
            "time": "2022-02-08T10:18:14Z",
        }
        assert (
            compact_resource(v)
            == "I don't think this is true (Patient/example, 2022-02-08T10:18:14Z)"
        )


class TestCompactMoney:
    """Test compact_resource with Money payloads."""

    def test_value_and_currency(self):
        """Test that value and currency are joined with a space."""
        assert compact_resource({"value": 49.99, "currency": "USD"}) == "49.99 USD"

    def test_value_without_currency(self):
        """Test that value alone is returned when currency is absent."""
        assert compact_resource({"value": 49.99, "currency": None}) == "49.99"


class TestCompactResourceList:
    """Test compact_resource list handling and recursive dispatch behavior."""

    def test_compacts_each_item_in_list(self):
        """Test that each item in a list is individually compacted."""
        data = [
            {"coding": [{"code": "M", "display": "Married"}]},
            {"coding": [{"code": "S", "display": "Single"}]},
        ]
        assert compact_resource(data) == ["Married (M)", "Single (S)"]

    def test_leaves_primitives_unchanged(self):
        """Test that primitive values are returned unchanged."""
        assert compact_resource("hello") == "hello"
        assert compact_resource(42) == 42
        assert compact_resource(True) is True

    def test_recurses_into_unrecognized_dict(self):
        """Test that unrecognized dicts are recursed into and their values compacted."""
        data = {
            "resourceType": "Patient",
            "valueQuantity": {"value": 7.2, "unit": "cm"},
        }
        assert compact_resource(data) == {
            "resourceType": "Patient",
            "valueQuantity": "7.2 cm",
        }


class TestCompactExtension:
    """Test compact_resource with Extension payloads (flat and nested)."""

    # us-core-interpreter-needed — flat valueCoding extension
    INTERPRETER_NEEDED = {
        "url": "http://hl7.org/fhir/us/core/StructureDefinition/us-core-interpreter-needed",
        "valueCoding": {
            "system": "http://snomed.info/sct",
            "version": "http://snomed.info/sct/731000124108",
            "code": "373066001",
        },
    }

    # us-core-race — nested extension with repeated ombCategory sub-URLs
    RACE = {
        "url": "http://hl7.org/fhir/us/core/StructureDefinition/us-core-race",
        "extension": [
            {
                "url": "ombCategory",
                "valueCoding": {
                    "system": "urn:oid:2.16.840.1.113883.6.238",
                    "code": "2106-3",
                    "display": "White",
                },
            },
            {
                "url": "ombCategory",
                "valueCoding": {
                    "system": "urn:oid:2.16.840.1.113883.6.238",
                    "code": "1002-5",
                    "display": "American Indian or Alaska Native",
                },
            },
            {
                "url": "ombCategory",
                "valueCoding": {
                    "system": "urn:oid:2.16.840.1.113883.6.238",
                    "code": "2028-9",
                    "display": "Asian",
                },
            },
            {
                "url": "detailed",
                "valueCoding": {
                    "system": "urn:oid:2.16.840.1.113883.6.238",
                    "code": "1586-7",
                    "display": "Shoshone",
                },
            },
            {
                "url": "detailed",
                "valueCoding": {
                    "system": "urn:oid:2.16.840.1.113883.6.238",
                    "code": "2036-2",
                    "display": "Filipino",
                },
            },
            {"url": "text", "valueString": "Mixed"},
        ],
    }

    # us-core-tribal-affiliation — nested with valueCodeableConcept and valueBoolean
    TRIBAL_AFFILIATION = {
        "url": "http://hl7.org/fhir/us/core/StructureDefinition/us-core-tribal-affiliation",
        "extension": [
            {
                "url": "tribalAffiliation",
                "valueCodeableConcept": {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/v3-TribalEntityUS",
                            "code": "187",
                            "display": "Paiute-Shoshone Tribe of the Fallon Reservation and Colony, Nevada",
                        }
                    ],
                    "text": "Shoshone",
                },
            },
            {"url": "isEnrolled", "valueBoolean": False},
        ],
    }

    def test_flat_extension_returns_url_pipe_value(self):
        """Test that a flat extension compacts to url|value."""
        result = compact_resource(self.INTERPRETER_NEEDED)
        assert (
            result
            == "http://hl7.org/fhir/us/core/StructureDefinition/us-core-interpreter-needed|http://snomed.info/sct|373066001"
        )

    def test_nested_extension_returns_dict_keyed_by_sub_url(self):
        """Test that nested extension compacts to a dict keyed by sub-extension URLs."""
        result = compact_resource(self.RACE)
        assert isinstance(result, dict)
        assert (
            result["url"]
            == "http://hl7.org/fhir/us/core/StructureDefinition/us-core-race"
        )
        assert result["text"] == "Mixed"

    def test_repeated_sub_url_becomes_list(self):
        """Test that repeated sub-extension URLs are collected into a list."""
        result = compact_resource(self.RACE)
        assert isinstance(result["ombCategory"], list)
        assert result["ombCategory"] == [
            "White (2106-3)",
            "American Indian or Alaska Native (1002-5)",
            "Asian (2028-9)",
        ]
        assert isinstance(result["detailed"], list)
        assert result["detailed"] == ["Shoshone (1586-7)", "Filipino (2036-2)"]

    def test_nested_extension_with_codeable_concept_and_boolean(self):
        """Test that valueCodeableConcept and valueBoolean are compacted in nested extensions."""
        result = compact_resource(self.TRIBAL_AFFILIATION)
        assert isinstance(result, dict)
        assert (
            result["url"]
            == "http://hl7.org/fhir/us/core/StructureDefinition/us-core-tribal-affiliation"
        )
        assert result["tribalAffiliation"] == "Shoshone"
        assert result["isEnrolled"] == "False"

    def test_unresolvable_nested_extension_returns_raw(self):
        """Test that a nested extension with no sub-extensions returns the raw dict."""
        data = {"url": "http://example.org/ext", "extension": []}
        result = compact_resource(data)
        assert result == data

    def test_sub_extension_value_that_compacts_to_dict_is_dropped(self):
        """Test that sub-extensions whose value cannot be reduced to a string are skipped."""
        # valueX that compact_resource cannot reduce to a string (unrecognized dict)
        # _extract_extension_value returns "" → sub-extension is skipped
        data = {
            "url": "http://example.org/ext",
            "extension": [
                {"url": "known", "valueString": "hello"},
                {"url": "unknown", "valueX": {"foo": "bar", "baz": 1}},
            ],
        }
        result = compact_resource(data)
        assert isinstance(result, dict)
        assert result["known"] == "hello"
        assert "unknown" not in result

    def test_float_value_in_extension(self):
        """Test that float values are compacted to url|value."""
        data = {"url": "http://example.org/ext", "valueDecimal": 3.14}
        assert compact_resource(data) == "http://example.org/ext|3.14"

    def test_int_value_in_extension(self):
        """Test that integer values are compacted to url|value."""
        data = {"url": "http://example.org/ext", "valueInteger": 42}
        assert compact_resource(data) == "http://example.org/ext|42"

    def test_no_value_keys_returns_raw(self):
        """Test that an extension with no value key returns the raw dict."""
        data = {"url": "http://example.org/ext"}
        assert compact_resource(data) == data

    def test_multiple_value_keys_returns_raw(self):
        """Test that an extension with multiple value keys returns the raw dict."""
        data = {"url": "http://example.org/ext", "valueString": "a", "valueInteger": 1}
        assert compact_resource(data) == data

    def test_extract_extension_value_list(self):
        """Test that a list-typed value field returns an empty string."""
        ext = Extension.model_validate({"url": "x", "valueList": [1, 2]})
        assert ext._extract_extension_value() == ""

    def test_compact_extension_nested_not_dict(self):
        """Test that non-dict items in extension list return the raw value."""
        v = {"url": "x", "extension": ["string"]}
        assert compact_resource(v) == v


class TestCompactTiming:
    """Test compact_resource with Timing payloads."""

    def test_code_text_used_verbatim(self):
        """Test that code text is returned as-is."""
        v = {"code": {"text": "Take medication in the morning on weekends"}}
        assert compact_resource(v) == "Take medication in the morning on weekends"

    def test_known_abbreviation_code(self):
        """Test that known timing abbreviation codes are returned as-is."""
        v = {"code": {"coding": [{"code": "BID"}]}}
        assert compact_resource(v) == "BID"

    def test_every_8_hours(self):
        """Test that frequency=1 over 8h period compacts to 'every 8h'."""
        v = {"repeat": {"frequency": 1, "period": 8, "periodUnit": "h"}}
        assert compact_resource(v) == "every 8h"

    def test_3_times_a_day(self):
        """Test that frequency=3 over 1d period compacts to '3x/day'."""
        v = {"repeat": {"frequency": 3, "period": 1, "periodUnit": "d"}}
        assert compact_resource(v) == "3x/day"

    def test_3_to_4_times_a_day(self):
        """Test that frequencyMax produces a range like '3-4x/day'."""
        v = {
            "repeat": {
                "frequency": 3,
                "frequencyMax": 4,
                "period": 1,
                "periodUnit": "d",
            }
        }
        assert compact_resource(v) == "3-4x/day"

    def test_every_4_to_6_hours(self):
        """Test that periodMax produces a range like 'every 4-6h'."""
        v = {"repeat": {"frequency": 1, "period": 4, "periodUnit": "h", "periodMax": 6}}
        assert compact_resource(v) == "every 4-6h"

    def test_every_21_days_for_1_hour(self):
        """Test that duration is appended after the frequency."""
        v = {
            "repeat": {
                "frequency": 1,
                "period": 21,
                "periodUnit": "d",
                "duration": 1,
                "durationUnit": "h",
            }
        }
        assert compact_resource(v) == "every 21d for 1h"

    def test_when_only(self):
        """Test that a when-only repeat expands to the meal/event label."""
        v = {"repeat": {"when": ["CM"]}}
        assert compact_resource(v) == "at breakfast"

    def test_duration_with_offset_and_when(self):
        """Test that duration, offset, and when are all combined."""
        v = {
            "repeat": {
                "duration": 5,
                "durationUnit": "min",
                "when": ["AC"],
                "offset": 10,
            }
        }
        assert (
            compact_resource(v) == "for 5min, 10min before meal"
        )  # AC → "before meal"

    def test_days_of_week_with_when(self):
        """Test that dayOfWeek and when are appended to the frequency."""
        v = {
            "repeat": {
                "frequency": 1,
                "period": 1,
                "periodUnit": "d",
                "dayOfWeek": ["mon", "wed", "fri"],
                "when": ["MORN"],
            }
        }
        assert compact_resource(v) == "1x/day on Mon/Wed/Fri morning"

    def test_time_of_day(self):
        """Test that timeOfDay is appended to the frequency."""
        v = {
            "repeat": {
                "frequency": 1,
                "period": 1,
                "periodUnit": "d",
                "timeOfDay": ["10:00:00"],
            }
        }
        assert compact_resource(v) == "1x/day at 10:00"

    def test_count_only(self):
        """Test that a count-only repeat compacts to 'N time(s)'."""
        v = {"repeat": {"count": 1}}
        assert compact_resource(v) == "1 time"

    def test_event_list(self):
        """Test that explicit event datetimes are joined with commas."""
        v = {"event": ["2012-01-07T09:00:00+10:00", "2012-01-14T09:00:00+10:00"]}
        assert (
            compact_resource(v)
            == "2012-01-07T09:00:00+10:00, 2012-01-14T09:00:00+10:00"
        )

    def test_multiple_times_per_multi_day_period(self):
        """Test that frequency over a multi-day period compacts to 'Nx/Nd'."""
        v = {"repeat": {"frequency": 2, "period": 3, "periodUnit": "d"}}
        assert compact_resource(v) == "2x/3d"

    def test_bounds_duration(self):
        """Test that boundsDuration is appended as 'for N<unit>'."""
        v = {
            "repeat": {
                "frequency": 2,
                "period": 1,
                "periodUnit": "d",
                "boundsDuration": {
                    "value": 10,
                    "unit": "d",
                    "system": "http://unitsofmeasure.org",
                    "code": "d",
                },
            }
        }
        assert compact_resource(v) == "2x/day for 10d"

    def test_bounds_range(self):
        """Test that boundsRange is appended as 'for low – high'."""
        v = {
            "repeat": {
                "frequency": 3,
                "period": 1,
                "periodUnit": "d",
                "boundsRange": {
                    "low": {"value": 3, "unit": "d"},
                    "high": {"value": 5, "unit": "d"},
                },
            }
        }
        assert compact_resource(v) == "3x/day for 3 d – 5 d"

    def test_bounds_period(self):
        """Test that boundsPeriod is appended as the compacted period string."""
        v = {
            "repeat": {
                "frequency": 2,
                "period": 1,
                "periodUnit": "d",
                "boundsPeriod": {"start": "2015-07-01"},
            }
        }
        assert compact_resource(v) == "2x/day from 2015-07-01"

    def test_when_with_frequency_no_duration(self):
        """Test that when label is appended without duration prefix."""
        v = {
            "repeat": {"frequency": 1, "period": 1, "periodUnit": "d", "when": ["MORN"]}
        }
        assert compact_resource(v) == "1x/day morning"

    def test_duration_with_when_no_offset(self):
        """Test that duration and when are combined without offset."""
        v = {"repeat": {"duration": 5, "durationUnit": "min", "when": ["AC"]}}
        assert compact_resource(v) == "for 5min before meal"

    def test_offset_with_when_no_duration(self):
        """Test that offset and when are combined without duration."""
        v = {"repeat": {"offset": 10, "when": ["AC"]}}
        assert compact_resource(v) == "10min before meal"

    def test_empty_timing_returns_raw(self):
        """Test that an empty Timing dict returns the raw dict."""
        v = {}
        assert compact_resource(v) == v


class TestRealWorldPayloads:
    """Test compact_resource against official FHIR example payloads."""

    def test_us_core_blood_pressure(self):
        """Test compaction of the US Core Blood Pressure Observation example."""
        # The exact US Core Blood Pressure JSON payload
        payload = {
            "resourceType": "Observation",
            "id": "blood-pressure",
            "meta": {
                "profile": [
                    "http://hl7.org/fhir/us/core/StructureDefinition/us-core-blood-pressure|9.0.0"
                ]
            },
            "text": {
                "status": "generated",
                "div": '<div xmlns="http://www.w3.org/1999/xhtml"><p class="res-header-id"><b>Generated Narrative: Observation blood-pressure</b></p><a name="blood-pressure"> </a><a name="hcblood-pressure"> </a><div style="display: inline-block; background-color: #d9e0e7; padding: 6px; margin: 4px; border: 1px solid #8da1b4; border-radius: 5px; line-height: 60%"><p style="margin-bottom: 0px"/><p style="margin-bottom: 0px">Profile: <a href="StructureDefinition-us-core-blood-pressure.html">US Core Blood Pressure Profile</a> version: 9.0.0</p></div><p><b>status</b>: Final</p><p><b>category</b>: <span title="Codes:{http://terminology.hl7.org/CodeSystem/observation-category vital-signs}">Vital Signs</span></p><p><b>code</b>: <span title="Codes:{http://loinc.org 85354-9}">Blood pressure systolic and diastolic</span></p><p><b>subject</b>: <a href="Patient-example.html">Amy Shaw</a></p><p><b>encounter</b>: GP Visit</p><p><b>effective</b>: 1999-07-02</p><p><b>performer</b>: <a href="Practitioner-practitioner-1.html">Dr Ronald Bone</a></p><blockquote><p><b>component</b></p><p><b>code</b>: <span title="Codes:{http://loinc.org 8480-6}">Systolic blood pressure</span></p><p><b>value</b>: 109 mmHg<span style="background: LightGoldenRodYellow"> (Details: UCUM  codemm[Hg] = \'mm[Hg]\')</span></p></blockquote><blockquote><p><b>component</b></p><p><b>code</b>: <span title="Codes:{http://loinc.org 8462-4}">Diastolic blood pressure</span></p><p><b>value</b>: 44 mmHg<span style="background: LightGoldenRodYellow"> (Details: UCUM  codemm[Hg] = \'mm[Hg]\')</span></p></blockquote></div>',
            },
            "status": "final",
            "category": [
                {
                    "coding": [
                        {
                            "system": "http://terminology.hl7.org/CodeSystem/observation-category",
                            "code": "vital-signs",
                            "display": "Vital Signs",
                        }
                    ],
                    "text": "Vital Signs",
                }
            ],
            "code": {
                "coding": [
                    {
                        "system": "http://loinc.org",
                        "code": "85354-9",
                        "display": "Blood pressure panel with all children optional",
                    }
                ],
                "text": "Blood pressure systolic and diastolic",
            },
            "subject": {"reference": "Patient/example", "display": "Amy Shaw"},
            "encounter": {"display": "GP Visit"},
            "effectiveDateTime": "1999-07-02",
            "performer": [
                {
                    "reference": "Practitioner/practitioner-1",
                    "display": "Dr Ronald Bone",
                }
            ],
            "component": [
                {
                    "code": {
                        "coding": [
                            {
                                "system": "http://loinc.org",
                                "code": "8480-6",
                                "display": "Systolic blood pressure",
                            }
                        ],
                        "text": "Systolic blood pressure",
                    },
                    "valueQuantity": {
                        "value": 109,
                        "unit": "mmHg",
                        "system": "http://unitsofmeasure.org",
                        "code": "mm[Hg]",
                    },
                },
                {
                    "code": {
                        "coding": [
                            {
                                "system": "http://loinc.org",
                                "code": "8462-4",
                                "display": "Diastolic blood pressure",
                            }
                        ],
                        "text": "Diastolic blood pressure",
                    },
                    "valueQuantity": {
                        "value": 44,
                        "unit": "mmHg",
                        "system": "http://unitsofmeasure.org",
                        "code": "mm[Hg]",
                    },
                },
            ],
        }

        result = compact_resource(payload)

        assert result["resourceType"] == "Observation"
        assert result["code"] == "Blood pressure systolic and diastolic"
        assert result["category"] == ["Vital Signs"]

        # Components should be cleanly flattened
        assert len(result["component"]) == 2

        assert result["component"][0]["code"] == "Systolic blood pressure"
        assert result["component"][0]["valueQuantity"] == "109 mmHg"

        assert result["component"][1]["code"] == "Diastolic blood pressure"
        assert result["component"][1]["valueQuantity"] == "44 mmHg"
