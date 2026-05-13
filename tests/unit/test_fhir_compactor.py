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
from fhir_mcp_server.compactor.dispatch import compact_resource


class TestCompactCodeableConcept:
    def test_uses_text_when_present(self):
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
        assert (
            compact_resource({"text": "uncoded free text result"})
            == "uncoded free text result"
        )

    def test_uses_display_and_code_when_no_text(self):
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
        v = {"coding": [{"display": "Body Height"}]}
        assert compact_resource(v) == "Body Height"

    def test_uses_system_and_code_when_no_display(self):
        v = {"coding": [{"system": "http://loinc.org", "code": "8302-2"}]}
        assert compact_resource(v) == "http://loinc.org|8302-2"

    def test_code_only_no_system_no_display(self):
        v = {"coding": [{"code": "8302-2"}]}
        assert compact_resource(v) == "8302-2"

    def test_empty_coding_returns_raw(self):
        v = {"coding": [{"userSelected": True}]}
        assert compact_resource(v) == v

    def test_multiple_codings_uses_first(self):
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
    def test_uses_display_and_code(self):
        v = {"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"}
        assert compact_resource(v) == "Body Height (8302-2)"

    def test_display_only(self):
        v = {"display": "Body Height"}
        assert compact_resource(v) == "Body Height"

    def test_uses_system_and_code_when_no_display(self):
        v = {"system": "http://loinc.org", "code": "8302-2"}
        assert compact_resource(v) == "http://loinc.org|8302-2"

    def test_code_only(self):
        v = {"code": "8302-2"}
        assert compact_resource(v) == "8302-2"


class TestCompactQuantity:
    def test_value_and_unit(self):
        assert compact_resource({"value": 7.2, "unit": "mmol/L"}) == "7.2 mmol/L"

    def test_with_comparator(self):
        assert (
            compact_resource({"value": 5.0, "comparator": ">=", "unit": "mg/dL"})
            == ">=5 mg/dL"
        )

    def test_integer_value_no_trailing_zeros(self):
        assert compact_resource({"value": 150, "unit": "cm"}) == "150 cm"

    def test_value_only_no_unit(self):
        assert (
            compact_resource({"value": 42, "system": "http://unitsofmeasure.org"})
            == "42"
        )

    def test_unit_only_no_value(self):
        assert compact_resource({"unit": "cm"}) == "cm"


class TestCompactQuantitySubtypes:
    def test_age(self):
        assert compact_resource({"value": 30, "unit": "yr"}) == "30 yr"

    def test_count(self):
        assert compact_resource({"value": 3, "unit": "{count}"}) == "3 {count}"

    def test_distance(self):
        assert compact_resource({"value": 5, "unit": "km"}) == "5 km"

    def test_duration(self):
        assert compact_resource({"value": 30, "unit": "min"}) == "30 min"

    def test_money_quantity(self):
        assert (
            compact_resource(
                {"value": 100, "unit": "USD", "system": "urn:iso:std:iso:4217"}
            )
            == "100 USD"
        )

    def test_simple_quantity(self):
        assert compact_resource({"value": 5, "unit": "mg"}) == "5 mg"


class TestCompactRange:
    def test_low_and_high(self):
        v = {
            "low": {"value": 3.5, "unit": "mmol/L"},
            "high": {"value": 5.5, "unit": "mmol/L"},
        }
        assert compact_resource(v) == "3.5 mmol/L – 5.5 mmol/L"

    def test_only_low(self):
        v = {"low": {"value": 3.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "3.5 mmol/L"

    def test_only_high(self):
        v = {"high": {"value": 5.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "5.5 mmol/L"

    def test_equal_bounds_allowed(self):
        from fhir_mcp_server.compactor.types.complex_types.range import Range

        r = Range.model_validate({"low": {"value": 5.0}, "high": {"value": 5.0}})
        assert r.low.value == r.high.value


class TestPeriodValidation:
    def test_date_objects_accepted(self):
        from datetime import date
        from fhir_mcp_server.compactor.types.complex_types.period import Period

        p = Period.model_validate({"start": date(2024, 1, 1), "end": date(2024, 6, 1)})
        assert p.start == date(2024, 1, 1)

    def test_equal_start_end_allowed(self):
        from fhir_mcp_server.compactor.types.complex_types.period import Period

        p = Period.model_validate({"start": "2024-01-01", "end": "2024-01-01"})
        assert p.start == p.end

    def test_period_datetime_validation(self):
        from fhir_mcp_server.compactor.types.complex_types.period import Period
        from datetime import datetime

        p = Period.model_validate(
            {"start": datetime(2024, 1, 1, 10), "end": datetime(2024, 1, 1, 12)}
        )
        assert p.start == datetime(2024, 1, 1, 10)


class TestCompactRatio:
    def test_numerator_and_denominator(self):
        v = {
            "numerator": {"value": 1, "unit": "mg"},
            "denominator": {"value": 10, "unit": "mL"},
        }
        assert compact_resource(v) == "1 mg/10 mL"

    def test_missing_denominator_returns_raw(self):
        v = {"numerator": {"value": 1, "unit": "mg"}}
        assert compact_resource(v) == v

    def test_missing_numerator_returns_raw(self):
        v = {"denominator": {"value": 10, "unit": "mL"}}
        assert compact_resource(v) == v


class TestCompactPeriod:
    def test_start_and_end(self):
        assert (
            compact_resource({"start": "2024-01-01", "end": "2024-06-30"})
            == "2024-01-01 – 2024-06-30"
        )

    def test_only_start(self):
        assert compact_resource({"start": "2024-01-01"}) == "from 2024-01-01"

    def test_only_end(self):
        assert compact_resource({"end": "2024-06-30"}) == "until 2024-06-30"


class TestCompactHumanName:
    def test_full_name_with_prefix(self):
        v = {"use": "official", "family": "Smith", "given": ["John"], "prefix": ["Dr."]}
        assert compact_resource(v) == "Dr. John Smith"

    def test_nickname_appends_use(self):
        v = {"use": "nickname", "given": ["Johnny"]}
        assert compact_resource(v) == "Johnny (nickname)"

    def test_uses_text_when_present(self):
        v = {"text": "John Smith", "family": "Smith", "given": ["John"]}
        assert compact_resource(v) == "John Smith"

    def test_suffix_appended(self):
        v = {"family": "Smith", "given": ["John"], "suffix": ["Jr."]}
        assert compact_resource(v) == "John Smith Jr."

    def test_official_use_suppressed(self):
        v = {"use": "official", "family": "Smith", "given": ["John"]}
        assert compact_resource(v) == "John Smith"

    def test_maiden_use_shown(self):
        v = {"use": "maiden", "family": "Jones", "given": ["Jane"]}
        assert compact_resource(v) == "Jane Jones (maiden)"

    def test_usual_use_shown(self):
        v = {"use": "usual", "family": "Smith", "given": ["Johnny"]}
        assert compact_resource(v) == "Johnny Smith (usual)"

    def test_multiple_names_compacted_as_list(self):
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
    def test_full_address(self):
        v = {
            "line": ["123 Main St"],
            "city": "Boston",
            "state": "MA",
            "postalCode": "02101",
            "country": "US",
        }
        assert compact_resource(v) == "123 Main St, Boston MA 02101, US"

    def test_uses_text_when_present(self):
        # text + city ensures HumanName validation fails (no city field) and Address is reached
        v = {"text": "123 Main St, Boston MA 02101", "city": "Boston"}
        assert compact_resource(v) == "123 Main St, Boston MA 02101"

    def test_district_included_in_location(self):
        v = {
            "city": "Boston",
            "district": "Suffolk",
            "state": "MA",
            "postalCode": "02101",
        }
        assert compact_resource(v) == "Boston Suffolk MA 02101"

    def test_use_and_type_appended(self):
        v = {"use": "home", "type": "postal", "line": ["123 Main St"], "city": "Boston"}
        assert compact_resource(v) == "123 Main St, Boston (home, postal)"

    def test_use_only(self):
        v = {"use": "work", "city": "Boston"}
        assert compact_resource(v) == "Boston (work)"


class TestCompactContactPoint:
    def test_phone_with_use(self):
        assert (
            compact_resource({"system": "phone", "value": "555-1234", "use": "home"})
            == "phone: 555-1234 (home)"
        )

    def test_email_without_use(self):
        assert (
            compact_resource({"system": "email", "value": "john@example.com"})
            == "email: john@example.com"
        )

    def test_rank_appended(self):
        v = {"system": "phone", "value": "555-1234", "use": "home", "rank": 1}
        assert compact_resource(v) == "phone: 555-1234 (home) #1"


class TestCompactIdentifier:
    def test_system_value_and_use(self):
        v = {"system": "http://hospital.org/mrn", "value": "MRN123", "use": "official"}
        assert compact_resource(v) == "http://hospital.org/mrn|MRN123 [official]"

    def test_not_confused_with_contact_point(self):
        # URI system should not be detected as ContactPoint
        v = {"system": "http://hospital.org/mrn", "value": "MRN123"}
        result = compact_resource(v)
        assert "http://hospital.org/mrn" in result

    def test_type_prepended_as_label(self):
        v = {
            "type": {"text": "MRN"},
            "system": "http://hospital.org/mrn",
            "value": "MRN123",
        }
        assert compact_resource(v) == "MRN: http://hospital.org/mrn|MRN123"

    def test_value_only(self):
        assert compact_resource({"value": "MRN123"}) == "MRN123"

    def test_system_only(self):
        assert (
            compact_resource({"system": "http://hospital.org/mrn"})
            == "http://hospital.org/mrn"
        )


class TestCompactAttachment:
    def test_title_and_content_type(self):
        v = {"title": "Discharge Summary", "contentType": "application/pdf"}
        assert compact_resource(v) == "Discharge Summary (application/pdf)"

    def test_title_without_content_type(self):
        v = {"title": "Discharge Summary"}
        assert compact_resource(v) == "Discharge Summary"

    def test_falls_back_to_url(self):
        v = {"url": "http://example.com/image.png", "contentType": "image/png"}
        assert compact_resource(v) == "http://example.com/image.png"

    def test_content_type_only(self):
        v = {"contentType": "application/pdf"}
        assert compact_resource(v) == "application/pdf"

    def test_inline_text_data_decoded(self):
        import base64

        v = {
            "contentType": "text/plain",
            "data": base64.b64encode(b"hello world").decode(),
        }
        assert compact_resource(v) == "hello world"

    def test_inline_binary_data_as_data_uri(self):
        import base64

        raw = b"\x89PNG\r\n"
        v = {"contentType": "image/png", "data": base64.b64encode(raw).decode()}
        assert (
            compact_resource(v)
            == f"data:image/png;base64,{base64.b64encode(raw).decode()}"
        )

    def test_hash_bytes_passthrough(self):
        from fhir_mcp_server.compactor.types.complex_types.attachment import Attachment

        raw_hash = b"\xde\xad\xbe\xef"
        a = Attachment.model_validate(
            {"contentType": "application/pdf", "hash": raw_hash}
        )
        assert a.hash == raw_hash

    def test_data_bytes_passthrough(self):
        from fhir_mcp_server.compactor.types.complex_types.attachment import Attachment

        raw = b"raw bytes"
        a = Attachment.model_validate({"contentType": "application/pdf", "data": raw})
        assert a.data == raw

    def test_attachment_hash_data_non_string(self):
        from fhir_mcp_server.compactor.types.complex_types.attachment import Attachment

        with pytest.raises(Exception):
            Attachment.model_validate(
                {"contentType": "text/plain", "hash": {"dict": 1}, "data": {"dict": 2}}
            )


class TestCompactAnnotation:
    def test_text_only(self):
        v = {"text": "Patient was fasting"}
        assert compact_resource(v) == "Patient was fasting"

    def test_text_with_time(self):
        v = {"text": "Patient was fasting", "time": "2024-01-01T09:00:00Z"}
        assert compact_resource(v) == "Patient was fasting (2024-01-01T09:00:00Z)"

    def test_text_with_author_string(self):
        v = {"text": "Patient was fasting", "authorString": "Dr. Smith"}
        assert compact_resource(v) == "Patient was fasting (Dr. Smith)"

    def test_text_with_author_and_time(self):
        v = {
            "text": "Patient was fasting",
            "authorString": "Dr. Smith",
            "time": "2024-01-01",
        }
        assert compact_resource(v) == "Patient was fasting (Dr. Smith, 2024-01-01)"

    def test_author_reference(self):
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
    def test_value_and_currency(self):
        assert compact_resource({"value": 49.99, "currency": "USD"}) == "49.99 USD"

    def test_value_without_currency(self):
        assert compact_resource({"value": 49.99, "currency": None}) == "49.99"


class TestCompactResourceList:
    def test_compacts_each_item_in_list(self):
        data = [
            {"coding": [{"code": "M", "display": "Married"}]},
            {"coding": [{"code": "S", "display": "Single"}]},
        ]
        assert compact_resource(data) == ["Married (M)", "Single (S)"]

    def test_leaves_primitives_unchanged(self):
        assert compact_resource("hello") == "hello"
        assert compact_resource(42) == 42
        assert compact_resource(True) is True

    def test_recurses_into_unrecognized_dict(self):
        data = {
            "resourceType": "Patient",
            "valueQuantity": {"value": 7.2, "unit": "cm"},
        }
        assert compact_resource(data) == {
            "resourceType": "Patient",
            "valueQuantity": "7.2 cm",
        }


class TestCompactExtension:
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
        result = compact_resource(self.INTERPRETER_NEEDED)
        assert (
            result
            == "http://hl7.org/fhir/us/core/StructureDefinition/us-core-interpreter-needed|http://snomed.info/sct|373066001"
        )

    def test_nested_extension_returns_dict_keyed_by_sub_url(self):
        result = compact_resource(self.RACE)
        assert isinstance(result, dict)
        assert (
            result["url"]
            == "http://hl7.org/fhir/us/core/StructureDefinition/us-core-race"
        )
        assert result["text"] == "Mixed"

    def test_repeated_sub_url_becomes_list(self):
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
        result = compact_resource(self.TRIBAL_AFFILIATION)
        assert isinstance(result, dict)
        assert (
            result["url"]
            == "http://hl7.org/fhir/us/core/StructureDefinition/us-core-tribal-affiliation"
        )
        assert result["tribalAffiliation"] == "Shoshone"
        assert result["isEnrolled"] == "False"

    def test_unresolvable_nested_extension_returns_raw(self):
        data = {"url": "http://example.org/ext", "extension": []}
        result = compact_resource(data)
        assert result == data

    def test_sub_extension_value_that_compacts_to_dict_is_dropped(self):
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
        data = {"url": "http://example.org/ext", "valueDecimal": 3.14}
        assert compact_resource(data) == "http://example.org/ext|3.14"

    def test_int_value_in_extension(self):
        data = {"url": "http://example.org/ext", "valueInteger": 42}
        assert compact_resource(data) == "http://example.org/ext|42"

    def test_no_value_keys_returns_raw(self):
        data = {"url": "http://example.org/ext"}
        assert compact_resource(data) == data

    def test_multiple_value_keys_returns_raw(self):
        data = {"url": "http://example.org/ext", "valueString": "a", "valueInteger": 1}
        assert compact_resource(data) == data

    def test_extract_extension_value_list(self):
        from fhir_mcp_server.compactor.compactors.extension import _extract_extension_value
        from fhir_mcp_server.compactor.types.complex_types.extension import Extension

        ext = Extension.model_validate({"url": "x", "valueList": [1, 2]})
        assert _extract_extension_value(ext) == ""

    def test_compact_extension_nested_not_dict(self):
        v = {"url": "x", "extension": ["string"]}
        assert compact_resource(v) == v


class TestCompactTiming:
    def test_code_text_used_verbatim(self):
        v = {"code": {"text": "Take medication in the morning on weekends"}}
        assert compact_resource(v) == "Take medication in the morning on weekends"

    def test_known_abbreviation_code(self):
        v = {"code": {"coding": [{"code": "BID"}]}}
        assert compact_resource(v) == "BID"

    def test_every_8_hours(self):
        v = {"repeat": {"frequency": 1, "period": 8, "periodUnit": "h"}}
        assert compact_resource(v) == "every 8h"

    def test_3_times_a_day(self):
        v = {"repeat": {"frequency": 3, "period": 1, "periodUnit": "d"}}
        assert compact_resource(v) == "3x/day"

    def test_3_to_4_times_a_day(self):
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
        v = {"repeat": {"frequency": 1, "period": 4, "periodUnit": "h", "periodMax": 6}}
        assert compact_resource(v) == "every 4-6h"

    def test_every_21_days_for_1_hour(self):
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
        v = {"repeat": {"when": ["CM"]}}
        assert compact_resource(v) == "at breakfast"

    def test_duration_with_offset_and_when(self):
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
        v = {"repeat": {"count": 1}}
        assert compact_resource(v) == "1 time"

    def test_event_list(self):
        v = {"event": ["2012-01-07T09:00:00+10:00", "2012-01-14T09:00:00+10:00"]}
        assert (
            compact_resource(v)
            == "2012-01-07T09:00:00+10:00, 2012-01-14T09:00:00+10:00"
        )

    def test_multiple_times_per_multi_day_period(self):
        v = {"repeat": {"frequency": 2, "period": 3, "periodUnit": "d"}}
        assert compact_resource(v) == "2x/3d"

    def test_bounds_duration(self):
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
        v = {
            "repeat": {"frequency": 1, "period": 1, "periodUnit": "d", "when": ["MORN"]}
        }
        assert compact_resource(v) == "1x/day morning"

    def test_duration_with_when_no_offset(self):
        v = {"repeat": {"duration": 5, "durationUnit": "min", "when": ["AC"]}}
        assert compact_resource(v) == "for 5min before meal"

    def test_offset_with_when_no_duration(self):
        v = {"repeat": {"offset": 10, "when": ["AC"]}}
        assert compact_resource(v) == "10min before meal"

    def test_empty_timing_returns_raw(self):
        v = {}
        assert compact_resource(v) == v


class TestRealWorldPayloads:
    # Test on an official example
    def test_us_core_blood_pressure(self):
        from fhir_mcp_server.compactor.dispatch import compact_resource

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
