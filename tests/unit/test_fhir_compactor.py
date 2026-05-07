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
from fhir_mcp_server.fhir_compactor import compact_resource
from fhir_mcp_server.utils import filter_resource_fields


class TestCompactCodeableConcept:
    def test_uses_text_when_present(self):
        v = {"coding": [{"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"}], "text": "Body Height"}
        assert compact_resource(v) == "Body Height"

    def test_text_only_no_coding(self):
        assert compact_resource({"text": "uncoded free text result"}) == "uncoded free text result"

    def test_uses_display_and_code_when_no_text(self):
        v = {"coding": [{"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"}]}
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
        v = {"coding": [
            {"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"},
            {"system": "https://acme.lab/codes", "code": "HT", "display": "Height"},
        ]}
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
        assert compact_resource({"value": 5.0, "comparator": ">=", "unit": "mg/dL"}) == ">=5 mg/dL"

    def test_integer_value_no_trailing_zeros(self):
        assert compact_resource({"value": 150, "unit": "cm"}) == "150 cm"

    def test_value_only_no_unit(self):
        assert compact_resource({"value": 42, "system": "http://unitsofmeasure.org"}) == "42"

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
        assert compact_resource({"value": 100, "unit": "USD", "system": "urn:iso:std:iso:4217"}) == "100 USD"

    def test_simple_quantity(self):
        assert compact_resource({"value": 5, "unit": "mg"}) == "5 mg"


class TestCompactRange:
    def test_low_and_high(self):
        v = {"low": {"value": 3.5, "unit": "mmol/L"}, "high": {"value": 5.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "3.5 mmol/L – 5.5 mmol/L"

    def test_only_low(self):
        v = {"low": {"value": 3.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "3.5 mmol/L"

    def test_only_high(self):
        v = {"high": {"value": 5.5, "unit": "mmol/L"}}
        assert compact_resource(v) == "5.5 mmol/L"


class TestCompactRatio:
    def test_numerator_and_denominator(self):
        v = {"numerator": {"value": 1, "unit": "mg"}, "denominator": {"value": 10, "unit": "mL"}}
        assert compact_resource(v) == "1 mg/10 mL"

    def test_missing_denominator_returns_raw(self):
        v = {"numerator": {"value": 1, "unit": "mg"}}
        assert compact_resource(v) == v

    def test_missing_numerator_returns_raw(self):
        v = {"denominator": {"value": 10, "unit": "mL"}}
        assert compact_resource(v) == v


class TestCompactPeriod:
    def test_start_and_end(self):
        assert compact_resource({"start": "2024-01-01", "end": "2024-06-30"}) == "2024-01-01 – 2024-06-30"

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
            {"use": "official", "prefix": ["Ms."], "family": "Smith", "given": ["Jane"]},
            {"use": "maiden", "family": "Jones", "given": ["Jane"]},
            {"use": "nickname", "given": ["Jenny"]},
        ]
        assert compact_resource(v) == ["Ms. Jane Smith", "Jane Jones (maiden)", "Jenny (nickname)"]


class TestCompactAddress:
    def test_full_address(self):
        v = {"line": ["123 Main St"], "city": "Boston", "state": "MA", "postalCode": "02101", "country": "US"}
        assert compact_resource(v) == "123 Main St, Boston MA 02101, US"

    def test_uses_text_when_present(self):
        # text + city ensures HumanName validation fails (no city field) and Address is reached
        v = {"text": "123 Main St, Boston MA 02101", "city": "Boston"}
        assert compact_resource(v) == "123 Main St, Boston MA 02101"

    def test_district_included_in_location(self):
        v = {"city": "Boston", "district": "Suffolk", "state": "MA", "postalCode": "02101"}
        assert compact_resource(v) == "Boston Suffolk MA 02101"

    def test_use_and_type_appended(self):
        v = {"use": "home", "type": "postal", "line": ["123 Main St"], "city": "Boston"}
        assert compact_resource(v) == "123 Main St, Boston (home, postal)"

    def test_use_only(self):
        v = {"use": "work", "city": "Boston"}
        assert compact_resource(v) == "Boston (work)"


class TestCompactContactPoint:
    def test_phone_with_use(self):
        assert compact_resource({"system": "phone", "value": "555-1234", "use": "home"}) == "phone: 555-1234 (home)"

    def test_email_without_use(self):
        assert compact_resource({"system": "email", "value": "john@example.com"}) == "email: john@example.com"

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
        v = {"type": {"text": "MRN"}, "system": "http://hospital.org/mrn", "value": "MRN123"}
        assert compact_resource(v) == "MRN: http://hospital.org/mrn|MRN123"

    def test_value_only(self):
        assert compact_resource({"value": "MRN123"}) == "MRN123"

    def test_system_only(self):
        assert compact_resource({"system": "http://hospital.org/mrn"}) == "http://hospital.org/mrn"


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
        v = {"contentType": "text/plain", "data": base64.b64encode(b"hello world").decode()}
        assert compact_resource(v) == "hello world"

    def test_inline_binary_data_as_data_uri(self):
        import base64
        raw = b"\x89PNG\r\n"
        v = {"contentType": "image/png", "data": base64.b64encode(raw).decode()}
        assert compact_resource(v) == f"data:image/png;base64,{base64.b64encode(raw).decode()}"


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
        v = {"text": "Patient was fasting", "authorString": "Dr. Smith", "time": "2024-01-01"}
        assert compact_resource(v) == "Patient was fasting (Dr. Smith, 2024-01-01)"

    def test_author_reference(self):
        v = {"text": "I don't think this is true", "authorReference": {"reference": "Patient/example"}, "time": "2022-02-08T10:18:14Z"}
        assert compact_resource(v) == "I don't think this is true (Patient/example, 2022-02-08T10:18:14Z)"


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
        data = {"resourceType": "Patient", "valueQuantity": {"value": 7.2, "unit": "cm"}}
        assert compact_resource(data) == {"resourceType": "Patient", "valueQuantity": "7.2 cm"}


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
        v = {"repeat": {"frequency": 3, "frequencyMax": 4, "period": 1, "periodUnit": "d"}}
        assert compact_resource(v) == "3-4x/day"

    def test_every_4_to_6_hours(self):
        v = {"repeat": {"frequency": 1, "period": 4, "periodUnit": "h", "periodMax": 6}}
        assert compact_resource(v) == "every 4-6h"

    def test_every_21_days_for_1_hour(self):
        v = {"repeat": {"frequency": 1, "period": 21, "periodUnit": "d", "duration": 1, "durationUnit": "h"}}
        assert compact_resource(v) == "every 21d for 1h"

    def test_when_only(self):
        v = {"repeat": {"when": ["CM"]}}
        assert compact_resource(v) == "at breakfast"

    def test_duration_with_offset_and_when(self):
        v = {"repeat": {"duration": 5, "durationUnit": "min", "when": ["AC"], "offset": 10}}
        assert compact_resource(v) == "for 5min, 10min before meal"  # AC → "before meal"

    def test_days_of_week_with_when(self):
        v = {"repeat": {"frequency": 1, "period": 1, "periodUnit": "d", "dayOfWeek": ["mon", "wed", "fri"], "when": ["MORN"]}}
        assert compact_resource(v) == "1x/day on Mon/Wed/Fri morning"

    def test_time_of_day(self):
        v = {"repeat": {"frequency": 1, "period": 1, "periodUnit": "d", "timeOfDay": ["10:00:00"]}}
        assert compact_resource(v) == "1x/day at 10:00"

    def test_count_only(self):
        v = {"repeat": {"count": 1}}
        assert compact_resource(v) == "1 time"

    def test_event_list(self):
        v = {"event": ["2012-01-07T09:00:00+10:00", "2012-01-14T09:00:00+10:00"]}
        assert compact_resource(v) == "2012-01-07T09:00:00+10:00, 2012-01-14T09:00:00+10:00"

    def test_multiple_times_per_multi_day_period(self):
        v = {"repeat": {"frequency": 2, "period": 3, "periodUnit": "d"}}
        assert compact_resource(v) == "2x/3d"

    def test_bounds_duration(self):
        v = {"repeat": {"frequency": 2, "period": 1, "periodUnit": "d", "boundsDuration": {"value": 10, "unit": "d", "system": "http://unitsofmeasure.org", "code": "d"}}}
        assert compact_resource(v) == "2x/day for 10d"

    def test_bounds_range(self):
        v = {"repeat": {"frequency": 3, "period": 1, "periodUnit": "d", "boundsRange": {"low": {"value": 3, "unit": "d"}, "high": {"value": 5, "unit": "d"}}}}
        assert compact_resource(v) == "3x/day for 3 d – 5 d"

    def test_bounds_period(self):
        v = {"repeat": {"frequency": 2, "period": 1, "periodUnit": "d", "boundsPeriod": {"start": "2015-07-01"}}}
        assert compact_resource(v) == "2x/day from 2015-07-01"

    def test_when_with_frequency_no_duration(self):
        v = {"repeat": {"frequency": 1, "period": 1, "periodUnit": "d", "when": ["MORN"]}}
        assert compact_resource(v) == "1x/day morning"

    def test_duration_with_when_no_offset(self):
        v = {"repeat": {"duration": 5, "durationUnit": "min", "when": ["AC"]}}
        assert compact_resource(v) == "for 5min before meal"

    def test_offset_with_when_no_duration(self):
        v = {"repeat": {"offset": 10, "when": ["AC"]}}
        assert compact_resource(v) == "10min before meal"


class TestFilterByFhirpathWithCompaction:
    OBSERVATION = {
        "resourceType": "Observation",
        "id": "o1",
        "code": {"coding": [{"system": "http://loinc.org", "code": "8302-2", "display": "Body Height"}], "text": "Body Height"},
        "valueQuantity": {"value": 170.5, "unit": "cm"},
        "effectivePeriod": {"start": "2024-01-01", "end": "2024-01-01"},
    }

    # def test_compact_types_true_compacts_matched_values(self):
    #     result = filter_by_fhirpath(self.OBSERVATION, ["Observation.code", "Observation.valueQuantity"])
    #     assert result["Observation.code"] == ["Body Height"]
    #     assert result["Observation.valueQuantity"] == ["170.5 cm"]

    # def test_compact_types_false_returns_raw_dicts(self):
    #     result = filter_by_fhirpath(self.OBSERVATION, ["Observation.code", "Observation.valueQuantity"])
    #     assert isinstance(result["Observation.code"][0], dict)
    #     assert isinstance(result["Observation.valueQuantity"][0], dict)

    # def test_compact_types_defaults_to_true(self):
    #     result = filter_by_fhirpath(self.OBSERVATION, ["Observation.code"])
    #     assert result["Observation.code"] == ["Body Height"]

